"""Render claude `--output-format stream-json --verbose` events live.

Pi's tracker tails a session file written to disk; claude's tracker
reads stdout from the docker subprocess directly. The transports are
different, the formatting primitives (timestamp, truncation, token
formatting) come from ``progress._render``. Adapted from
meta-orch's ``_run_orchestrator_cc`` parser
(``meta-orch/src/meta_orch/cli.py``); the structural change vs.
upstream is reading from a one-shot ``docker run`` Popen instead of
``docker exec``.

Event shapes we render (subset):

- ``{"type": "assistant", "message": {"content": [...]}}`` --
  ``content`` blocks: ``thinking`` (dim), ``text`` (plain),
  ``tool_use`` (yellow with ``name`` + arg detail).
- ``{"type": "user", "message": {"content": [<tool_result blocks>]}}``
  -- green check on success, red ``x`` on ``is_error``.
- ``{"type": "result", "result": "..."}`` -- final answer, captured
  for the return value (printed by the launcher to stdout for pipe
  compatibility); not rendered inline.
- ``{"type": "system", "subtype": "api_retry"}`` -- yellow retry line.
- ``{"type": "rate_limit_event", ...}`` -- yellow status line.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
from datetime import UTC, datetime

from rich.console import Console
from rich.markup import escape

from agentbox.progress._render import (
    _debug,
    _event_dt,
    _event_ts,
    _fmt_duration,
    _fmt_tokens,
    _trunc_oneline,
)


# ----------------------------------------------------------------------------
# Tool-call detail formatters
# ----------------------------------------------------------------------------


def _shorten_path(path: str) -> str:
    """Collapse long ``/tmp/claude-*`` scratch paths to ``.../<tail>``."""
    if path.startswith("/tmp/claude-"):
        parts = path.split("/")
        if len(parts) > 3:
            return ".../" + "/".join(parts[-2:])
    return path


def _tool_detail(name: str, inp: dict) -> str:
    """Short, single-line description of a tool_use block."""
    if name == "Bash":
        return _trunc_oneline(inp.get("command", ""), 120)
    if name in ("Read", "Write", "Edit"):
        return _shorten_path(str(inp.get("file_path", "")))
    if name in ("Glob", "Grep"):
        return str(inp.get("pattern", ""))
    if name == "Agent":
        return str(inp.get("description", ""))
    return _trunc_oneline(str(inp), 100)


_HEREDOC_RE = re.compile(
    r"<<['\"]?(?P<tag>[A-Z_][A-Z0-9_]*)['\"]?\s*\n(?P<body>.*?)\n(?P=tag)\b",
    re.DOTALL,
)


def _extract_heredoc_body(cmd: str) -> str:
    """Return the heredoc body from a shell command, or '' if none found.

    Used to surface child-claude prompts in orchestrator-style runs
    where the parent invokes ``claude -p ... <<'WORKER_INPUT'``.
    Inert in agentbox's single-agent case (no orchestrator yet) but
    ports along so the parser stays one piece.
    """
    m = _HEREDOC_RE.search(cmd)
    return m.group("body") if m else ""


def _is_worker_invocation(tool_name: str, inp: dict) -> bool:
    """True iff a Bash tool_use is spawning a child claude (a worker)."""
    if tool_name != "Bash":
        return False
    cmd = inp.get("command", "")
    return "claude -p" in cmd or "claude --print" in cmd


def _tool_result_text(block: dict) -> str:
    """Flatten a tool_result content field to a single string."""
    content = block.get("content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for sub in content:
            if isinstance(sub, dict) and sub.get("type") == "text":
                parts.append(sub.get("text", ""))
        return "\n".join(parts)
    return str(content)


_CAT_N_RE = re.compile(r"(?m)^\s*\d+\t")


def _strip_cat_n_prefix(text: str) -> str:
    """Strip the ``NNN\\t`` line-number prefix that the Read tool adds."""
    return _CAT_N_RE.sub("", text)


# ----------------------------------------------------------------------------
# Usage / rate-limit helpers
# ----------------------------------------------------------------------------


def _context_size(event: dict) -> int:
    """Sum of tokens the model saw on this assistant turn (input + cached).

    Anthropic's usage block splits input into three counters: fresh
    input_tokens, cache_read_input_tokens, and cache_creation_input_tokens.
    Their sum is the context that was actually sent for this turn.
    """
    usage = (event.get("message") or {}).get("usage") or {}
    input_tokens = usage.get("input_tokens") or 0
    cache_read = usage.get("cache_read_input_tokens") or 0
    cache_create = usage.get("cache_creation_input_tokens") or 0
    return input_tokens + cache_read + cache_create


def _fmt_relative(delta_seconds: float) -> str:
    """Format seconds as ``in Xd Yh`` or ``in Xh Ym``."""
    s = int(delta_seconds)
    if s <= 0:
        return "now"
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m = s // 60
    if d > 0:
        return f"in {d}d {h}h"
    if h > 0:
        return f"in {h}h {m}m"
    return f"in {m}m"


def _rate_limit_detail(info: dict) -> str:
    """Format extra rate-limit fields (utilization, reset time) for display."""
    parts: list[str] = []
    utilization = info.get("utilization")
    if utilization is not None:
        parts.append(f"{utilization:.0%} used")
    resets_at = info.get("resetsAt")
    if resets_at:
        try:
            reset_dt = datetime.fromtimestamp(resets_at, tz=UTC).astimezone()
            tz_label = reset_dt.strftime("UTC%z")
            resets = reset_dt.strftime(f"%a %b %d %H:%M {tz_label}")
            now = datetime.now(tz=UTC)
            delta = reset_dt.timestamp() - now.timestamp()
            relative = _fmt_relative(delta)
            parts.append(f"resets {resets}, {relative}")
        except (OSError, ValueError):
            pass
    if not parts:
        return ""
    return f" ({', '.join(parts)})"


# ----------------------------------------------------------------------------
# Stream parser
# ----------------------------------------------------------------------------


def run_claude_stream(
    proc: subprocess.Popen,
    console: Console,
    stop_event: threading.Event,
) -> str:
    """Read claude's stream-json output line-by-line and render to ``console``.

    ``proc`` is the docker subprocess we Popen'd with ``stdout=PIPE``.
    We don't ``proc.wait()`` here -- that's the caller's job; we just
    keep reading until the pipe closes.

    Returns the final ``result`` event's ``result`` text so the caller
    can write it to stdout for pipe compatibility (matching pi's
    behaviour, which gets the same effect for free because pi runs
    in plain-text mode).
    """
    if proc.stdout is None:
        _debug(console, "claude watcher: proc.stdout is None; nothing to read")
        return ""

    last_type: str | None = None
    # Track Bash tool_use ids that spawn a child claude (a worker).
    # Value is the start timestamp so we can report wall-clock duration
    # when the tool_result arrives. Inert today (single-agent mode);
    # ports along for orchestrator scenarios.
    worker_tool_uses: dict[str, datetime] = {}
    # Running context size from the model's own usage metrics. Updated
    # on every assistant message; shown on worker-output headers.
    ctx_tokens: int = 0
    final_result: str = ""

    for raw_line in proc.stdout:
        if stop_event.is_set():
            break
        line = raw_line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue

        etype = event.get("type", "")

        if etype == "assistant" and "message" in event:
            ctx_tokens = _context_size(event) or ctx_tokens
            for block in event["message"].get("content", []):
                btype = block.get("type", "")

                if btype == "thinking":
                    thought = block.get("thinking", "").strip()
                    if not thought:
                        continue
                    if last_type and last_type != "thinking":
                        console.print()
                    ts = _event_ts(event)
                    for text_line in thought.splitlines():
                        console.print(f"  [dim]{ts} . {text_line}[/]")
                    last_type = "thinking"

                elif btype == "text":
                    text = block.get("text", "").strip()
                    if not text:
                        continue
                    if last_type and last_type != "text":
                        console.print()
                    ts = _event_ts(event)
                    for text_line in text.splitlines():
                        console.print(f"  [dim]{ts} |[/] {text_line}")
                    last_type = "text"

                elif btype == "tool_use":
                    ts = _event_ts(event)
                    name = block.get("name", "?")
                    inp = block.get("input", {}) or {}
                    tool_id = block.get("id", "")
                    if last_type and last_type != "tool_use":
                        console.print()
                    if _is_worker_invocation(name, inp):
                        if tool_id:
                            worker_tool_uses[tool_id] = (
                                _event_dt(event) or datetime.now().astimezone()
                            )
                        cmd = inp.get("command", "")
                        prompt_body = _extract_heredoc_body(cmd)
                        console.print(
                            f"  [dim]{ts}[/] [yellow]>[/] [bold cyan]Worker[/]"
                        )
                        body = prompt_body if prompt_body else cmd
                        for text_line in body.splitlines():
                            console.print(f"    [dim]|[/] {escape(text_line)}")
                    elif name == "TodoWrite":
                        console.print(
                            f"  [dim]{ts}[/] [yellow]>[/] [bold]TodoWrite[/]"
                        )
                        for todo in inp.get("todos", []) or []:
                            status = todo.get("status", "pending")
                            marker = {
                                "completed": "[green]x[/]",
                                "in_progress": "[yellow]-[/]",
                                "pending": "[dim]o[/]",
                            }.get(status, "[dim]?[/]")
                            console.print(
                                f"    {marker} {todo.get('content', '')}",
                                markup=True,
                            )
                    else:
                        detail = _tool_detail(name, inp)
                        console.print(
                            f"  [dim]{ts}[/] [yellow]>[/] [bold]{name}[/] {detail}"
                        )
                    last_type = "tool_use"

        elif etype == "user" and "message" in event:
            msg = event.get("message", {})
            content = msg.get("content", [])
            if not isinstance(content, list):
                continue
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                ts = _event_ts(event)
                is_err = block.get("is_error", False)
                tool_id = block.get("tool_use_id", "")
                text = _strip_cat_n_prefix(_tool_result_text(block))
                label = "[red]x[/]" if is_err else "[green]<[/]"
                if tool_id in worker_tool_uses:
                    started_at = worker_tool_uses.pop(tool_id)
                    stats_parts: list[str] = []
                    finished_at = _event_dt(event)
                    if finished_at and started_at:
                        secs = (finished_at - started_at).total_seconds()
                        stats_parts.append(_fmt_duration(int(secs * 1000)))
                    if ctx_tokens:
                        stats_parts.append(f"ctx {_fmt_tokens(ctx_tokens)}")
                    stats = (
                        f" [dim]({', '.join(stats_parts)})[/]"
                        if stats_parts
                        else ""
                    )
                    console.print(
                        f"  [dim]{ts}[/] {label} [bold cyan]Worker output[/]"
                        f"{stats}"
                    )
                    for text_line in text.splitlines():
                        console.print(f"    [dim]|[/] {escape(text_line)}")
                elif is_err:
                    snippet = _trunc_oneline(text, 120)
                    console.print(f"  [dim]{ts}[/] {label} [dim]{snippet}[/]")
                last_type = "tool_result"

        elif etype == "result":
            # Capture for the caller; suppress inline display so the
            # rendered transcript ends with the last tool result.
            final_result = str(event.get("result", "") or "")

        elif etype == "system":
            if event.get("subtype", "") == "api_retry":
                ts = _event_ts(event)
                err_status = event.get("error_status", "")
                attempt = event.get("attempt", "?")
                max_retries = event.get("max_retries", "?")
                delay = event.get("retry_delay_ms", 0)
                console.print(
                    f"  [dim]{ts}[/] [yellow]! Rate limited (HTTP {err_status})"
                    f" -- retry {attempt}/{max_retries}"
                    f" in {delay / 1000:.0f}s[/]"
                )
                last_type = "system"

        elif etype == "rate_limit_event":
            info = event.get("rate_limit_info", {})
            if info.get("status") != "allowed":
                ts = _event_ts(event)
                detail = _rate_limit_detail(info)
                console.print(
                    f"  [dim]{ts}[/] [yellow]! Rate limit "
                    f"({info.get('rateLimitType', '?')}): "
                    f"{info.get('status', '?')}{detail}[/]"
                )
                last_type = "system"

    return final_result
