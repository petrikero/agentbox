"""Render pi session events as compact terminal progress.

Pi writes the same JSONL event stream to two places:

1. stdout, when launched with ``--mode json``.
2. ``$PI_CODING_AGENT_DIR/sessions/<cwd-encoded>/<timestamp>_<uuid>.jsonl``
   (default ``~/.pi/agent/sessions/...``), always, unless ``--no-session``.

Streaming via stdout from inside a Docker container hits buffering layers
(Node's pipe buffer, the docker client, Python's text-mode wrapper) and the
TTY workaround is unreliable on Windows. Tailing the session file from the
host -- which is just a normal mounted file growing in real time -- avoids
all of that, so that's what this module does.

Event shape we render (subset):

- ``{"type": "model_change", "provider": ..., "modelId": ...}``
- ``{"type": "thinking_level_change", "thinkingLevel": ...}``
- ``{"type": "message", "message": {"role": "user|assistant|toolResult",
  "content": [...]}}``

Assistant content blocks: ``text``, ``thinking``, ``toolCall``.
ToolResult content blocks: ``text`` (plus optional ``details``/``isError``).
"""

from __future__ import annotations

import json
import subprocess
import threading
import time
from pathlib import Path

from rich.console import Console
from rich.markup import escape

from agentbox.progress._render import (
    _DEBUG,
    _POLL_INTERVAL,
    _debug,
    _flatten,
    _printw,
)


def _arg_preview(name: str, args: dict) -> str:
    if name == "bash":
        return _flatten(str(args.get("command", "")))
    if name == "pyrepl":
        code = str(args.get("code", "")).strip()
        first = next((ln for ln in code.splitlines() if ln.strip()), "")
        return _flatten(first)
    if name in {"read", "edit", "write"}:
        path = args.get("path") or args.get("file_path") or ""
        return _flatten(str(path))
    return _flatten(json.dumps(args, ensure_ascii=False))


def _result_preview(content: list[dict], details: dict | None) -> str:
    if details and details.get("disabled"):
        return "(tool disabled)"
    text_blocks = [b.get("text", "") for b in content if b.get("type") == "text"]
    text = "\n".join(text_blocks).strip()
    if not text:
        return "(empty)"
    first = next((ln for ln in text.splitlines() if ln.strip()), "")
    return _flatten(first)


def _render_event(event: dict, console: Console) -> None:
    et = event.get("type")
    if et == "model_change":
        provider = event.get("provider", "")
        model = event.get("modelId", "")
        console.print(
            f"  [dim cyan]·[/]  [dim]{'model':<10}[/]  "
            f"{escape(provider)}/{escape(model)}"
        )
        return
    if et == "thinking_level_change":
        level = event.get("thinkingLevel", "")
        console.print(
            f"  [dim cyan]·[/]  [dim]{'thinking':<10}[/]  {escape(str(level))}"
        )
        return
    if et != "message":
        return  # session, compaction, custom, label, branch_summary, ... — ignore

    msg = event.get("message", {}) or {}
    role = msg.get("role")
    content = msg.get("content", []) or []

    if role == "user":
        return  # prompt is already echoed in the launch banner

    if role == "toolResult":
        is_error = bool(msg.get("isError"))
        details = msg.get("details") or {}
        preview = _result_preview(content, details)
        marker = "[red]x[/] " if is_error else "[blue]<[/] "
        body_style = "red" if is_error else "dim"
        _printw(console, f"  {marker} [{body_style}]{escape(preview)}[/]")
        return

    if role == "assistant":
        for block in content:
            bt = block.get("type")
            if bt == "thinking":
                think = _flatten(str(block.get("thinking", "")))
                if think:
                    _printw(
                        console,
                        f"  [magenta]~[/]  [dim italic]{escape(think)}[/]",
                    )
            elif bt == "toolCall":
                name = block.get("name", "")
                args = block.get("arguments", {}) or {}
                if name == "pyrepl":
                    # Show the full code, not just the first line, so the user
                    # can read what pi actually ran. Subsequent lines are
                    # aligned under the first.
                    code = str(args.get("code", "")).strip("\n")
                    code_lines = code.splitlines() or [""]
                    _printw(
                        console,
                        f"  [yellow]>[/]  [bold yellow]{escape(name):<10}[/]  "
                        f"[dim]{escape(code_lines[0])}[/]",
                    )
                    for extra in code_lines[1:]:
                        _printw(
                            console, f"                 [dim]{escape(extra)}[/]"
                        )
                else:
                    preview = _arg_preview(name, args)
                    _printw(
                        console,
                        f"  [yellow]>[/]  [bold yellow]{escape(name):<10}[/]  "
                        f"{escape(preview)}",
                    )
            # text blocks are not rendered here -- pi's --mode text already
            # writes the final answer to stdout; rendering it again would
            # duplicate it on the user's terminal.


def _render_lines(lines: list[str], console: Console) -> None:
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue  # session file may have partial lines mid-write
        try:
            _render_event(event, console)
        except Exception as exc:
            console.print(
                f"[dim red]progress: render error: {escape(str(exc))}[/]"
            )


def _wait_for_new_session_file(
    session_dir: Path,
    snapshot: set[str],
    proc: subprocess.Popen,
    stop_event: threading.Event,
    console: Console,
) -> Path | None:
    """Poll ``session_dir`` for a .jsonl that wasn't there at launch time.

    Polls until the file appears, ``stop_event`` is set, or pi exits
    without ever creating a session file (e.g. ``--no-session``).
    There's no fixed deadline -- a slow cold start (image build, model
    handshake) shouldn't kill the watcher prematurely; the wait ends
    naturally when pi finishes.

    Returns the new file path, or None if pi exited without creating one.
    """
    poll_count = 0
    while not stop_event.is_set():
        try:
            current = {
                p.name for p in session_dir.iterdir() if p.suffix == ".jsonl"
            }
        except FileNotFoundError:
            current = set()
        new_names = current - snapshot
        if new_names:
            chosen = max(
                new_names,
                key=lambda n: (session_dir / n).stat().st_mtime,
            )
            _debug(
                console,
                f"watcher: found new session after {poll_count} polls: {chosen}",
            )
            return session_dir / chosen
        if proc.poll() is not None:
            _debug(
                console,
                f"watcher: pi exited (rc={proc.returncode}) before "
                f"writing a session file (polled {poll_count}x)",
            )
            return None
        poll_count += 1
        if _DEBUG and poll_count % 50 == 0:  # ~5s
            _debug(
                console,
                f"watcher: still waiting for new .jsonl in {session_dir} "
                f"(seen {len(current)} files, {len(snapshot)} pre-existing, "
                f"poll={poll_count})",
            )
        time.sleep(_POLL_INTERVAL)
    _debug(console, "watcher: stop_event set before session file appeared")
    return None


def tail_session_file(
    session_dir: Path,
    snapshot: set[str],
    proc: subprocess.Popen,
    console: Console,
    stop_event: threading.Event,
) -> None:
    """Watch ``session_dir`` for the new session file, then tail it.

    Run from a daemon thread. ``snapshot`` is the set of .jsonl filenames
    that existed *before* pi launched, so we can identify the new one.
    Stops when ``stop_event`` is set or pi has exited and the file has no
    further bytes.
    """
    _debug(
        console,
        f"watcher: started; session_dir={session_dir}, "
        f"snapshot_size={len(snapshot)}, dir_exists={session_dir.exists()}",
    )
    target = _wait_for_new_session_file(
        session_dir, snapshot, proc, stop_event, console
    )
    if target is None:
        _debug(console, "watcher: no session file to tail; exiting")
        return

    _debug(console, f"watcher: tailing {target}")
    pos = 0
    pending = ""
    lines_rendered = 0
    while not stop_event.is_set():
        try:
            with target.open("r", encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
        except OSError as exc:
            _debug(console, f"watcher: read error ({exc}); retrying")
            time.sleep(_POLL_INTERVAL)
            continue
        if chunk:
            pending += chunk
            *complete, pending = pending.split("\n")
            if complete:
                _render_lines(complete, console)
                lines_rendered += len(complete)
                _debug(
                    console,
                    f"watcher: rendered {len(complete)} new line(s) "
                    f"(pos={pos}, total={lines_rendered})",
                )
        elif proc.poll() is not None:
            if pending.strip():
                _render_lines([pending], console)
            _debug(
                console,
                f"watcher: pi exited (rc={proc.returncode}); "
                f"rendered {lines_rendered} line(s) total",
            )
            return
        else:
            time.sleep(_POLL_INTERVAL)
    _debug(console, "watcher: stop_event set; exiting")
