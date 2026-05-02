"""mitmproxy addon: short-circuit LLM API calls with scripted responses.

Used by e2e tests / harnesses that want to run the real ``pi`` /
``claude`` binaries inside the agentbox sandbox but with a
deterministic, offline LLM. The real proxy already MITMs every TLS
connection from the agent container, so swapping the upstream is
just an extra addon -- no agent reconfiguration, no DNS hacks, no
extra cert plumbing.

When the ``agentbox_mock_llm_script`` mitmproxy option is set, this
addon loads the user's Python module and, on every request to
``api.anthropic.com`` / ``api.openai.com`` / ``api.z.ai``, asks it
for the next response. ``flow.response`` gets set to a
Messages-API-shaped reply, which makes mitmproxy skip the upstream
connection entirely. When ``agentbox_mock_llm_transcript`` is also
set, every intercepted (request, response) pair is appended as a
JSON line to that path so tests can assert on what the agent asked
for.

Script API::

    def replies(req):
        '''
        req: {
            "host": str,
            "path": str,
            "method": str,
            "body": dict,    # parsed JSON request body (Messages API shape)
            "turn": int,     # 0-indexed call counter
        }

        Return a dict::

            {
                "content": [
                    {"type": "text", "text": "..."},
                    {"type": "tool_use", "id": "toolu_1",
                     "name": "Read", "input": {"file_path": "..."}},
                    {"type": "thinking", "thinking": "..."},
                ],
                "stop_reason": "end_turn" | "tool_use" | "stop_sequence",
                "model": "...",                 # optional override
                "input_tokens": 100,            # optional override
                "output_tokens": 20,            # optional override
            }
        '''
        ...

The addon serialises the high-level dict to either non-streaming
JSON (Content-Type ``application/json``) or streaming SSE
(Content-Type ``text/event-stream``) depending on whether the
incoming request had ``"stream": true``. The Anthropic SDK's
streaming reader parses the SSE body fine even when it arrives in
one shot with a Content-Length, because the format is line-oriented.
"""

from __future__ import annotations

import importlib.util
import json
import time
import uuid
from pathlib import Path
from typing import Any

from mitmproxy import ctx, http


# Hosts the addon will short-circuit. Matches the LLM endpoints in
# the bundled allowlist (``proxy/allowlist.yaml``).
_LLM_HOSTS: frozenset[str] = frozenset({
    "api.anthropic.com",
    "api.openai.com",
    "api.z.ai",
})


def _log(level: str, message: str) -> None:
    """Best-effort log via mitmproxy's ctx; falls back to stderr.

    ``ctx.log`` is only set up while a mitmproxy session is active; in
    unit tests that drive the addon directly it's absent. Falling back
    to stderr keeps the addon usable in both paths.
    """
    log = getattr(ctx, "log", None)
    fn = getattr(log, level, None) if log is not None else None
    if fn is not None:
        fn(message)
        return
    print(f"agentbox mock-llm [{level}]: {message}", flush=True)


def _load_script(path: str) -> Any:
    """Import the user's mock-llm script as a one-off module.

    The module must export a ``replies(request) -> dict`` callable.
    Errors at import time surface as a friendly message in the proxy
    log; runtime errors inside ``replies`` are caught per-request and
    returned to the agent as a 500.
    """
    resolved = Path(path).expanduser().resolve()
    if not resolved.is_file():
        raise RuntimeError(
            f"agentbox mock-llm: script not found at {resolved}"
        )
    spec = importlib.util.spec_from_file_location(
        "agentbox_mock_llm_script", resolved,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(
            f"agentbox mock-llm: cannot load script at {resolved}"
        )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "replies") or not callable(module.replies):
        raise RuntimeError(
            f"agentbox mock-llm: script {resolved} must export "
            f"a callable `replies(req)`"
        )
    return module


def _output_token_estimate(content_blocks: list[dict]) -> int:
    """Rough word-count estimate so the usage block has a plausible value."""
    n = 0
    for block in content_blocks:
        if block.get("type") == "text":
            n += len(str(block.get("text", "")).split())
        elif block.get("type") == "thinking":
            n += len(str(block.get("thinking", "")).split())
    return n or 1


def _new_msg_id() -> str:
    return f"msg_{uuid.uuid4().hex[:24]}"


def _new_tool_id() -> str:
    return f"toolu_{uuid.uuid4().hex[:16]}"


def _build_nonstream_body(reply: dict) -> bytes:
    """Build a non-streaming Anthropic Messages API response body."""
    content = list(reply.get("content") or [])
    body = {
        "id": _new_msg_id(),
        "type": "message",
        "role": "assistant",
        "model": reply.get("model", "claude-mock-1"),
        "content": content,
        "stop_reason": reply.get("stop_reason", "end_turn"),
        "stop_sequence": None,
        "usage": {
            "input_tokens": reply.get("input_tokens", 100),
            "output_tokens": reply.get(
                "output_tokens", _output_token_estimate(content),
            ),
        },
    }
    return json.dumps(body).encode("utf-8")


def _sse(event_type: str, payload: dict) -> str:
    return f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"


def _build_stream_body(reply: dict) -> bytes:
    """Build a streaming SSE Anthropic Messages API response body.

    The body is sent in one shot but stays format-correct: each
    ``event: ... \\ndata: {...}\\n\\n`` block is what the Anthropic
    SDK's stream reader expects. Real wire-level streaming would
    require flow.response.stream + a generator; for deterministic
    test fixtures the one-shot body is enough.
    """
    content = list(reply.get("content") or [])
    msg_id = _new_msg_id()
    out: list[str] = []

    out.append(_sse("message_start", {
        "type": "message_start",
        "message": {
            "id": msg_id,
            "type": "message",
            "role": "assistant",
            "model": reply.get("model", "claude-mock-1"),
            "content": [],
            "stop_reason": None,
            "stop_sequence": None,
            "usage": {
                "input_tokens": reply.get("input_tokens", 100),
                "output_tokens": 0,
            },
        },
    }))

    for idx, block in enumerate(content):
        btype = block.get("type", "text")
        if btype == "text":
            out.append(_sse("content_block_start", {
                "type": "content_block_start",
                "index": idx,
                "content_block": {"type": "text", "text": ""},
            }))
            text = str(block.get("text", ""))
            if text:
                out.append(_sse("content_block_delta", {
                    "type": "content_block_delta",
                    "index": idx,
                    "delta": {"type": "text_delta", "text": text},
                }))
            out.append(_sse("content_block_stop", {
                "type": "content_block_stop", "index": idx,
            }))
        elif btype == "tool_use":
            tool_id = str(block.get("id") or _new_tool_id())
            out.append(_sse("content_block_start", {
                "type": "content_block_start",
                "index": idx,
                "content_block": {
                    "type": "tool_use",
                    "id": tool_id,
                    "name": str(block.get("name", "")),
                    "input": {},
                },
            }))
            inp = block.get("input") or {}
            out.append(_sse("content_block_delta", {
                "type": "content_block_delta",
                "index": idx,
                "delta": {
                    "type": "input_json_delta",
                    "partial_json": json.dumps(inp),
                },
            }))
            out.append(_sse("content_block_stop", {
                "type": "content_block_stop", "index": idx,
            }))
        elif btype == "thinking":
            out.append(_sse("content_block_start", {
                "type": "content_block_start",
                "index": idx,
                "content_block": {"type": "thinking", "thinking": ""},
            }))
            out.append(_sse("content_block_delta", {
                "type": "content_block_delta",
                "index": idx,
                "delta": {
                    "type": "thinking_delta",
                    "thinking": str(block.get("thinking", "")),
                },
            }))
            out.append(_sse("content_block_stop", {
                "type": "content_block_stop", "index": idx,
            }))

    out.append(_sse("message_delta", {
        "type": "message_delta",
        "delta": {
            "stop_reason": reply.get("stop_reason", "end_turn"),
            "stop_sequence": None,
        },
        "usage": {
            "output_tokens": reply.get(
                "output_tokens", _output_token_estimate(content),
            ),
        },
    }))
    out.append(_sse("message_stop", {"type": "message_stop"}))

    return "".join(out).encode("utf-8")


class MockLLM:
    """mitmproxy addon: scripted LLM responses for offline e2e tests.

    Inert when ``agentbox_mock_llm_script`` is empty; in that case
    every request flows through to the next addon (the real
    ``AgentboxFilter``) unchanged. Listed first in the addon list so
    its ``request()`` hook runs before the network filter would see
    the request.
    """

    def __init__(self) -> None:
        self.script: Any | None = None
        self.script_path: str = ""
        self.transcript_path: str = ""
        self.turn: int = 0

    def load(self, loader) -> None:
        loader.add_option(
            "agentbox_mock_llm_script", str, "",
            "Path to a Python module that scripts mock LLM responses",
        )
        loader.add_option(
            "agentbox_mock_llm_transcript", str, "",
            "Path to append a JSONL transcript of intercepted LLM "
            "requests / responses",
        )

    def configure(self, updates) -> None:
        if "agentbox_mock_llm_script" in updates:
            path = ctx.options.agentbox_mock_llm_script
            self.script_path = path
            if path:
                self.script = _load_script(path)
                _log("info", f"agentbox: mock-llm active ({path})")
            else:
                self.script = None
        if "agentbox_mock_llm_transcript" in updates:
            self.transcript_path = ctx.options.agentbox_mock_llm_transcript

    def request(self, flow: http.HTTPFlow) -> None:
        if self.script is None:
            return
        # Don't double-handle: a previous addon (or a re-run) may
        # already have set the response.
        if flow.response is not None:
            return
        host = flow.request.pretty_host.lower()
        if host not in _LLM_HOSTS:
            return

        body_text = flow.request.get_text() or "{}"
        try:
            body = json.loads(body_text)
        except json.JSONDecodeError:
            body = {}

        req_view = {
            "host": host,
            "path": flow.request.path,
            "method": flow.request.method,
            "body": body,
            "turn": self.turn,
        }
        try:
            reply = self.script.replies(req_view)
        except Exception as exc:
            _log("error", f"agentbox mock-llm: script error: {exc}")
            flow.response = http.Response.make(
                500,
                json.dumps({
                    "type": "error",
                    "error": {
                        "type": "mock_script_error",
                        "message": str(exc),
                    },
                }).encode("utf-8"),
                {"Content-Type": "application/json"},
            )
            return

        if not isinstance(reply, dict):
            _log(
                "error",
                f"agentbox mock-llm: script returned "
                f"{type(reply).__name__}, expected dict",
            )
            flow.response = http.Response.make(
                500,
                json.dumps({
                    "type": "error",
                    "error": {
                        "type": "mock_script_error",
                        "message": (
                            f"replies() returned {type(reply).__name__}, "
                            "expected dict"
                        ),
                    },
                }).encode("utf-8"),
                {"Content-Type": "application/json"},
            )
            return

        is_stream = bool(body.get("stream"))
        if is_stream:
            response_body = _build_stream_body(reply)
            headers = {"Content-Type": "text/event-stream"}
        else:
            response_body = _build_nonstream_body(reply)
            headers = {"Content-Type": "application/json"}

        flow.response = http.Response.make(200, response_body, headers)
        self._record(req_view, reply, is_stream)
        self.turn += 1

    def _record(self, req: dict, reply: dict, is_stream: bool) -> None:
        if not self.transcript_path:
            return
        try:
            line = json.dumps({
                "ts": time.time(),
                "turn": req["turn"],
                "host": req["host"],
                "path": req["path"],
                "method": req["method"],
                "stream": is_stream,
                "request_body": req["body"],
                "reply": reply,
            })
            with open(self.transcript_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except OSError as exc:
            _log(
                "error",
                f"agentbox mock-llm: transcript write to "
                f"{self.transcript_path} failed: {exc}",
            )
