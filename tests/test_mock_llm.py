"""Unit tests for the agentbox mock-llm proxy addon.

These tests exercise ``MockLLM.request`` against a duck-typed mitmproxy
flow, with no Docker and no real mitmdump in the loop. They pin the
on-the-wire contract the e2e harness relies on:

- requests to LLM hosts are short-circuited (``flow.response`` set,
  upstream skipped),
- non-LLM hosts (and a no-script configuration) are passed through
  untouched,
- streaming requests get an SSE body with the right event sequence,
- non-streaming requests get a Messages-API-shaped JSON body,
- the per-instance turn counter increments and is forwarded to the
  script,
- transcript writing produces one valid JSON line per intercepted
  request.

Run from the agentbox project root::

    python -m unittest tests.test_mock_llm
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from mitmproxy.http import HTTPFlow, Request

from agentbox.proxy import mock_llm as mock_llm_mod
from agentbox.proxy.mock_llm import MockLLM


_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "mock_scripts"


def _make_flow(
    method: str,
    url: str,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> HTTPFlow:
    """Duck-typed HTTPFlow stub. The addon only touches request + response."""
    request = Request.make(method, url, body, cast(Any, headers or {}))
    return cast("HTTPFlow", SimpleNamespace(request=request, response=None))


def _make_addon_with_script(script_path: Path) -> MockLLM:
    """Build a MockLLM with the script loaded directly (skip mitmproxy ctx)."""
    addon = MockLLM()
    addon.script = mock_llm_mod._load_script(str(script_path))
    addon.script_path = str(script_path)
    return addon


def _resp(flow: HTTPFlow):
    """Narrow ``flow.response`` from Optional so pyright + tests agree."""
    assert flow.response is not None, "addon should have set flow.response"
    return flow.response


def _parse_sse(body: bytes) -> list[tuple[str, dict]]:
    """Parse an SSE body into [(event, data_dict), ...]."""
    events: list[tuple[str, dict]] = []
    for raw_chunk in body.decode("utf-8").split("\n\n"):
        chunk = raw_chunk.strip()
        if not chunk:
            continue
        event_name = ""
        data_payload = ""
        for line in chunk.splitlines():
            if line.startswith("event: "):
                event_name = line[len("event: "):]
            elif line.startswith("data: "):
                data_payload = line[len("data: "):]
        if event_name and data_payload:
            events.append((event_name, json.loads(data_payload)))
    return events


class HostMatchingTests(unittest.TestCase):
    """The addon should only short-circuit known LLM hosts."""

    def setUp(self) -> None:
        self.addon = _make_addon_with_script(_FIXTURES / "pi_simple.py")

    def test_anthropic_host_intercepted(self) -> None:
        flow = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages",
            body=json.dumps({"model": "claude-x", "messages": []}).encode(),
        )
        self.addon.request(flow)
        self.assertEqual(_resp(flow).status_code, 200)

    def test_openai_host_intercepted(self) -> None:
        flow = _make_flow(
            "POST", "https://api.openai.com/v1/chat/completions",
            body=b"{}",
        )
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)

    def test_z_ai_host_intercepted(self) -> None:
        flow = _make_flow(
            "POST", "https://api.z.ai/v1/messages",
            body=b"{}",
        )
        self.addon.request(flow)
        self.assertIsNotNone(flow.response)

    def test_unknown_host_passed_through(self) -> None:
        flow = _make_flow(
            "POST", "https://api.github.com/repos/x/y/issues",
            body=b"{}",
        )
        self.addon.request(flow)
        self.assertIsNone(flow.response)

    def test_inert_when_no_script_loaded(self) -> None:
        addon = MockLLM()  # no script
        flow = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages", body=b"{}",
        )
        addon.request(flow)
        self.assertIsNone(flow.response)


class NonStreamingResponseTests(unittest.TestCase):
    """Non-streaming requests get a JSON Messages API body."""

    def setUp(self) -> None:
        self.addon = _make_addon_with_script(_FIXTURES / "pi_simple.py")

    def test_response_is_messages_api_shaped(self) -> None:
        flow = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages",
            body=json.dumps({
                "model": "claude-test",
                "messages": [{"role": "user", "content": "hi"}],
            }).encode(),
        )
        self.addon.request(flow)
        response = _resp(flow)
        self.assertEqual(
            response.headers.get("Content-Type"), "application/json",
        )
        body = json.loads(response.get_text() or "")
        self.assertEqual(body["type"], "message")
        self.assertEqual(body["role"], "assistant")
        self.assertEqual(body["stop_reason"], "end_turn")
        self.assertEqual(len(body["content"]), 1)
        self.assertEqual(body["content"][0]["type"], "text")
        self.assertIn("agentbox", body["content"][0]["text"])
        self.assertIn("input_tokens", body["usage"])
        self.assertIn("output_tokens", body["usage"])


class StreamingResponseTests(unittest.TestCase):
    """Streaming requests get an SSE body with the canonical event sequence."""

    def setUp(self) -> None:
        self.addon = _make_addon_with_script(_FIXTURES / "claude_simple.py")

    def test_streaming_text_emits_full_sse_sequence(self) -> None:
        flow = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages",
            body=json.dumps({
                "model": "claude-test",
                "stream": True,
                "messages": [{"role": "user", "content": "hi"}],
            }).encode(),
        )
        # Bypass turn 0 (which has a tool_use); test turn 1 (final text).
        self.addon.turn = 1
        self.addon.request(flow)
        response = _resp(flow)
        self.assertEqual(
            response.headers.get("Content-Type"), "text/event-stream",
        )
        events = _parse_sse(response.get_content() or b"")
        types = [e[0] for e in events]
        self.assertEqual(types[0], "message_start")
        self.assertEqual(types[-1], "message_stop")
        self.assertIn("content_block_start", types)
        self.assertIn("content_block_delta", types)
        self.assertIn("content_block_stop", types)
        self.assertIn("message_delta", types)

        # The text_delta payload carries the scripted final text.
        text_deltas = [
            e[1]["delta"]["text"] for e in events
            if e[0] == "content_block_delta"
            and e[1]["delta"].get("type") == "text_delta"
        ]
        self.assertTrue(any("agentbox" in t for t in text_deltas))

    def test_streaming_tool_use_emits_input_json_delta(self) -> None:
        flow = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages",
            body=json.dumps({"stream": True, "messages": []}).encode(),
        )
        # Turn 0 of claude_simple.py has a Read tool_use.
        self.addon.turn = 0
        self.addon.request(flow)
        events = _parse_sse(_resp(flow).get_content() or b"")

        tool_starts = [
            e[1] for e in events
            if e[0] == "content_block_start"
            and e[1]["content_block"].get("type") == "tool_use"
        ]
        self.assertEqual(len(tool_starts), 1)
        self.assertEqual(tool_starts[0]["content_block"]["name"], "Read")

        json_deltas = [
            json.loads(e[1]["delta"]["partial_json"])
            for e in events
            if e[0] == "content_block_delta"
            and e[1]["delta"].get("type") == "input_json_delta"
        ]
        self.assertEqual(json_deltas, [{"file_path": "README.md"}])


class TurnCounterTests(unittest.TestCase):
    """The turn counter advances per intercepted request and reaches the script."""

    def test_turn_counter_advances(self) -> None:
        addon = _make_addon_with_script(_FIXTURES / "claude_simple.py")
        body = json.dumps({"messages": []}).encode()

        flow0 = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages", body=body,
        )
        addon.request(flow0)
        # Turn 0 = tool_use reply.
        body0 = json.loads(_resp(flow0).get_text() or "")
        self.assertEqual(body0["stop_reason"], "tool_use")

        flow1 = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages", body=body,
        )
        addon.request(flow1)
        # Turn 1 = final text reply.
        body1 = json.loads(_resp(flow1).get_text() or "")
        self.assertEqual(body1["stop_reason"], "end_turn")
        self.assertEqual(body1["content"][0]["type"], "text")

        self.assertEqual(addon.turn, 2)


class TranscriptWritingTests(unittest.TestCase):
    """The optional JSONL transcript records every intercepted exchange."""

    def test_transcript_writes_one_line_per_request(self) -> None:
        addon = _make_addon_with_script(_FIXTURES / "claude_simple.py")
        with tempfile.TemporaryDirectory() as tmp:
            transcript = Path(tmp) / "t.jsonl"
            addon.transcript_path = str(transcript)

            body = json.dumps({
                "model": "claude-test",
                "messages": [{"role": "user", "content": "go"}],
            }).encode()
            for _ in range(2):
                flow = _make_flow(
                    "POST", "https://api.anthropic.com/v1/messages",
                    body=body,
                )
                addon.request(flow)

            lines = transcript.read_text("utf-8").splitlines()
            self.assertEqual(len(lines), 2)
            entries = [json.loads(line) for line in lines]
            self.assertEqual(entries[0]["turn"], 0)
            self.assertEqual(entries[1]["turn"], 1)
            self.assertEqual(entries[0]["host"], "api.anthropic.com")
            self.assertEqual(entries[0]["path"], "/v1/messages")
            self.assertEqual(entries[0]["method"], "POST")
            self.assertEqual(
                entries[0]["request_body"]["model"], "claude-test",
            )
            self.assertIn("reply", entries[0])

    def test_no_transcript_when_path_unset(self) -> None:
        addon = _make_addon_with_script(_FIXTURES / "pi_simple.py")
        # No transcript_path -> just don't crash, no file written.
        flow = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages", body=b"{}",
        )
        addon.request(flow)
        self.assertIsNotNone(flow.response)


class ResponseAlreadySetTests(unittest.TestCase):
    """If a previous addon already set ``flow.response`` we must not clobber it."""

    def test_existing_response_is_preserved(self) -> None:
        addon = _make_addon_with_script(_FIXTURES / "pi_simple.py")
        flow = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages", body=b"{}",
        )
        # Simulate an upstream addon that already produced a response.
        from mitmproxy import http
        sentinel = http.Response.make(403, b"blocked\n")
        flow.response = sentinel
        addon.request(flow)
        self.assertIs(flow.response, sentinel)
        self.assertEqual(addon.turn, 0)


class ScriptErrorHandlingTests(unittest.TestCase):
    """Errors inside the script are turned into a 500 with a structured body."""

    def test_script_raises_returns_500(self) -> None:
        addon = MockLLM()

        class _Boom:
            def replies(self, req: dict) -> dict:
                raise RuntimeError("kaboom")

        addon.script = _Boom()
        flow = _make_flow(
            "POST", "https://api.anthropic.com/v1/messages", body=b"{}",
        )
        addon.request(flow)
        response = _resp(flow)
        self.assertEqual(response.status_code, 500)
        body = json.loads(response.get_text() or "")
        self.assertEqual(body["error"]["type"], "mock_script_error")
        self.assertIn("kaboom", body["error"]["message"])


if __name__ == "__main__":
    unittest.main()
