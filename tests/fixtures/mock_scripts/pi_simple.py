"""Minimal mock-llm script for the pi e2e test.

Single-turn answer; pi -p uses non-streaming HTTP by default for the
Anthropic Messages API.
"""
from __future__ import annotations


_FINAL_TEXT = "agentbox: experimental sandbox for AI coding agents."


def replies(req: dict) -> dict:
    return {
        "content": [{"type": "text", "text": _FINAL_TEXT}],
        "stop_reason": "end_turn",
    }
