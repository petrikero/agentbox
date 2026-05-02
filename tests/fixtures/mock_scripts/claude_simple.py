"""Minimal mock-llm script for the claude e2e test.

Two-turn flow: read README, then summarise. The Read tool result is
fabricated by the agent runtime (claude executes the tool itself);
we only script the assistant turns.
"""
from __future__ import annotations


_FINAL_TEXT = (
    "agentbox is an experimental sandbox launcher for AI coding agents."
)


def replies(req: dict) -> dict:
    turn = req["turn"]
    if turn == 0:
        return {
            "content": [
                {"type": "text", "text": "Reading README to summarise the repo."},
                {
                    "type": "tool_use",
                    "id": "toolu_mock_readme",
                    "name": "Read",
                    "input": {"file_path": "README.md"},
                },
            ],
            "stop_reason": "tool_use",
        }
    return {
        "content": [{"type": "text", "text": _FINAL_TEXT}],
        "stop_reason": "end_turn",
    }
