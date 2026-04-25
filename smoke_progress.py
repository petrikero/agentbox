"""Smoke-test the progress renderer against a real pi session JSONL.

Replays an existing pi session file through the line renderer so we can
eyeball the rendered progress output without spinning up Docker.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))

from rich.console import Console

from agentbox.progress.pi import _render_lines


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("usage: python smoke_progress.py <session.jsonl>")
    fixture = Path(sys.argv[1])
    lines = fixture.read_text("utf-8").splitlines()
    console = Console(stderr=False, highlight=False, soft_wrap=True)
    _render_lines(lines, console)


if __name__ == "__main__":
    main()
