"""Shared rendering primitives for the live progress trackers.

Pi (file-tail) and claude (stdout-stream) speak different transports
and emit different event shapes, but the surface formatting on the
terminal -- truncation, timestamp parsing, duration / token-count
formatting, debug logging -- is the same. Those primitives live here
so the two trackers can share them without depending on each other.
"""

from __future__ import annotations

import os
from datetime import datetime

from rich.console import Console
from rich.markup import escape


# Common poll interval for both trackers.
_POLL_INTERVAL = 0.1

# ``AGENTBOX_DEBUG=1`` surfaces watcher heartbeats and other diagnostics.
_DEBUG = os.environ.get("AGENTBOX_DEBUG", "").lower() in {"1", "true", "yes"}


def _debug(console: Console, msg: str) -> None:
    if _DEBUG:
        console.print(f"[dim cyan]debug:[/] [dim]{escape(msg)}[/]")


def _flatten(text: str) -> str:
    """Collapse whitespace runs (incl. newlines) into single spaces.

    Width-aware truncation is delegated to ``console.print`` via
    ``no_wrap=True, overflow="ellipsis"`` at each call site, so each
    line gets cut to fit the actual terminal width rather than a
    hardcoded cap.
    """
    return " ".join(text.split())


def _printw(console: Console, line: str) -> None:
    """Print one line, ellipsis-truncated to the actual terminal width."""
    console.print(line, no_wrap=True, overflow="ellipsis")


def _trunc_oneline(text: str, limit: int) -> str:
    """Collapse whitespace and truncate to a single line of ``limit`` chars."""
    collapsed = _flatten(text)
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 3] + "..."


def _fmt_duration(ms: int) -> str:
    """Format milliseconds as a human-readable duration."""
    s = ms / 1000
    if s < 60:
        return f"{s:.0f}s"
    m = int(s) // 60
    s = int(s) % 60
    if m < 60:
        return f"{m}m{s:02d}s"
    h = m // 60
    m = m % 60
    return f"{h}h{m:02d}m"


def _fmt_tokens(n: int) -> str:
    """Compact token count: 47200 -> '47k', 142500 -> '142k'."""
    if n < 1000:
        return str(n)
    if n < 1_000_000:
        return f"{n // 1000}k"
    return f"{n / 1_000_000:.1f}M"


def _event_dt(event: dict) -> datetime | None:
    """Parse an event's ``timestamp`` into an aware ``datetime``, or None."""
    raw = event.get("timestamp")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone()
    except ValueError:
        return None


def _event_ts(event: dict) -> str:
    """Return ``HH:MM:SS`` for ``event``'s timestamp, or wall-clock now."""
    dt = _event_dt(event)
    if dt:
        return dt.strftime("%H:%M:%S")
    return datetime.now().strftime("%H:%M:%S")
