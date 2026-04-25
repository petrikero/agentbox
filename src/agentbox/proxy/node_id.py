# Ported from airut (https://github.com/airutorg/airut) — MIT licensed,
# Copyright (c) 2026 Pyry Haulos. Reused here under the same MIT terms;
# see https://opensource.org/licenses/MIT.
#
# This file is intentionally a near-verbatim port; please send upstream
# fixes to airut as well as here so the two implementations don't drift.

"""GitHub GraphQL node ID decoding.

GitHub's new-format node IDs encode type and ownership information::

    TYPE_PREFIX + "_" + base64(msgpack([0, repo_db_id, ...]))

For repository-scoped objects (Issues, PRs, Discussions, Comments,
etc.), the msgpack payload contains the parent repository's database
ID at index 1. This lets the proxy verify node ownership without an
API call -- the foundation for per-repo / per-PR / per-issue scoping
of GitHub's GraphQL endpoint, which all flows over a single
``/graphql`` URL.

The format is not officially documented but has been stable since
GitHub's 2021 "new global ID format" migration. This module is
**fail-secure**: anything that *looks* like a node ID but cannot be
decoded raises ``ValueError`` so the caller can block the request.

The hand-rolled msgpack decoder covers only the subset of types
GitHub actually emits (fixarray + small ints + short strings); any
unsupported byte raises ``ValueError`` -- if GitHub ever extends the
format, the proxy fails closed instead of silently letting a new
shape past the scope check.
"""

from __future__ import annotations

import base64
import re
import struct


# Pattern for GitHub new-format node IDs: 1-6 uppercase letters,
# underscore, then base64 payload (at least 4 characters).
_NODE_ID_RE = re.compile(r"^[A-Z]{1,6}_[A-Za-z0-9+/=_-]{4,}$")

# Known prefixes for objects that do NOT belong to a repository.
# Their msgpack payload doesn't put a repo DB id at index 1, so we
# skip them rather than try to decode and reason about them.
_NON_REPO_PREFIXES = frozenset({"U", "O", "T", "BOT", "EMU"})


def is_non_repo_node_id(value: str) -> bool:
    """Return ``True`` if ``value`` is a known non-repo-scoped node ID.

    Used by the scope checker to distinguish "known safe to skip"
    (users, orgs, teams, bots, EMU users) from "unrecognized format"
    (which the caller must block).
    """
    if not _NODE_ID_RE.match(value):
        return False
    prefix = value.split("_", 1)[0]
    return prefix in _NON_REPO_PREFIXES


def decode_repo_db_id(node_id: str) -> int | None:
    """Extract the parent repository database ID from a node ID.

    Returns the integer DB ID of the parent repository for repo-scoped
    types (R_, I_, PR_, IC_, D_, C_, PRRC_, ...). Returns ``None`` for
    values that aren't node IDs at all and for known non-repo-scoped
    types (U_, O_, T_, BOT_, EMU_).

    Raises ``ValueError`` if the value matches the node-ID shape but
    can't be decoded -- callers must treat that as a hard block.
    """
    if not _NODE_ID_RE.match(node_id):
        return None  # Not a node ID

    prefix, payload = node_id.split("_", 1)

    if prefix in _NON_REPO_PREFIXES:
        return None  # Not repo-scoped

    # GitHub uses URL-safe base64 (- instead of +, _ instead of /),
    # and strips padding. Add it back before decoding.
    try:
        raw = base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
    except Exception as exc:
        raise ValueError(
            f"base64 decode failed for node ID {node_id!r}"
        ) from exc

    try:
        arr = _decode_msgpack_array(raw)
    except Exception as exc:
        raise ValueError(
            f"msgpack decode failed for node ID {node_id!r}"
        ) from exc

    if len(arr) < 2:
        raise ValueError(
            f"unexpected array length {len(arr)} for node ID {node_id!r}"
        )

    repo_db_id = arr[1]
    if not isinstance(repo_db_id, int):
        raise ValueError(f"non-integer repo_db_id in node ID {node_id!r}")

    return repo_db_id


def repo_db_ids_from_node_ids(node_ids: frozenset[str]) -> frozenset[int]:
    """Convert a set of repository node IDs (``R_xxx``) to DB IDs.

    Non-``R_`` IDs are silently dropped so the launcher can pass in
    a mixed set without filtering. Raises ``ValueError`` if any
    ``R_``-prefixed node ID can't be decoded.
    """
    db_ids: list[int] = []
    for node_id in node_ids:
        if not node_id.startswith("R_"):
            continue
        db_id = decode_repo_db_id(node_id)
        if db_id is not None:
            db_ids.append(db_id)
    return frozenset(db_ids)


def _decode_msgpack_array(raw: bytes) -> list[int | str]:
    """Minimal msgpack decoder for GitHub node ID payloads.

    Only handles the subset GitHub actually emits: fixarray of
    positive integers (fixint, uint16/32/64), int32, and short
    strings (fixstr, str8). Anything else raises ``ValueError`` --
    fail-secure against future format changes.
    """
    if not raw:
        raise ValueError("empty payload")

    if not (0x90 <= raw[0] <= 0x9F):
        raise ValueError(f"expected fixarray, got 0x{raw[0]:02x}")

    arr_len = raw[0] & 0x0F
    result: list[int | str] = []
    i = 1

    for _ in range(arr_len):
        if i >= len(raw):
            raise ValueError("truncated array")
        byte = raw[i]
        if byte <= 0x7F:  # positive fixint (0-127)
            result.append(byte)
            i += 1
        elif byte == 0xCD:  # uint16
            result.append(struct.unpack(">H", raw[i + 1 : i + 3])[0])
            i += 3
        elif byte == 0xCE:  # uint32
            result.append(struct.unpack(">I", raw[i + 1 : i + 5])[0])
            i += 5
        elif byte == 0xCF:  # uint64
            result.append(struct.unpack(">Q", raw[i + 1 : i + 9])[0])
            i += 9
        elif byte == 0xD2:  # int32
            result.append(struct.unpack(">i", raw[i + 1 : i + 5])[0])
            i += 5
        elif 0xA0 <= byte <= 0xBF:  # fixstr (0-31 bytes)
            slen = byte & 0x1F
            if i + 1 + slen > len(raw):
                raise ValueError("truncated string")
            result.append(raw[i + 1 : i + 1 + slen].decode("utf-8"))
            i += 1 + slen
        elif byte == 0xD9:  # str8
            if i + 2 > len(raw):
                raise ValueError("truncated string")
            slen = raw[i + 1]
            if i + 2 + slen > len(raw):
                raise ValueError("truncated string")
            result.append(raw[i + 2 : i + 2 + slen].decode("utf-8"))
            i += 2 + slen
        else:
            raise ValueError(f"unhandled msgpack type 0x{byte:02x}")

    return result
