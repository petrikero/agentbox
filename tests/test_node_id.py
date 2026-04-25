# Test vectors and case structure ported from airut
# (https://github.com/airutorg/airut/blob/main/tests/proxy/test_node_id.py)
# -- MIT licensed, Copyright (c) 2026 Pyry Haulos. Adapted to unittest
# to match the rest of the agentbox test suite (no pytest dependency).

"""Unit tests for the GitHub node-ID decoder.

Covers:
- ``_NODE_ID_RE``: which strings the proxy treats as node IDs at all.
- ``is_non_repo_node_id``: the U_/O_/T_/BOT_/EMU_ skip-list.
- ``_decode_msgpack_array``: every byte-marker the decoder accepts,
  plus every truncation/unhandled-type failure mode.
- ``decode_repo_db_id``: real-world repo-scoped node IDs (R_, I_, PR_,
  IC_, D_, C_), URL-safe base64 with both ``-`` and ``_`` payload
  characters, and the fail-secure ``ValueError`` paths (bad base64,
  bad msgpack, short array, non-integer repo_db_id).
- ``repo_db_ids_from_node_ids``: bulk launcher-side conversion.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import base64
import struct
import sys
import unittest
from pathlib import Path

# Prefer the in-tree source over any cached install in site-packages.
_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox.proxy.node_id import (
    _NODE_ID_RE,
    _decode_msgpack_array,
    decode_repo_db_id,
    is_non_repo_node_id,
    repo_db_ids_from_node_ids,
)


# -- Test fixtures: real and synthetic node IDs ---------------------
# Same vectors airut uses, so the two test suites stay in sync.

REPO_1_DB_ID = 1149106347
REPO_2_DB_ID = 1181584653
EVIL_REPO_DB_ID = 999999999

# URL-safe base64 with '-' and '_' in the payload -- GitHub uses
# URL-safe base64 and these vectors exercise both substitutions.
URLSAFE_REPO_DB_ID = 1149100024
URLSAFE_REPO_ID = "R_kgDORH3f-A"
URLSAFE_ISSUE_ID = "I_kwDORH3f-M4AADA5"
URLSAFE_UNDERSCORE_REPO_DB_ID = 1149100028
URLSAFE_UNDERSCORE_REPO_ID = "R_kgDORH3f_A"

# Node IDs for in-scope repositories.
ISSUE_IN_SCOPE_1 = "I_kwDORH34q80wOQ"
PR_IN_SCOPE_2 = "PR_kwDORm2NDc4AAQky"
COMMENT_IN_SCOPE_1 = "IC_kwDORH34q80rZw"
DISCUSSION_IN_SCOPE_2 = "D_kwDORm2NDc1Wzg"
COMMIT_IN_SCOPE_1 = "C_kwDORH34q6xhYmMxMjNkZWY0NTY"

# Node IDs for an out-of-scope ("evil") repository.
ISSUE_EVIL = "I_kwDOO5rJ/84AAYaf"

# Non-repo-scoped IDs.
USER_ID = "U_kgDOAAjmPw"
ORG_ID = "O_kgDNMDk"


class NodeIdPatternTests(unittest.TestCase):
    """Coverage for ``_NODE_ID_RE``: what counts as a node ID."""

    def test_matches_valid_node_ids(self) -> None:
        for value in (
            "R_kgDORH34qw",
            "I_kwDORH34q80wOQ",
            "PR_kwDORm2NDc4AAQky",
            "IC_kwDORH34q80rZw",
            "PRRC_kwABCDEF",
            URLSAFE_REPO_ID,
            URLSAFE_UNDERSCORE_REPO_ID,
            URLSAFE_ISSUE_ID,
            USER_ID,
            ORG_ID,
        ):
            with self.subTest(value=value):
                self.assertIsNotNone(_NODE_ID_RE.match(value))

    def test_rejects_non_node_ids(self) -> None:
        for value in (
            "not-a-node-id",
            "abc_xyz",  # lowercase prefix
            "R_ab",  # payload too short (< 4 chars)
            "12345",
            "",
            "TOOLONG_abcdef",  # prefix > 6 chars
            "R_",  # no payload
            "clientMutationId-value",
            "550e8400-e29b-41d4-a716-446655440000",  # UUID
        ):
            with self.subTest(value=value):
                self.assertIsNone(_NODE_ID_RE.match(value))


class IsNonRepoNodeIdTests(unittest.TestCase):
    """Coverage for the U_/O_/T_/BOT_/EMU_ skip-list."""

    def test_known_non_repo_types(self) -> None:
        for value in (
            USER_ID,
            ORG_ID,
            "T_kgDOAbcdef",  # Team
            "BOT_kgDOAbcd",  # Bot
            "EMU_kgDOAbcd",  # EMU user
        ):
            with self.subTest(value=value):
                self.assertTrue(is_non_repo_node_id(value))

    def test_non_matching_values(self) -> None:
        for value in (
            "R_kgDORH34qw",  # repo -- repo-scoped, not "non-repo"
            ISSUE_IN_SCOPE_1,
            PR_IN_SCOPE_2,
            "not-a-node-id",
            "",
            "12345",
            "abc_xyz",
            "TOOLONG_abcdef",
            "550e8400-e29b-41d4-a716-446655440000",
        ):
            with self.subTest(value=value):
                self.assertFalse(is_non_repo_node_id(value))


class DecodeMsgpackArrayTests(unittest.TestCase):
    """Coverage for the hand-rolled msgpack decoder."""

    def test_fixint(self) -> None:
        # [0, 42]
        self.assertEqual(
            _decode_msgpack_array(bytes([0x92, 0x00, 0x2A])), [0, 42]
        )

    def test_uint16(self) -> None:
        raw = bytes([0x92, 0x00, 0xCD]) + struct.pack(">H", 1000)
        self.assertEqual(_decode_msgpack_array(raw), [0, 1000])

    def test_uint32(self) -> None:
        raw = bytes([0x92, 0x00, 0xCE]) + struct.pack(">I", 1149106347)
        self.assertEqual(_decode_msgpack_array(raw), [0, 1149106347])

    def test_uint64(self) -> None:
        raw = bytes([0x92, 0x00, 0xCF]) + struct.pack(">Q", 2**33)
        self.assertEqual(_decode_msgpack_array(raw), [0, 2**33])

    def test_int32(self) -> None:
        raw = bytes([0x92, 0x00, 0xD2]) + struct.pack(">i", -1)
        self.assertEqual(_decode_msgpack_array(raw), [0, -1])

    def test_fixstr(self) -> None:
        # [0, 42, "abc"]
        raw = bytes([0x93, 0x00, 0x2A, 0xA3]) + b"abc"
        self.assertEqual(_decode_msgpack_array(raw), [0, 42, "abc"])

    def test_str8(self) -> None:
        s = "x" * 40
        raw = bytes([0x93, 0x00, 0x2A, 0xD9, 40]) + s.encode()
        self.assertEqual(_decode_msgpack_array(raw), [0, 42, s])

    def test_empty_payload_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "empty payload"):
            _decode_msgpack_array(b"")

    def test_not_fixarray_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected fixarray"):
            _decode_msgpack_array(bytes([0x80]))  # fixmap

    def test_truncated_array_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "truncated array"):
            _decode_msgpack_array(bytes([0x93, 0x00]))

    def test_truncated_fixstr_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "truncated string"):
            # fixstr claiming 5 bytes with only 2 remaining
            _decode_msgpack_array(bytes([0x92, 0x00, 0xA5, 0x61, 0x62]))

    def test_truncated_str8_header_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "truncated string"):
            _decode_msgpack_array(bytes([0x91, 0xD9]))

    def test_truncated_str8_body_raises(self) -> None:
        with self.assertRaisesRegex(ValueError, "truncated string"):
            # str8 claiming 10 bytes with only 3 remaining
            _decode_msgpack_array(
                bytes([0x92, 0x00, 0xD9, 10, 0x61, 0x62])
            )

    def test_unhandled_type_raises(self) -> None:
        # 0xC0 is msgpack nil -- not in our supported subset.
        with self.assertRaisesRegex(ValueError, "unhandled msgpack type"):
            _decode_msgpack_array(bytes([0x91, 0xC0]))


class DecodeRepoDbIdTests(unittest.TestCase):
    """Coverage for ``decode_repo_db_id`` -- the load-bearing public API."""

    def test_repository_id(self) -> None:
        self.assertEqual(decode_repo_db_id("R_kgDORH34qw"), REPO_1_DB_ID)

    def test_issue_id(self) -> None:
        self.assertEqual(decode_repo_db_id(ISSUE_IN_SCOPE_1), REPO_1_DB_ID)

    def test_pull_request_id(self) -> None:
        self.assertEqual(decode_repo_db_id(PR_IN_SCOPE_2), REPO_2_DB_ID)

    def test_issue_comment_id(self) -> None:
        self.assertEqual(
            decode_repo_db_id(COMMENT_IN_SCOPE_1), REPO_1_DB_ID
        )

    def test_discussion_id(self) -> None:
        self.assertEqual(
            decode_repo_db_id(DISCUSSION_IN_SCOPE_2), REPO_2_DB_ID
        )

    def test_commit_id(self) -> None:
        self.assertEqual(decode_repo_db_id(COMMIT_IN_SCOPE_1), REPO_1_DB_ID)

    def test_urlsafe_base64_hyphen_repo(self) -> None:
        self.assertEqual(
            decode_repo_db_id(URLSAFE_REPO_ID), URLSAFE_REPO_DB_ID
        )

    def test_urlsafe_base64_hyphen_issue(self) -> None:
        self.assertEqual(
            decode_repo_db_id(URLSAFE_ISSUE_ID), URLSAFE_REPO_DB_ID
        )

    def test_urlsafe_base64_underscore_repo(self) -> None:
        self.assertEqual(
            decode_repo_db_id(URLSAFE_UNDERSCORE_REPO_ID),
            URLSAFE_UNDERSCORE_REPO_DB_ID,
        )

    def test_evil_repo_issue(self) -> None:
        self.assertEqual(decode_repo_db_id(ISSUE_EVIL), EVIL_REPO_DB_ID)

    def test_user_id_returns_none(self) -> None:
        self.assertIsNone(decode_repo_db_id(USER_ID))

    def test_org_id_returns_none(self) -> None:
        self.assertIsNone(decode_repo_db_id(ORG_ID))

    def test_not_a_node_id_returns_none(self) -> None:
        self.assertIsNone(decode_repo_db_id("not-a-node-id"))

    def test_uuid_returns_none(self) -> None:
        self.assertIsNone(
            decode_repo_db_id("550e8400-e29b-41d4-a716-446655440000")
        )

    def test_empty_string_returns_none(self) -> None:
        self.assertIsNone(decode_repo_db_id(""))

    def test_bad_base64_raises(self) -> None:
        # 1 data char is invalid base64 length (1 more than a
        # multiple of 4 after stripping padding).
        with self.assertRaisesRegex(ValueError, "base64 decode failed"):
            decode_repo_db_id("R_a===")

    def test_bad_msgpack_raises(self) -> None:
        # Valid base64, payload is fixmap (0x80) not fixarray.
        bad_payload = (
            base64.b64encode(b"\x80\x00\x00\x00").rstrip(b"=").decode()
        )
        with self.assertRaisesRegex(ValueError, "msgpack decode failed"):
            decode_repo_db_id(f"R_{bad_payload}")

    def test_short_array_raises(self) -> None:
        # Single-element array [42].
        payload = (
            base64.b64encode(bytes([0x91, 0x2A, 0x00])).rstrip(b"=").decode()
        )
        with self.assertRaisesRegex(ValueError, "unexpected array length"):
            decode_repo_db_id(f"R_{payload}")

    def test_non_integer_repo_db_id_raises(self) -> None:
        # [0, "bad"] -- index 1 must be int, not str.
        raw = bytes([0x92, 0x00, 0xA3]) + b"bad"
        payload = base64.b64encode(raw).rstrip(b"=").decode()
        with self.assertRaisesRegex(ValueError, "non-integer repo_db_id"):
            decode_repo_db_id(f"R_{payload}")


class RepoDbIdsFromNodeIdsTests(unittest.TestCase):
    """Coverage for the launcher-side bulk converter."""

    def test_basic_conversion(self) -> None:
        self.assertEqual(
            repo_db_ids_from_node_ids(
                frozenset({"R_kgDORH34qw", "R_kgDORm2NDQ"})
            ),
            frozenset({REPO_1_DB_ID, REPO_2_DB_ID}),
        )

    def test_non_r_ids_ignored(self) -> None:
        self.assertEqual(
            repo_db_ids_from_node_ids(
                frozenset({"R_kgDORH34qw", "I_kwDORH34q80wOQ"})
            ),
            frozenset({REPO_1_DB_ID}),
        )

    def test_urlsafe_base64_conversion(self) -> None:
        self.assertEqual(
            repo_db_ids_from_node_ids(
                frozenset({URLSAFE_REPO_ID, URLSAFE_UNDERSCORE_REPO_ID})
            ),
            frozenset(
                {URLSAFE_REPO_DB_ID, URLSAFE_UNDERSCORE_REPO_DB_ID}
            ),
        )

    def test_empty_set(self) -> None:
        self.assertEqual(
            repo_db_ids_from_node_ids(frozenset()), frozenset()
        )

    def test_bad_r_id_raises(self) -> None:
        bad_payload = (
            base64.b64encode(b"\x80\x00\x00\x00").rstrip(b"=").decode()
        )
        with self.assertRaises(ValueError):
            repo_db_ids_from_node_ids(frozenset({f"R_{bad_payload}"}))


if __name__ == "__main__":
    unittest.main()
