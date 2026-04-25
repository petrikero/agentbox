"""Unit tests for the Layer-3 dangerous-ops watchlist.

Covers:
- Exact-match patterns (the common case).
- Glob patterns (``mutation/delete*``, ``mutation/*``).
- Empty / None inputs short-circuit to None (no work, no crash).
- Non-string entries in the pattern list are skipped (fail-secure
  for misconfigured YAML).
- Case sensitivity (GraphQL field names are case-sensitive).

The watchlist is shadow-mode -- it doesn't decide allow/block. The
filter integration test in ``test_filter.py`` confirms a matched
operation is logged and *passed through*, not blocked.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox.proxy.dangerous_operations import check_dangerous


class CheckDangerousTests(unittest.TestCase):
    """Coverage for :func:`check_dangerous`."""

    def test_exact_match(self) -> None:
        self.assertEqual(
            check_dangerous(
                "mutation/mergePullRequest",
                ["mutation/mergePullRequest"],
            ),
            "mutation/mergePullRequest",
        )

    def test_glob_prefix_match(self) -> None:
        self.assertEqual(
            check_dangerous("mutation/deleteRepository", ["mutation/delete*"]),
            "mutation/delete*",
        )

    def test_glob_wildcard_matches_any_mutation(self) -> None:
        self.assertEqual(
            check_dangerous("mutation/createIssue", ["mutation/*"]),
            "mutation/*",
        )

    def test_first_matching_pattern_returned(self) -> None:
        # Order in patterns is the order they're tested; first hit wins.
        self.assertEqual(
            check_dangerous(
                "mutation/mergePullRequest",
                ["mutation/delete*", "mutation/merge*", "mutation/*"],
            ),
            "mutation/merge*",
        )

    def test_no_match_returns_none(self) -> None:
        self.assertIsNone(
            check_dangerous(
                "mutation/createIssue",
                ["mutation/delete*", "mutation/transferRepository"],
            )
        )

    def test_query_does_not_match_mutation_pattern(self) -> None:
        # Patterns are matched against the full type/field tag, so
        # `mutation/foo` does not match a `query/foo` request.
        self.assertIsNone(
            check_dangerous("query/repository", ["mutation/repository"])
        )

    def test_query_pattern_can_match_query(self) -> None:
        # Operators can warn on queries too -- e.g. introspection probes.
        self.assertEqual(
            check_dangerous("query/__schema", ["query/__schema"]),
            "query/__schema",
        )

    def test_case_sensitive(self) -> None:
        # GraphQL field names are case-sensitive per spec.
        self.assertIsNone(
            check_dangerous(
                "mutation/MergePullRequest",
                ["mutation/mergePullRequest"],
            )
        )

    def test_none_tag_short_circuits(self) -> None:
        self.assertIsNone(check_dangerous(None, ["mutation/*"]))

    def test_empty_patterns_short_circuits(self) -> None:
        self.assertIsNone(check_dangerous("mutation/mergePullRequest", []))

    def test_non_string_patterns_skipped(self) -> None:
        # A YAML edit like `dangerous: [42, "mutation/merge*"]` must
        # not crash; the int is silently skipped, the str still works.
        self.assertEqual(
            check_dangerous(
                "mutation/mergePullRequest",
                [42, None, "mutation/merge*"],  # type: ignore[list-item]
            ),
            "mutation/merge*",
        )


if __name__ == "__main__":
    unittest.main()
