"""Unit tests for the Layer-1 GraphQL operation allowlist.

Covers:
- Default-deny: a missing or empty pattern list for an operation type
  blocks every operation of that type.
- Pattern matching via ``fnmatch`` (exact, prefix, ``*``).
- All structural fail-secure paths: oversized body, invalid JSON,
  batched (array) body, missing/non-string ``query``, GraphQL parse
  errors, multi-operation docs without ``operationName``, named
  fragment spreads at the operation root.
- Aliased fields use the *original* field name.
- Inline fragments at the operation root are resolved (their fields
  are treated as top-level).

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from agentbox.proxy.graphql_operations import (
    OperationVerdict,
    check_operations,
)


def _body(query: str, **extra: object) -> bytes:
    payload: dict = {"query": query}
    payload.update(extra)
    return json.dumps(payload).encode()


# Sane defaults: read everything, write only a curated mutation list.
DEFAULT_CONFIG: dict[str, list[str]] = {
    "queries": ["*"],
    "mutations": [
        "createIssue",
        "createPullRequest",
        "addComment",
        "mergePullRequest",
    ],
    "subscriptions": [],
}


class OperationsAllowedTests(unittest.TestCase):
    """Coverage for the happy path."""

    def test_query_allowed_by_wildcard(self) -> None:
        result = check_operations(
            _body("query { viewer { login } }"), DEFAULT_CONFIG
        )
        self.assertEqual(result.verdict, OperationVerdict.ALLOWED)
        self.assertEqual(result.operation_tag, "query/viewer")

    def test_anonymous_query_allowed(self) -> None:
        # Shorthand `{ viewer }` is implicitly a query per the spec.
        result = check_operations(
            _body("{ viewer { login } }"), DEFAULT_CONFIG
        )
        self.assertEqual(result.verdict, OperationVerdict.ALLOWED)

    def test_listed_mutation_allowed(self) -> None:
        result = check_operations(
            _body(
                'mutation { addComment(input: {subjectId: "X", body: "hi"})'
                " { clientMutationId } }"
            ),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.ALLOWED)
        self.assertEqual(result.operation_tag, "mutation/addComment")

    def test_alias_uses_original_name(self) -> None:
        # `x: createIssue(...)` -> tag is mutation/createIssue, not /x.
        result = check_operations(
            _body(
                'mutation { x: createIssue(input: {repositoryId: "R", title: "t"})'
                " { issue { id } } }"
            ),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.ALLOWED)
        self.assertEqual(result.operation_tag, "mutation/createIssue")

    def test_inline_fragment_resolved(self) -> None:
        result = check_operations(
            _body(
                "mutation { ... on Mutation {"
                ' createIssue(input: {repositoryId: "R", title: "t"})'
                " { issue { id } } } }"
            ),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.ALLOWED)


class OperationsBlockedTests(unittest.TestCase):
    """Coverage for default-deny + pattern-mismatch."""

    def test_unlisted_mutation_blocked(self) -> None:
        result = check_operations(
            _body(
                'mutation { deleteRepository(input: {repositoryId: "R"})'
                " { clientMutationId } }"
            ),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "deleteRepository")
        self.assertEqual(result.operation_tag, "mutation/deleteRepository")

    def test_subscription_blocked_by_empty_list(self) -> None:
        result = check_operations(
            _body("subscription { somethingChanged { id } }"),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "subscription:<blocked>")

    def test_query_blocked_when_queries_omitted(self) -> None:
        # No "queries" key at all -> default-deny for queries.
        result = check_operations(
            _body("query { viewer { login } }"),
            {"mutations": ["*"]},
        )
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "query:<blocked>")

    def test_pattern_prefix_match(self) -> None:
        cfg = {"queries": ["*"], "mutations": ["create*"]}
        ok = check_operations(
            _body(
                'mutation { createIssue(input: {repositoryId: "R", title: "t"})'
                " { issue { id } } }"
            ),
            cfg,
        )
        bad = check_operations(
            _body(
                'mutation { deleteIssue(input: {issueId: "I"})'
                " { clientMutationId } }"
            ),
            cfg,
        )
        self.assertEqual(ok.verdict, OperationVerdict.ALLOWED)
        self.assertEqual(bad.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(bad.detail, "deleteIssue")


class OperationsFailSecureTests(unittest.TestCase):
    """Coverage for parse / size / structural failures."""

    def test_oversized_body(self) -> None:
        body = json.dumps({"query": "query { x }" + " " * (1024 * 1024)}).encode()
        result = check_operations(body, DEFAULT_CONFIG)
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "<too-large>")

    def test_invalid_json(self) -> None:
        result = check_operations(b"not json {", DEFAULT_CONFIG)
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "<unparseable>")

    def test_batched_array_body(self) -> None:
        result = check_operations(
            json.dumps([{"query": "{ viewer }"}]).encode(),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "<batched>")

    def test_missing_query_field(self) -> None:
        # Persisted-query shape: no `query`, just an id/hash.
        result = check_operations(
            json.dumps({"id": "abc123"}).encode(),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "<unparseable>")

    def test_invalid_graphql(self) -> None:
        result = check_operations(_body("not valid graphql"), DEFAULT_CONFIG)
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "<unparseable>")

    def test_multi_op_without_operation_name(self) -> None:
        result = check_operations(
            _body(
                "query A { viewer { login } } "
                "query B { rateLimit { remaining } }"
            ),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "<operation-name-invalid>")

    def test_multi_op_with_operation_name(self) -> None:
        result = check_operations(
            _body(
                "query A { viewer { login } } "
                "query B { rateLimit { remaining } }",
                operationName="B",
            ),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.ALLOWED)
        self.assertEqual(result.operation_tag, "query/rateLimit")

    def test_named_fragment_spread_blocked(self) -> None:
        result = check_operations(
            _body(
                "mutation { ...MyFrag } "
                'fragment MyFrag on Mutation { createIssue(input: {repositoryId: "R", title: "t"}) { issue { id } } }'
            ),
            DEFAULT_CONFIG,
        )
        self.assertEqual(result.verdict, OperationVerdict.BLOCKED)
        self.assertEqual(result.detail, "<fragment-spread>")


if __name__ == "__main__":
    unittest.main()
