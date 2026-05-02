"""Unit tests for the Layer-2 GraphQL repository scope check.

Covers each of the four sub-layers in ``check_repo_scope``:

- Layer 0: ``repository(owner, name)`` selections, plus the chained
  ``organization(login).repository(name)`` shape and the unresolvable
  ``viewer.repository(name)`` fail-secure block.
- Layer 1: ``repositoryId`` inline values, variable references, and
  variable-object scans.
- Layer 2: ``repositoryNameWithOwner`` (case-insensitive).
- Layer 3: every other ``*Id`` / ``*Ids`` field, decoded via the node
  ID decoder; covers the in-scope path, the out-of-scope path,
  ``labelIds`` list values, the U_-prefix non-repo skip, and the
  fail-secure block on undecodable / unknown-prefix IDs.

Plus the structural fail-secure paths: oversized body, invalid JSON,
missing ``query``, undecodable variables, ``clientMutationId`` skip.

Synthetic node-ID vectors mirror the ones in ``test_node_id.py`` so
the two suites stay in lock-step. Tail of node-ID DB IDs:

    R_kgDORH34qw -> repo_db_id 1149106347 (repo 1)
    R_kgDORm2NDQ -> repo_db_id 1181584653 (repo 2)
    I_kwDOO5rJ/84AAYaf -> repo_db_id 999999999 (evil)

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

from agentbox.proxy.graphql_scope import (
    ScopeResult,
    ScopeVerdict,
    check_repo_scope,
)


ALLOWED_IDS = frozenset({"R_kgDORH34qw", "R_kgDORm2NDQ"})
ALLOWED_NAMES = frozenset({"my-org/repo-one", "my-org/repo-two"})

ISSUE_IN_SCOPE = "I_kwDORH34q80wOQ"           # repo 1
PR_IN_SCOPE = "PR_kwDORm2NDc4AAQky"           # repo 2
COMMENT_IN_SCOPE = "IC_kwDORH34q80rZw"        # repo 1
ISSUE_EVIL = "I_kwDOO5rJ/84AAYaf"             # evil repo
USER_ID = "U_kgDOAAjmPw"                      # non-repo


def _body(query: str, variables: dict | None = None) -> bytes:
    payload: dict = {"query": query}
    if variables is not None:
        payload["variables"] = variables
    return json.dumps(payload).encode()


def _allowed() -> ScopeResult:
    return ScopeResult(ScopeVerdict.ALLOWED)


def _oos(detail: str) -> ScopeResult:
    return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, detail)


def _too_deep() -> ScopeResult:
    return ScopeResult(ScopeVerdict.PARSE_ERROR, "<too-deep>")


class Layer0RepositoryFieldTests(unittest.TestCase):
    """Coverage for the ``repository(owner, name)`` selection check."""

    def test_top_level_repository_in_scope(self) -> None:
        body = _body(
            'query { repository(owner: "my-org", name: "repo-one")'
            " { id } }"
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _allowed(),
        )

    def test_top_level_repository_out_of_scope(self) -> None:
        body = _body(
            'query { repository(owner: "evil", name: "repo")'
            " { id } }"
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _oos("evil/repo"),
        )

    def test_case_insensitive_name_match(self) -> None:
        body = _body(
            'query { repository(owner: "My-Org", name: "Repo-One")'
            " { id } }"
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _allowed(),
        )

    def test_chained_organization_repository(self) -> None:
        body = _body(
            'query { organization(login: "my-org") {'
            ' repository(name: "repo-one") { id } } }'
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _allowed(),
        )

    def test_chained_organization_repository_out_of_scope(self) -> None:
        body = _body(
            'query { organization(login: "evil") {'
            ' repository(name: "repo") { id } } }'
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _oos("evil/repo"),
        )

    def test_viewer_repository_blocked(self) -> None:
        # `viewer.repository(name: "x")` -- no `login` argument
        # available on the immediate parent -> fail-secure block.
        body = _body(
            'query { viewer { repository(name: "repo-one") { id } } }'
        )
        result = check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES)
        self.assertEqual(result.verdict, ScopeVerdict.OUT_OF_SCOPE)
        self.assertEqual(result.detail, "<unknown>/repo-one")

    def test_repository_via_variables(self) -> None:
        body = _body(
            "query Q($o: String!, $n: String!) {"
            " repository(owner: $o, name: $n) { id } }",
            variables={"o": "my-org", "n": "repo-two"},
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _allowed(),
        )

    def test_repository_via_unbound_variable(self) -> None:
        body = _body(
            "query Q($o: String!, $n: String!) {"
            " repository(owner: $o, name: $n) { id } }",
            variables={"o": "my-org"},
        )
        result = check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES)
        self.assertEqual(
            result.verdict, ScopeVerdict.UNRESOLVED_VARIABLE
        )

    def test_repository_field_without_args_ignored(self) -> None:
        # Output-only `.repository` (e.g. on Commit/Ref) has no args
        # and addresses no new repo -- must not block.
        body = _body(
            "query { node(id: \"" + COMMENT_IN_SCOPE + "\") {"
            " ... on IssueComment { repository { id } } } }"
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _allowed(),
        )


class Layer1RepositoryIdTests(unittest.TestCase):
    """Coverage for ``repositoryId`` field handling."""

    def test_inlined_in_scope(self) -> None:
        body = _body(
            'mutation { createIssue(input: {repositoryId: "R_kgDORH34qw",'
            ' title: "t"}) { issue { id } } }'
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _allowed())

    def test_inlined_out_of_scope(self) -> None:
        body = _body(
            'mutation { createIssue(input: {repositoryId: "R_evil",'
            ' title: "t"}) { issue { id } } }'
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS), _oos("R_evil")
        )

    def test_variable_reference_in_scope(self) -> None:
        body = _body(
            "mutation Q($rid: ID!) { createIssue(input: {repositoryId: $rid,"
            ' title: "t"}) { issue { id } } }',
            variables={"rid": "R_kgDORm2NDQ"},
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _allowed())

    def test_variable_reference_out_of_scope(self) -> None:
        body = _body(
            "mutation Q($rid: ID!) { createIssue(input: {repositoryId: $rid,"
            ' title: "t"}) { issue { id } } }',
            variables={"rid": "R_evil"},
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS), _oos("R_evil")
        )

    def test_variable_object_repositoryid_in_scope(self) -> None:
        # createIssue takes the whole input as a variable; the proxy
        # has to scan the variable JSON for `repositoryId` to catch
        # this shape (the AST has no inlined repositoryId).
        body = _body(
            "mutation Q($input: CreateIssueInput!) {"
            " createIssue(input: $input) { issue { id } } }",
            variables={
                "input": {"repositoryId": "R_kgDORH34qw", "title": "t"}
            },
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _allowed())

    def test_variable_object_repositoryid_out_of_scope(self) -> None:
        body = _body(
            "mutation Q($input: CreateIssueInput!) {"
            " createIssue(input: $input) { issue { id } } }",
            variables={
                "input": {"repositoryId": "R_evil", "title": "t"}
            },
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS), _oos("R_evil")
        )


class Layer2RepositoryNameWithOwnerTests(unittest.TestCase):
    """Coverage for ``repositoryNameWithOwner`` field handling."""

    def test_inlined_in_scope(self) -> None:
        body = _body(
            "mutation { createCommitOnBranch(input: { branch: {"
            ' repositoryNameWithOwner: "my-org/repo-one",'
            ' branchName: "main" } }) { clientMutationId } }'
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _allowed(),
        )

    def test_inlined_out_of_scope(self) -> None:
        body = _body(
            "mutation { createCommitOnBranch(input: { branch: {"
            ' repositoryNameWithOwner: "evil/repo",'
            ' branchName: "main" } }) { clientMutationId } }'
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _oos("evil/repo"),
        )

    def test_case_insensitive(self) -> None:
        body = _body(
            "mutation { createCommitOnBranch(input: { branch: {"
            ' repositoryNameWithOwner: "MY-ORG/REPO-ONE",'
            ' branchName: "main" } }) { clientMutationId } }'
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS, ALLOWED_NAMES),
            _allowed(),
        )


class Layer3NodeIdOwnershipTests(unittest.TestCase):
    """Coverage for the ``*Id``/``*Ids`` node-ID ownership check."""

    def test_addcomment_subjectid_in_scope(self) -> None:
        body = _body(
            'mutation { addComment(input: {subjectId: "' + PR_IN_SCOPE + '",'
            ' body: "hi"}) { clientMutationId } }'
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _allowed())

    def test_addcomment_subjectid_out_of_scope(self) -> None:
        body = _body(
            'mutation { addComment(input: {subjectId: "' + ISSUE_EVIL + '",'
            ' body: "hi"}) { clientMutationId } }'
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS), _oos(ISSUE_EVIL)
        )

    def test_user_id_skipped(self) -> None:
        # assigneeIds carrying a U_ user ID -- non-repo-scoped, so
        # the scope check must NOT block on it.
        body = _body(
            'mutation { updateIssue(input: {id: "' + ISSUE_IN_SCOPE + '",'
            ' assigneeIds: ["' + USER_ID + '"]}) { clientMutationId } }'
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _allowed())

    def test_label_ids_list_in_scope(self) -> None:
        body = _body(
            'mutation { addLabelsToLabelable(input: {'
            ' labelableId: "' + ISSUE_IN_SCOPE + '",'
            ' labelIds: ["' + COMMENT_IN_SCOPE + '"]'
            " }) { clientMutationId } }"
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _allowed())

    def test_label_ids_list_one_out_of_scope(self) -> None:
        body = _body(
            'mutation { addLabelsToLabelable(input: {'
            ' labelableId: "' + ISSUE_IN_SCOPE + '",'
            ' labelIds: ["' + COMMENT_IN_SCOPE + '", "' + ISSUE_EVIL + '"]'
            " }) { clientMutationId } }"
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS), _oos(ISSUE_EVIL)
        )

    def test_undecodable_node_id_blocked(self) -> None:
        # Looks like a node ID (matches regex) but msgpack-decodes to
        # garbage -> fail-secure block.
        body = _body(
            'mutation { addComment(input: {subjectId: "PR_xxxxxxxx",'
            ' body: "hi"}) { clientMutationId } }'
        )
        result = check_repo_scope(body, ALLOWED_IDS)
        self.assertEqual(result.verdict, ScopeVerdict.OUT_OF_SCOPE)
        self.assertEqual(result.detail, "PR_xxxxxxxx")

    def test_client_mutation_id_skipped(self) -> None:
        # clientMutationId is a passthrough field, never a node ID,
        # explicitly excluded from the *Id sweep.
        body = _body(
            'mutation { addComment(input: {subjectId: "' + PR_IN_SCOPE + '",'
            ' body: "hi", clientMutationId: "anything-goes"})'
            " { clientMutationId } }"
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _allowed())

    def test_no_id_values_allowed(self) -> None:
        # Read query with no IDs at all -- nothing for Layer 3 to check,
        # passes through.
        body = _body("query { viewer { login } }")
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _allowed())

    def test_variable_object_node_id_in_scope(self) -> None:
        body = _body(
            "mutation Q($input: AddCommentInput!) {"
            " addComment(input: $input) { clientMutationId } }",
            variables={"input": {"subjectId": PR_IN_SCOPE, "body": "hi"}},
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _allowed())

    def test_variable_object_node_id_out_of_scope(self) -> None:
        body = _body(
            "mutation Q($input: AddCommentInput!) {"
            " addComment(input: $input) { clientMutationId } }",
            variables={"input": {"subjectId": ISSUE_EVIL, "body": "hi"}},
        )
        self.assertEqual(
            check_repo_scope(body, ALLOWED_IDS), _oos(ISSUE_EVIL)
        )


class FailSecureTests(unittest.TestCase):
    """Coverage for body-level fail-secure paths."""

    def test_oversized_body(self) -> None:
        body = (
            json.dumps({"query": "query { x }" + " " * (1024 * 1024)}).encode()
        )
        result = check_repo_scope(body, ALLOWED_IDS)
        self.assertEqual(result.verdict, ScopeVerdict.PARSE_ERROR)
        self.assertEqual(result.detail, "<too-large>")

    def test_invalid_json(self) -> None:
        result = check_repo_scope(b"garbage", ALLOWED_IDS)
        self.assertEqual(result.verdict, ScopeVerdict.PARSE_ERROR)

    def test_missing_query(self) -> None:
        result = check_repo_scope(
            json.dumps({"id": "abc"}).encode(), ALLOWED_IDS
        )
        self.assertEqual(result.verdict, ScopeVerdict.PARSE_ERROR)

    def test_invalid_graphql(self) -> None:
        result = check_repo_scope(_body("not valid"), ALLOWED_IDS)
        self.assertEqual(result.verdict, ScopeVerdict.PARSE_ERROR)


class DeeplyNestedVariablesTests(unittest.TestCase):
    """Pathologically nested ``variables`` must not crash the proxy.

    The variable-scan walkers were rewritten from recursive to
    iterative so a deeply nested body could not blow Python's
    ~1000-frame default recursion limit. But ``check_repo_scope``
    still calls ``json.loads`` on the raw body before the walkers
    ever run, and stdlib ``json`` is itself recursive (one C frame
    per container). Past ``sys.getrecursionlimit()`` the parser
    raises ``RecursionError``, which used to escape and 500 the
    proxy.

    The fix is fail-secure: catch ``RecursionError`` and return a
    PARSE_ERROR / ``<too-deep>`` verdict so the gate 403s the
    request. These tests pin that behaviour.

    Bodies are constructed as raw JSON bytes (not via ``json.dumps``,
    which is also recursive and would crash the test setup itself
    well before reaching the code under test).
    """

    _DEPTH = 5000

    def test_deeply_nested_dict_does_not_recurse(self) -> None:
        # Nest a benign dict 5000 levels deep with no repositoryId
        # anywhere. json.loads RecursionErrors -> _too_deep().
        body = (
            b'{"query":"query Q { viewer { login } }","variables":'
            + b'{"nested":' * self._DEPTH
            + b'{"x":1}'
            + b"}" * self._DEPTH
            + b"}"
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _too_deep())

    def test_deeply_nested_list_does_not_recurse(self) -> None:
        # Same depth but alternating list/dict containers, so the
        # parser hits both code paths on the way down.
        opens: list[bytes] = []
        closes: list[bytes] = []
        for i in range(self._DEPTH):
            if i % 2:
                opens.append(b"[")
                closes.append(b"]")
            else:
                opens.append(b'{"nested":')
                closes.append(b"}")
        body = (
            b'{"query":"query Q { viewer { login } }","variables":{"v":'
            + b"".join(opens)
            + b'{"x":1}'
            + b"".join(reversed(closes))
            + b"}}"
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _too_deep())

    def test_deeply_nested_dict_with_oos_payload_rejected(self) -> None:
        # Even when the leaf hides an out-of-scope subjectId, the
        # body is rejected at parse time -- the walker never runs,
        # which is fine because PARSE_ERROR also fails the gate.
        leaf = json.dumps({"subjectId": ISSUE_EVIL}).encode()
        body = (
            b'{"query":"mutation Q($input: AddCommentInput!) {'
            b" addComment(input: $input) { clientMutationId } }\","
            b'"variables":{"input":'
            + b'{"nested":' * self._DEPTH
            + leaf
            + b"}" * self._DEPTH
            + b"}}"
        )
        self.assertEqual(check_repo_scope(body, ALLOWED_IDS), _too_deep())


if __name__ == "__main__":
    unittest.main()
