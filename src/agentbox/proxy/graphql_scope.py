# Ported from airut (https://github.com/airutorg/airut) — MIT licensed,
# Copyright (c) 2026 Pyry Haulos. Reused here under the same MIT terms;
# see https://opensource.org/licenses/MIT.
#
# This file is intentionally a near-verbatim port; please send upstream
# fixes to airut as well as here so the two implementations don't drift.

"""GraphQL repository scope check (Layer 2 of the /graphql gate).

Parses a GitHub GraphQL request and walks both the AST and the
``variables`` JSON for every value that addresses a repository, then
checks each against the launcher-supplied allowed-repos set. Four
sub-layers, in order:

0. **``repository(owner, name)`` selections.** Catches reads addressed
   by plain string args, including the chained
   ``organization(login).repository(name)`` /
   ``user(login).repository(name)`` /
   ``repositoryOwner(login).repository(name)`` paths.
1. **``repositoryId``** values (string match against allowed node IDs).
2. **``repositoryNameWithOwner``** values (case-insensitive match
   against ``owner/name`` full names; used by mutations like
   ``createCommitOnBranch``).
3. **Every other ``*Id`` / ``*Ids`` field**: decodes the GitHub node
   ID payload (see :mod:`agentbox.proxy.node_id`) and checks the
   embedded parent repo DB ID against the allowed set. Catches
   mutations like ``addComment(input: {subjectId: ...})`` that target
   repo-scoped objects without an explicit ``repositoryId`` field.

Fail-secure throughout: any decode failure, missing variable, or
unrecognized node-ID prefix returns a non-ALLOWED verdict so the
caller can 403 the request.
"""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass

from graphql import parse
from graphql.language import ast as gql_ast
from graphql.language import visitor

from agentbox.proxy.node_id import (
    decode_repo_db_id,
    is_non_repo_node_id,
    repo_db_ids_from_node_ids,
)


class ScopeVerdict(enum.Enum):
    """Result of a GraphQL repository scope check."""

    ALLOWED = "allowed"
    OUT_OF_SCOPE = "out_of_scope"
    PARSE_ERROR = "parse_error"
    UNRESOLVED_VARIABLE = "unresolved_variable"


@dataclass(frozen=True)
class ScopeResult:
    """Structured result from :func:`check_repo_scope`.

    ``detail`` carries the offending node ID / repo full-name (for
    OUT_OF_SCOPE) or a diagnostic label (``"<unparseable>"``,
    ``"<too-large>"``, ``"<unresolved-variable>"``). ``None`` for
    ALLOWED.
    """

    verdict: ScopeVerdict
    detail: str | None = None


_ALLOWED = ScopeResult(ScopeVerdict.ALLOWED)
_PARSE_ERROR = ScopeResult(ScopeVerdict.PARSE_ERROR, "<unparseable>")
_UNRESOLVED = ScopeResult(
    ScopeVerdict.UNRESOLVED_VARIABLE, "<unresolved-variable>"
)
_TOO_LARGE = ScopeResult(ScopeVerdict.PARSE_ERROR, "<too-large>")

_MAX_BODY_SIZE = 1024 * 1024

# Fields ending in "Id" that are NOT GitHub node IDs.
_SKIP_FIELDS = frozenset({"clientMutationId"})


class _StringResolution(enum.Enum):
    """Non-string outcomes of :func:`_resolve_string_value`."""

    UNRESOLVED = "unresolved"
    MALFORMED = "malformed"


def _resolve_string_value(
    value: gql_ast.ValueNode, variables: dict[str, object]
) -> str | _StringResolution:
    """Resolve an AST value or variable reference to a string.

    Returns the literal string for ``StringValueNode``, the bound
    variable's string value for ``VariableNode``,
    :attr:`_StringResolution.UNRESOLVED` if the variable isn't bound,
    or :attr:`_StringResolution.MALFORMED` for any other shape.
    """
    if isinstance(value, gql_ast.StringValueNode):
        return value.value
    if isinstance(value, gql_ast.VariableNode):
        var_name = value.name.value
        if var_name not in variables:
            return _StringResolution.UNRESOLVED
        bound = variables[var_name]
        if isinstance(bound, str):
            return bound
        return _StringResolution.MALFORMED
    return _StringResolution.MALFORMED


def _is_id_field(name: str) -> bool:
    """True if a field name could carry a GitHub node ID.

    Matches ``id``, anything ending in ``Id`` (``subjectId``,
    ``pullRequestId``) or ``Ids`` (``labelIds``, ``assigneeIds``),
    excluding ``clientMutationId``.
    """
    if name in _SKIP_FIELDS:
        return False
    return name == "id" or name.endswith("Id") or name.endswith("Ids")


@dataclass(frozen=True)
class _RepoFieldRef:
    """A ``repository(owner, name)`` selection awaiting resolution.

    ``owner`` is ``None`` when no parent ``login`` argument could be
    located; the reference fail-secure blocks during resolution.
    """

    owner: gql_ast.ValueNode | None
    name: gql_ast.ValueNode


def _find_parent_login_arg(
    ancestors: list[gql_ast.Node],
) -> gql_ast.ValueNode | None:
    """Find the immediate parent ``FieldNode`` and return its ``login``.

    Walks ancestors backwards to the *immediate* parent FieldNode and
    returns its ``login`` arg value, or ``None`` if none reachable.
    Deliberately stops at the immediate parent: a more-distant
    ancestor's ``login`` could refer to a different entity, so we
    fail-secure rather than guess.
    """
    for ancestor in reversed(ancestors):
        if isinstance(ancestor, gql_ast.FieldNode):
            for arg in ancestor.arguments or ():
                if arg.name.value == "login":
                    return arg.value
            return None
    return None


class _IdFieldFinder(visitor.Visitor):
    """AST visitor that collects every value targeting a repository.

    Three buckets mirror the four sub-layers of :func:`check_repo_scope`:
    ``repo_field_refs`` for Layer 0 (``repository(owner, name)``),
    ``repo_*`` for Layer 1 (``repositoryId``), ``repo_name_*`` for
    Layer 2 (``repositoryNameWithOwner``), ``node_id_*`` for Layer 3
    (every other ``*Id`` / ``*Ids``).

    Both ``ObjectFieldNode`` (input-object fields) and ``ArgumentNode``
    (top-level mutation args) are handled, plus ``ListValueNode`` for
    plural ``*Ids`` fields.
    """

    def __init__(self) -> None:
        super().__init__()
        # Layer 0
        self.repo_field_refs: list[_RepoFieldRef] = []
        # Layer 1
        self.repo_inlined: list[str] = []
        self.repo_var_refs: list[str] = []
        # Layer 2
        self.repo_name_inlined: list[str] = []
        self.repo_name_var_refs: list[str] = []
        # Layer 3
        self.node_id_inlined: list[str] = []
        self.node_id_var_refs: list[str] = []

    def _collect_id_value(self, name: str, value: gql_ast.Node) -> None:
        if name == "repositoryId":
            if isinstance(value, gql_ast.StringValueNode):
                self.repo_inlined.append(value.value)
            elif isinstance(value, gql_ast.VariableNode):
                self.repo_var_refs.append(value.name.value)
        elif name == "repositoryNameWithOwner":
            if isinstance(value, gql_ast.StringValueNode):
                self.repo_name_inlined.append(value.value)
            elif isinstance(value, gql_ast.VariableNode):
                self.repo_name_var_refs.append(value.name.value)
        elif _is_id_field(name):
            if isinstance(value, gql_ast.StringValueNode):
                self.node_id_inlined.append(value.value)
            elif isinstance(value, gql_ast.VariableNode):
                self.node_id_var_refs.append(value.name.value)
            elif isinstance(value, gql_ast.ListValueNode):
                for item in value.values:
                    if isinstance(item, gql_ast.StringValueNode):
                        self.node_id_inlined.append(item.value)
                    elif isinstance(item, gql_ast.VariableNode):
                        self.node_id_var_refs.append(item.name.value)

    def enter_object_field(
        self, node: gql_ast.ObjectFieldNode, *_args: object
    ) -> None:
        self._collect_id_value(node.name.value, node.value)

    def enter_argument(
        self, node: gql_ast.ArgumentNode, *_args: object
    ) -> None:
        self._collect_id_value(node.name.value, node.value)

    def enter_field(
        self,
        node: gql_ast.FieldNode,
        _key: object,
        _parent: object,
        _path: object,
        ancestors: list[gql_ast.Node],
    ) -> None:
        """Capture every ``repository(owner, name)`` selection.

        Selections without a ``name`` argument are ignored: ``Commit``,
        ``Ref`` and several other GitHub types expose ``repository`` as
        an argument-less output field that cannot itself address a new
        repository.
        """
        if node.name.value != "repository":
            return
        owner_val: gql_ast.ValueNode | None = None
        name_val: gql_ast.ValueNode | None = None
        for arg in node.arguments or ():
            if arg.name.value == "owner":
                owner_val = arg.value
            elif arg.name.value == "name":
                name_val = arg.value
        if name_val is None:
            return
        if owner_val is None:
            owner_val = _find_parent_login_arg(ancestors)
        self.repo_field_refs.append(_RepoFieldRef(owner_val, name_val))


def _collect_repo_ids_from_variables(
    obj: dict[str, object], out: list[str]
) -> None:
    """Collect ``repositoryId`` strings from variables.

    Iterative walk over an explicit stack: variables are attacker-
    controlled JSON, and a deeply nested body would otherwise blow
    Python's recursion limit and 500 the proxy.
    """
    stack: list[dict[str, object]] = [obj]
    while stack:
        node = stack.pop()
        for key, value in node.items():
            if key == "repositoryId" and isinstance(value, str):
                out.append(value)
            elif isinstance(value, dict):
                stack.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        stack.append(item)


def _collect_repo_names_from_variables(
    obj: dict[str, object], out: list[str]
) -> None:
    """Collect ``repositoryNameWithOwner`` from variables (iterative)."""
    stack: list[dict[str, object]] = [obj]
    while stack:
        node = stack.pop()
        for key, value in node.items():
            if key == "repositoryNameWithOwner" and isinstance(value, str):
                out.append(value)
            elif isinstance(value, dict):
                stack.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        stack.append(item)


def _collect_node_ids_from_variables(
    obj: dict[str, object], out: list[str]
) -> None:
    """Collect ``*Id`` / ``*Ids`` strings from variables (iterative).

    Skips ``repositoryId`` (handled by Layer 1) and known non-node-ID
    fields. Extracts string list items for plural fields like
    ``labelIds``.
    """
    stack: list[dict[str, object]] = [obj]
    while stack:
        node = stack.pop()
        for key, value in node.items():
            if key == "repositoryId":
                continue
            if _is_id_field(key):
                if isinstance(value, str):
                    out.append(value)
                elif isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            out.append(item)
            elif isinstance(value, dict):
                stack.append(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        stack.append(item)


def check_repo_scope(
    request_body: bytes,
    allowed_repo_ids: frozenset[str],
    allowed_repo_full_names: frozenset[str] = frozenset(),
) -> ScopeResult:
    """Verify a GraphQL request targets only allowed repositories.

    Args:
        request_body: Raw HTTP request body bytes.
        allowed_repo_ids: GitHub repository node IDs (``R_xxx``) the
            launcher resolved at startup.
        allowed_repo_full_names: ``owner/name`` full names matching
            those node IDs. Compared case-insensitively. An empty set
            blocks any ``repositoryNameWithOwner`` value encountered.

    Returns:
        :class:`ScopeResult`. Returns ``ALLOWED`` only when every
        repository-targeting value in the request can be conclusively
        proven in-scope; any parse failure, undecodable node ID, or
        out-of-scope reference returns a non-ALLOWED verdict.
    """
    if len(request_body) > _MAX_BODY_SIZE:
        return _TOO_LARGE

    try:
        body = json.loads(request_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _PARSE_ERROR

    if not isinstance(body, dict):
        return _PARSE_ERROR

    query = body.get("query")
    if not isinstance(query, str):
        return _PARSE_ERROR

    variables = body.get("variables")
    if variables is None:
        variables = {}
    if not isinstance(variables, dict):
        variables = {}

    try:
        document = parse(query)
    except Exception:
        return _PARSE_ERROR

    finder = _IdFieldFinder()
    visitor.visit(document, finder)

    allowed_names_lower = frozenset(
        n.lower() for n in allowed_repo_full_names
    )

    # ------------------------------------------------------------------
    # Layer 0: repository(owner, name) field selection check.
    # ------------------------------------------------------------------
    for ref in finder.repo_field_refs:
        name_str = _resolve_string_value(ref.name, variables)
        if name_str is _StringResolution.UNRESOLVED:
            return _UNRESOLVED
        if name_str is _StringResolution.MALFORMED:
            return _PARSE_ERROR
        if ref.owner is None:
            return ScopeResult(
                ScopeVerdict.OUT_OF_SCOPE, f"<unknown>/{name_str}"
            )
        owner_str = _resolve_string_value(ref.owner, variables)
        if owner_str is _StringResolution.UNRESOLVED:
            return _UNRESOLVED
        if owner_str is _StringResolution.MALFORMED:
            return _PARSE_ERROR
        full_name = f"{owner_str}/{name_str}"
        if full_name.lower() not in allowed_names_lower:
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, full_name)

    # ------------------------------------------------------------------
    # Layer 1: repositoryId field check (string match).
    # ------------------------------------------------------------------
    collected_ids: list[str] = list(finder.repo_inlined)

    for var_name in finder.repo_var_refs:
        if var_name not in variables:
            return _UNRESOLVED
        value = variables[var_name]
        if isinstance(value, str):
            collected_ids.append(value)
        # Dict values fall through to the variable-scan below.

    _collect_repo_ids_from_variables(variables, collected_ids)

    for repo_id in collected_ids:
        if repo_id not in allowed_repo_ids:
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, repo_id)

    # ------------------------------------------------------------------
    # Layer 2: repositoryNameWithOwner check (case-insensitive).
    # ------------------------------------------------------------------
    collected_names: list[str] = list(finder.repo_name_inlined)

    for var_name in finder.repo_name_var_refs:
        if var_name not in variables:
            return _UNRESOLVED
        value = variables[var_name]
        if isinstance(value, str):
            collected_names.append(value)

    _collect_repo_names_from_variables(variables, collected_names)

    for name in collected_names:
        if name.lower() not in allowed_names_lower:
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, name)

    # ------------------------------------------------------------------
    # Layer 3: Node-ID ownership check (decode + db-ID match).
    # ------------------------------------------------------------------
    # TODO(policy-language): today we check only arr[1] (the parent
    # repo DB id). The decoder also returns arr[2] for repo-scoped
    # types (PR DB id for PR_*, issue DB id for I_*, comment DB id
    # for IC_*, ...). Once the per-repo policy language lands, this
    # is the hook point for "PR #42 only" / "issue authored by the
    # agent only" enforcement: take the allowed (repo_db_id,
    # object_db_id) tuples that the launcher resolved and verify
    # both indices match. See matching markers in ``cli.py``,
    # ``proxy/allowlist.yaml``, and ``docs/design.md``.
    node_id_values: list[str] = list(finder.node_id_inlined)

    for var_name in finder.node_id_var_refs:
        if var_name not in variables:
            return _UNRESOLVED
        value = variables[var_name]
        if isinstance(value, str):
            node_id_values.append(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    node_id_values.append(item)

    _collect_node_ids_from_variables(variables, node_id_values)

    if not node_id_values:
        return _ALLOWED

    try:
        allowed_db_ids = repo_db_ids_from_node_ids(allowed_repo_ids)
    except ValueError:
        return _PARSE_ERROR

    for node_id_value in node_id_values:
        try:
            repo_db_id = decode_repo_db_id(node_id_value)
        except ValueError:
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, node_id_value)

        if repo_db_id is not None:
            if repo_db_id not in allowed_db_ids:
                return ScopeResult(
                    ScopeVerdict.OUT_OF_SCOPE, node_id_value
                )
        elif not is_non_repo_node_id(node_id_value):
            # Looks like a node ID, decoded to None, prefix unknown ->
            # block. Ensures future GitHub node-ID format changes don't
            # silently bypass scope checking.
            return ScopeResult(ScopeVerdict.OUT_OF_SCOPE, node_id_value)

    return _ALLOWED
