# Ported from airut (https://github.com/airutorg/airut) — MIT licensed,
# Copyright (c) 2026 Pyry Haulos. Reused here under the same MIT terms;
# see https://opensource.org/licenses/MIT.
#
# This file is intentionally a near-verbatim port; please send upstream
# fixes to airut as well as here so the two implementations don't drift.

"""GraphQL operation allowlist (Layer 1 of the /graphql gate).

Parses GraphQL requests, identifies the executing operation's type
(query / mutation / subscription) and top-level field names, then
matches them against fnmatch patterns from the agentbox config.

The match is **default-deny**: anything not on the configured pattern
list returns a structured BLOCKED verdict so the caller can 403 the
request and emit a structured log line. Operators tail those log
lines to discover GraphQL fields the proxy doesn't yet recognize
(new GitHub features, niche ``gh`` subcommands, ...) and add them to
the allowlist.

This layer is **schema-free**: it knows nothing about GitHub's
GraphQL types -- only operation type and top-level field names. It
runs *before* the per-repo scope check so unknown shapes never reach
the scope walker.

Uses graphql-core for AST parsing.
"""

from __future__ import annotations

import enum
import fnmatch
import json
from dataclasses import dataclass

from graphql import parse
from graphql.language import ast as gql_ast


class OperationVerdict(enum.Enum):
    """Result of a GraphQL operation allowlist check."""

    ALLOWED = "allowed"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class OperationResult:
    """Structured result from :func:`check_operations`.

    ``detail`` is the field name (for unlisted fields), one of the
    diagnostic labels below (for parse / size / structural failures),
    or ``None`` for ALLOWED.

    ``operation_tag`` is ``"<type>/<field>"`` for log lines, set
    whenever the operation could be parsed far enough to identify a
    type and at least one field.
    """

    verdict: OperationVerdict
    detail: str | None = None
    operation_tag: str | None = None


# Pre-built results for common block reasons.
_PARSE_ERROR = OperationResult(OperationVerdict.BLOCKED, "<unparseable>")
_BATCHED = OperationResult(OperationVerdict.BLOCKED, "<batched>")
_OP_NAME_INVALID = OperationResult(
    OperationVerdict.BLOCKED, "<operation-name-invalid>"
)
_FRAGMENT_SPREAD = OperationResult(
    OperationVerdict.BLOCKED, "<fragment-spread>"
)
_TOO_LARGE = OperationResult(OperationVerdict.BLOCKED, "<too-large>")

# Maximum request body size to parse (1 MiB). Larger bodies are
# rejected without invoking graphql-core to bound parser CPU cost.
_MAX_BODY_SIZE = 1024 * 1024

# Map graphql-core OperationType enum values to config keys.
_OP_TYPE_KEYS = {
    "query": "queries",
    "mutation": "mutations",
    "subscription": "subscriptions",
}


def _collect_top_level_fields(
    selections: tuple[gql_ast.SelectionNode, ...],
) -> list[str] | None:
    """Collect top-level field names, resolving inline fragments.

    Returns ``None`` if a named fragment spread is encountered at the
    operation root (or nested inside an inline fragment) -- the caller
    must fail-secure block. Type conditions on inline fragments are
    ignored: this layer has no schema knowledge.
    """
    fields: list[str] = []
    for sel in selections:
        if isinstance(sel, gql_ast.FieldNode):
            fields.append(sel.name.value)
        elif isinstance(sel, gql_ast.InlineFragmentNode):
            if sel.selection_set is not None:
                for inner in sel.selection_set.selections:
                    if isinstance(inner, gql_ast.FieldNode):
                        fields.append(inner.name.value)
                    elif isinstance(inner, gql_ast.InlineFragmentNode):
                        if inner.selection_set is not None:
                            for nested in inner.selection_set.selections:
                                if isinstance(nested, gql_ast.FieldNode):
                                    fields.append(nested.name.value)
                                else:
                                    return None
                    else:
                        return None
        elif isinstance(sel, gql_ast.FragmentSpreadNode):
            return None
    return fields


def check_operations(
    request_body: bytes,
    graphql_config: dict[str, list[str]],
) -> OperationResult:
    """Check whether a GraphQL request's top-level operations are allowed.

    ``graphql_config`` is a dict with optional ``queries`` /
    ``mutations`` / ``subscriptions`` keys, each a list of
    fnmatch patterns (e.g. ``["*"]``, ``["createIssue", "update*"]``,
    ``[]``). An omitted or empty list means **all operations of that
    type are blocked**.
    """
    if len(request_body) > _MAX_BODY_SIZE:
        return _TOO_LARGE

    try:
        body = json.loads(request_body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return _PARSE_ERROR

    if isinstance(body, list):
        return _BATCHED

    if not isinstance(body, dict):
        return _PARSE_ERROR

    query = body.get("query")
    if not isinstance(query, str):
        return _PARSE_ERROR

    try:
        document = parse(query)
    except Exception:
        return _PARSE_ERROR

    op_defs = [
        d
        for d in document.definitions
        if isinstance(d, gql_ast.OperationDefinitionNode)
    ]
    if not op_defs:
        return _PARSE_ERROR

    if len(op_defs) == 1:
        op = op_defs[0]
    else:
        # Multi-operation document: caller must specify operationName.
        op_name = body.get("operationName")
        if not isinstance(op_name, str):
            return _OP_NAME_INVALID
        matched = [d for d in op_defs if d.name and d.name.value == op_name]
        if len(matched) != 1:
            return _OP_NAME_INVALID
        op = matched[0]

    op_type = op.operation.value  # "query" / "mutation" / "subscription"

    assert op.selection_set is not None
    fields = _collect_top_level_fields(op.selection_set.selections)
    if fields is None:
        return _FRAGMENT_SPREAD
    assert fields  # graphql-core rejects empty selection sets at parse time

    config_key = _OP_TYPE_KEYS[op_type]
    patterns = graphql_config.get(config_key, [])

    if not patterns:
        # No patterns configured for this operation type -> default-deny.
        return OperationResult(
            OperationVerdict.BLOCKED,
            f"{op_type}:<blocked>",
            operation_tag=f"{op_type}/{fields[0]}",
        )

    for field in fields:
        try:
            # ``fnmatchcase`` -- GraphQL field names are
            # case-sensitive, and ``fnmatch`` is case-insensitive
            # on Windows because it routes through
            # ``os.path.normcase``.
            matched = any(fnmatch.fnmatchcase(field, pat) for pat in patterns)
        except TypeError:
            # Non-string pattern in config -> fail-secure.
            matched = False
        if not matched:
            return OperationResult(
                OperationVerdict.BLOCKED,
                field,
                operation_tag=f"{op_type}/{field}",
            )

    return OperationResult(
        OperationVerdict.ALLOWED,
        operation_tag=f"{op_type}/{fields[0]}",
    )
