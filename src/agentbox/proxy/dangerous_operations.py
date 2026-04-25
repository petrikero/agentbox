"""Shadow-mode watchlist for risky GraphQL operations (Layer 3).

After the supported-ops gate (Layer 1) and the per-repo scope check
(Layer 2) have both said ALLOW, this layer asks one more question:
"is this operation one we wanted a heads-up about?" If yes, the
filter emits a structured WARN log line and lets the request
through anyway -- the watchlist is *advisory*, not enforcing.

The point: scope checks tell us a request targets an allowed repo;
they don't tell us whether the *operation* is one the operator
expected to permit. ``mergePullRequest`` on the right repo is
in-scope but still worth flagging if the agent is meant to be
review-only. Operators tail the WARN feed and tighten the supported
mutations list, the dangerous-ops list, or the agent's prompt as
they see hits.

Patterns are fnmatch-style and match the full ``<type>/<field>``
operation tag from :class:`agentbox.proxy.graphql_operations.OperationResult`,
so a single ``mutation/*`` would warn on every mutation, while
``mutation/delete*`` covers any delete-shaped call. Patterns are
case-sensitive (GraphQL field names are case-sensitive).
"""

from __future__ import annotations

import fnmatch


def check_dangerous(
    operation_tag: str | None,
    patterns: list[str],
) -> str | None:
    """Return the first matching pattern from ``patterns``, or ``None``.

    ``operation_tag`` is ``"<type>/<field>"`` (e.g.
    ``"mutation/mergePullRequest"``); typically supplied by
    :attr:`OperationResult.operation_tag`. ``None`` or an empty
    pattern list short-circuits to ``None`` (nothing to match).

    Non-string entries in ``patterns`` are skipped (fail-secure -- a
    misconfigured YAML can't crash the proxy on a hot path).
    """
    if not operation_tag or not patterns:
        return None
    for pattern in patterns:
        if not isinstance(pattern, str):
            continue
        # ``fnmatchcase`` -- not ``fnmatch`` -- because GraphQL field
        # names are case-sensitive and Python's ``fnmatch`` falls
        # back to ``os.path.normcase`` on Windows, lowercasing the
        # comparison.
        if fnmatch.fnmatchcase(operation_tag, pattern):
            return pattern
    return None
