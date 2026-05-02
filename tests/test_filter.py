"""Unit tests for the agentbox proxy filter (allowlist + handler dispatch).

Covers:
- Allowlist host matching: ``domains``, ``url_prefixes`` (with optional
  method).
- Handler dispatch: the GitHub credential handler runs only on requests
  whose host is in its scope; unrelated allowlisted hosts (e.g.
  ``api.anthropic.com``) are passed through untouched.
- ``_build_handlers`` schema parsing for ``credentials.json``.

Run from the agentbox project root::

    python -m unittest discover tests
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

# Prefer the in-tree source over any cached install in site-packages so the
# tests always exercise the current code.
_SRC = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(_SRC))

from mitmproxy.http import HTTPFlow, Request

from agentbox.proxy import filter as filter_mod
from agentbox.proxy import handlers as handlers_mod
from agentbox.proxy.filter import AgentboxFilter, _build_handlers
from agentbox.proxy.handlers import GithubCredentialHandler


def _fake_flow(request: Request) -> HTTPFlow:
    """Duck-typed HTTPFlow stub: tests only touch ``request`` and ``response``."""
    return cast("HTTPFlow", SimpleNamespace(request=request))


def _make_filter(
    domains: list[str] | None = None,
    url_prefixes: list[dict] | None = None,
    handlers: list | None = None,
    permissive: bool = False,
) -> AgentboxFilter:
    f = AgentboxFilter()
    f.domains = [d.lower() for d in (domains or [])]
    f.url_prefixes = url_prefixes or []
    f.handlers = handlers or []
    f.permissive = permissive
    return f


def _make_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes = b"",
) -> Request:
    return Request.make(method, url, body, cast(Any, headers or {}))


class HostReachableTests(unittest.TestCase):
    """Coverage for _host_reachable: CONNECT-time host gating."""

    def test_exact_domain_matches(self) -> None:
        f = _make_filter(domains=["api.github.com"])
        self.assertTrue(f._host_reachable("api.github.com"))

    def test_domain_match_is_case_insensitive(self) -> None:
        f = _make_filter(domains=["api.github.com"])
        self.assertTrue(f._host_reachable("API.GitHub.COM"))

    def test_domain_wildcard_matches_subdomain(self) -> None:
        f = _make_filter(domains=["*.github.com"])
        self.assertTrue(f._host_reachable("raw.github.com"))
        self.assertTrue(f._host_reachable("api.github.com"))

    def test_domain_wildcard_does_not_match_bare(self) -> None:
        # fnmatch: '*.github.com' doesn't match the bare 'github.com'.
        f = _make_filter(domains=["*.github.com"])
        self.assertFalse(f._host_reachable("github.com"))

    def test_unknown_host_is_unreachable(self) -> None:
        f = _make_filter(domains=["api.github.com"])
        self.assertFalse(f._host_reachable("evil.example.com"))

    def test_url_prefix_host_makes_reachable(self) -> None:
        f = _make_filter(url_prefixes=[{"host": "api.github.com", "path": "/repos/*"}])
        self.assertTrue(f._host_reachable("api.github.com"))


class RequestAllowedTests(unittest.TestCase):
    """Coverage for _request_allowed: full path + method match."""

    def test_domain_entry_allows_any_method_and_path(self) -> None:
        f = _make_filter(domains=["api.github.com"])
        self.assertTrue(f._request_allowed(
            _make_request("DELETE", "https://api.github.com/repos/x/y")
        ))

    def test_url_prefix_path_match(self) -> None:
        f = _make_filter(url_prefixes=[{
            "host": "api.github.com",
            "path": "/repos/myorg/myrepo*",
            "methods": ["GET"],
        }])
        self.assertTrue(f._request_allowed(
            _make_request("GET", "https://api.github.com/repos/myorg/myrepo/issues")
        ))

    def test_url_prefix_path_mismatch(self) -> None:
        f = _make_filter(url_prefixes=[{
            "host": "api.github.com",
            "path": "/repos/myorg/myrepo*",
        }])
        self.assertFalse(f._request_allowed(
            _make_request("GET", "https://api.github.com/repos/otherorg/x")
        ))

    def test_url_prefix_method_filter_excludes_others(self) -> None:
        f = _make_filter(url_prefixes=[{
            "host": "api.github.com",
            "path": "/repos/myorg/myrepo/issues/*/comments",
            "methods": ["POST"],
        }])
        self.assertTrue(f._request_allowed(_make_request(
            "POST", "https://api.github.com/repos/myorg/myrepo/issues/1/comments"
        )))
        self.assertFalse(f._request_allowed(_make_request(
            "DELETE", "https://api.github.com/repos/myorg/myrepo/issues/1/comments"
        )))

    def test_url_prefix_no_methods_means_any(self) -> None:
        f = _make_filter(url_prefixes=[{
            "host": "api.github.com",
            "path": "/repos/*",
        }])
        for m in ("GET", "POST", "PUT", "DELETE", "PATCH"):
            self.assertTrue(f._request_allowed(
                _make_request(m, "https://api.github.com/repos/x/y")
            ), f"method={m} should be allowed")

    def test_unallowlisted_host_blocked(self) -> None:
        f = _make_filter(domains=["api.github.com"])
        self.assertFalse(f._request_allowed(
            _make_request("GET", "https://evil.example.com/x")
        ))


class PermissiveModeTests(unittest.TestCase):
    """Coverage for ``permissive: true`` on the filter.

    When permissive, both gate sites (CONNECT-time host check and
    request-time path/method check) must short-circuit to True, the
    GraphQL gate must be bypassed, and credential handlers must
    still run on hosts they scope to.
    """

    def setUp(self) -> None:
        log = SimpleNamespace(warn=lambda *a, **k: None,
                              info=lambda *a, **k: None)
        self._patches = [
            patch.object(filter_mod, "ctx", SimpleNamespace(log=log)),
            patch.object(handlers_mod, "ctx", SimpleNamespace(log=log)),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self) -> None:
        for p in self._patches:
            p.stop()

    def test_host_reachable_allows_anything_when_permissive(self) -> None:
        f = _make_filter(permissive=True)
        self.assertTrue(f._host_reachable("evil.example.com"))
        self.assertTrue(f._host_reachable("totally.random.host"))

    def test_request_allowed_allows_anything_when_permissive(self) -> None:
        f = _make_filter(permissive=True)
        self.assertTrue(f._request_allowed(
            _make_request("DELETE", "https://evil.example.com/wipe")
        ))

    def test_graphql_gate_bypassed_when_permissive(self) -> None:
        # github_config is populated (so strict mode would gate this
        # request), but permissive must short-circuit _is_graphql.
        f = _make_filter(permissive=True)
        f.github_config = {"graphql_operations": {"queries": ["viewer"]}}
        req = _make_request(
            "POST", "https://api.github.com/graphql", body=b'{"query":"..."}'
        )
        self.assertFalse(f._is_graphql(req))

    def test_credential_handler_still_runs_when_permissive(self) -> None:
        # The whole point of permissive mode: surrogate -> real swap
        # must keep happening on github hosts even though the
        # allowlist isn't gating anything.
        f = _make_filter(
            permissive=True,
            handlers=[GithubCredentialHandler(
                surrogate="ghp_FAKE", real="ghp_REAL",
            )],
        )
        flow = _fake_flow(_make_request(
            "GET", "https://api.github.com/repos/x/y",
            headers={"Authorization": "Bearer ghp_FAKE"},
        ))
        f.request(flow)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer ghp_REAL")

    def test_off_allowlist_host_passes_through_when_permissive(self) -> None:
        # In strict mode this would be blocked. In permissive mode
        # the request reaches the handler chain (and since no handler
        # matches this host, it passes through unchanged).
        f = _make_filter(
            permissive=True,
            handlers=[GithubCredentialHandler(
                surrogate="ghp_FAKE", real="ghp_REAL",
            )],
        )
        flow = _fake_flow(_make_request(
            "GET", "https://random.example.org/anything",
        ))
        f.request(flow)
        self.assertIsNone(getattr(flow, "response", None))


class HandlerDispatchTests(unittest.TestCase):
    """Coverage for the per-host handler dispatch in ``AgentboxFilter.request``.

    The contract is: a request that survives the allowlist runs through
    every handler whose ``matches_host`` is true. A handler that doesn't
    match must not see the request.
    """

    def setUp(self) -> None:
        # Silence both modules' ctx.log -- request() logs through filter_mod
        # and the handler logs through handlers_mod.
        log = SimpleNamespace(warn=lambda *a, **k: None,
                              info=lambda *a, **k: None)
        self._patches = [
            patch.object(filter_mod, "ctx", SimpleNamespace(log=log)),
            patch.object(handlers_mod, "ctx", SimpleNamespace(log=log)),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self) -> None:
        for p in self._patches:
            p.stop()

    def _filter(self) -> AgentboxFilter:
        return _make_filter(
            domains=["api.github.com", "api.anthropic.com"],
            handlers=[GithubCredentialHandler(
                surrogate="ghp_FAKE",
                real="ghp_REAL",
            )],
        )

    def test_github_handler_runs_on_github_host(self) -> None:
        f = self._filter()
        flow = _fake_flow(_make_request(
            "GET", "https://api.github.com/repos/x/y",
            headers={"Authorization": "Bearer ghp_FAKE"},
        ))
        f.request(flow)
        self.assertEqual(flow.request.headers["Authorization"], "Bearer ghp_REAL")

    def test_github_handler_does_not_run_on_anthropic_host(self) -> None:
        # An Anthropic API call must not be re-headered or stripped by the
        # GitHub handler -- that's the whole point of per-handler scoping.
        f = self._filter()
        flow = _fake_flow(_make_request(
            "POST", "https://api.anthropic.com/v1/messages",
            headers={"Authorization": "Bearer sk-ant-FAKE"},
        ))
        f.request(flow)
        self.assertEqual(
            flow.request.headers["Authorization"], "Bearer sk-ant-FAKE"
        )

    def test_blocked_request_does_not_invoke_handler(self) -> None:
        # If the allowlist rejects the request, no handler should ever see
        # it (defence in depth: a misconfigured handler that did its own
        # network call shouldn't be reachable past the gate).
        calls: list[tuple[str, str]] = []

        class RecordingHandler:
            def matches_host(self, host: str) -> bool:
                calls.append(("matches", host))
                return True

            def handle(self, request) -> None:
                calls.append(("handle", request.pretty_host))

        f = _make_filter(
            domains=["api.github.com"],
            handlers=[RecordingHandler()],
        )
        flow = _fake_flow(_make_request(
            "GET", "https://evil.example.com/x",
        ))
        f.request(flow)
        self.assertEqual(calls, [])
        # And the filter should have set a 403 response.
        assert flow.response is not None
        self.assertEqual(flow.response.status_code, 403)


class BuildHandlersTests(unittest.TestCase):
    """Coverage for ``_build_handlers``: credentials.json schema parsing."""

    def test_empty_dict_yields_no_handlers(self) -> None:
        self.assertEqual(list(_build_handlers({})), [])

    def test_github_block_yields_handler(self) -> None:
        handlers = list(_build_handlers({
            "github": {"surrogate": "ghp_S", "real": "ghp_R"},
        }))
        self.assertEqual(len(handlers), 1)
        h = handlers[0]
        self.assertIsInstance(h, GithubCredentialHandler)
        self.assertEqual(h.surrogate, "ghp_S")
        self.assertEqual(h.real, "ghp_R")
        self.assertFalse(h.allow_foreign)

    def test_github_block_honors_allow_foreign(self) -> None:
        handlers = list(_build_handlers({
            "github": {
                "surrogate": "ghp_S",
                "real": "ghp_R",
                "allow_foreign_credentials": True,
            },
        }))
        self.assertTrue(handlers[0].allow_foreign)

    def test_github_block_with_missing_real_skipped(self) -> None:
        # An incomplete block (e.g. surrogate generated but no real token
        # resolved) must not produce a handler -- otherwise the proxy
        # would try to swap an empty string into headers.
        self.assertEqual(
            list(_build_handlers({"github": {"surrogate": "ghp_S"}})),
            [],
        )

    def test_unknown_kind_ignored(self) -> None:
        # Forward-compat: an unrecognised kind should not crash; it just
        # produces no handler. (When a real handler is added, this test
        # gets updated alongside it.)
        self.assertEqual(
            list(_build_handlers({"future_kind": {"foo": "bar"}})),
            [],
        )


class GraphqlGateTests(unittest.TestCase):
    """Coverage for the /graphql gate wired into ``request()``.

    These are integration tests for the filter -- the underlying
    operation/scope checks have their own unit tests in
    ``test_graphql_operations.py`` and ``test_graphql_scope.py``.
    Here we confirm the wiring: gate runs only on
    ``api.github.com /graphql POST``, blocked operations produce a
    structured 403, and a fully-allowed request passes through.
    """

    def setUp(self) -> None:
        # Capture WARN/INFO log lines so tests can assert on them.
        self.warn_log: list[str] = []
        self.info_log: list[str] = []
        log = SimpleNamespace(
            warn=lambda msg, *a, **k: self.warn_log.append(msg),
            info=lambda msg, *a, **k: self.info_log.append(msg),
        )
        self._patch = patch.object(filter_mod, "ctx",
                                   SimpleNamespace(log=log))
        self._patch.start()

    def tearDown(self) -> None:
        self._patch.stop()

    def _gated(self) -> AgentboxFilter:
        f = _make_filter(domains=["api.github.com"])
        f.github_config = {
            "graphql_operations": {
                "queries": ["viewer", "repository"],
                "mutations": ["addComment"],
                "subscriptions": [],
            },
        }
        f.allowed_repo_ids = frozenset({"R_kgDORH34qw"})
        f.allowed_repo_full_names = frozenset({"my-org/repo-one"})
        return f

    def _post(self, body: bytes) -> HTTPFlow:
        return _fake_flow(_make_request(
            "POST", "https://api.github.com/graphql",
            headers={"Content-Type": "application/json"},
            body=body,
        ))

    def test_allowed_query_passes_through(self) -> None:
        flow = self._post(b'{"query":"query { viewer { login } }"}')
        self._gated().request(flow)
        # No response set -> request was not blocked.
        self.assertFalse(hasattr(flow, "response") and flow.response is not None
                         and flow.response.status_code == 403)

    def test_unsupported_query_blocked_with_structured_body(self) -> None:
        # `rateLimit` isn't on this filter's queries list -> 403 + JSON.
        flow = self._post(b'{"query":"query { rateLimit { remaining } }"}')
        self._gated().request(flow)
        assert flow.response is not None
        assert flow.response.content is not None
        self.assertEqual(flow.response.status_code, 403)
        payload = json.loads(flow.response.content)
        self.assertEqual(payload["error"], "unsupported_feature")
        self.assertEqual(payload["detail"], "rateLimit")

    def test_allowed_mutation_in_scope_passes(self) -> None:
        # I_kwDORH34q80wOQ is an issue node ID whose embedded repo
        # db_id is 1149106347, which matches R_kgDORH34qw in our
        # allowlist. Same vector used in test_node_id.py.
        body = (
            b'{"query":"mutation { addComment(input:'
            b' {subjectId: \\"I_kwDORH34q80wOQ\\", body: \\"hi\\"})'
            b' { clientMutationId } }"}'
        )
        flow = self._post(body)
        self._gated().request(flow)
        self.assertFalse(hasattr(flow, "response") and flow.response is not None
                         and flow.response.status_code == 403)

    def test_mutation_out_of_scope_blocked(self) -> None:
        # ISSUE_EVIL targets repo db_id 999999999 which is NOT in our
        # allowed set -> scope layer returns OUT_OF_SCOPE.
        body = (
            b'{"query":"mutation { addComment(input:'
            b' {subjectId: \\"I_kwDOO5rJ/84AAYaf\\", body: \\"hi\\"})'
            b' { clientMutationId } }"}'
        )
        flow = self._post(body)
        self._gated().request(flow)
        assert flow.response is not None
        assert flow.response.content is not None
        self.assertEqual(flow.response.status_code, 403)
        payload = json.loads(flow.response.content)
        self.assertEqual(payload["error"], "scope_out_of_scope")
        self.assertEqual(payload["detail"], "I_kwDOO5rJ/84AAYaf")

    def test_non_graphql_request_bypasses_gate(self) -> None:
        # A REST POST to api.github.com isn't /graphql -> gate skipped.
        f = self._gated()
        flow = _fake_flow(_make_request(
            "POST", "https://api.github.com/repos/x/y/issues",
            headers={"Content-Type": "application/json"},
            body=b'{"title":"hi"}',
        ))
        f.request(flow)
        self.assertFalse(
            hasattr(flow, "response") and flow.response is not None
            and flow.response.status_code == 403
        )

    def test_dangerous_op_passes_through_with_warn(self) -> None:
        # mergePullRequest is on the dangerous watchlist below; the
        # request is in-scope (PR's parent repo is allowed) so it
        # MUST pass through, but a WARN line MUST also be logged.
        f = self._gated()
        f.github_config["graphql_operations"]["mutations"].append(
            "mergePullRequest"
        )
        f.github_config["graphql_operations"]["dangerous"] = [
            "mutation/mergePullRequest",
        ]
        body = (
            b'{"query":"mutation { mergePullRequest(input:'
            b' {pullRequestId: \\"I_kwDORH34q80wOQ\\"})'
            b' { clientMutationId } }"}'
        )
        flow = self._post(body)
        f.request(flow)
        # Not blocked.
        self.assertFalse(
            hasattr(flow, "response") and flow.response is not None
            and flow.response.status_code == 403
        )
        # WARN line emitted with the matched pattern.
        warn_lines = [
            m for m in self.warn_log if "graphql_dangerous" in m
        ]
        self.assertEqual(len(warn_lines), 1, self.warn_log)
        payload = json.loads(warn_lines[0].split(": ", 1)[1])
        self.assertEqual(payload["op"], "mutation/mergePullRequest")
        self.assertEqual(
            payload["matched_pattern"], "mutation/mergePullRequest"
        )

    def test_non_dangerous_allowed_op_does_not_warn(self) -> None:
        # Sanity: a perfectly fine mutation must not trigger a WARN.
        f = self._gated()
        f.github_config["graphql_operations"]["dangerous"] = [
            "mutation/mergePullRequest",
        ]
        body = (
            b'{"query":"mutation { addComment(input:'
            b' {subjectId: \\"I_kwDORH34q80wOQ\\", body: \\"hi\\"})'
            b' { clientMutationId } }"}'
        )
        flow = self._post(body)
        f.request(flow)
        warn_lines = [
            m for m in self.warn_log if "graphql_dangerous" in m
        ]
        self.assertEqual(warn_lines, [])

    def test_gate_disabled_when_github_config_empty(self) -> None:
        # github_config explicitly cleared -> gate is bypassed even
        # on /graphql. The default value comes from the bundled
        # github_policy.yaml; clearing it simulates a user-supplied
        # allowlist whose `github:` block is an empty mapping.
        f = _make_filter(domains=["api.github.com"])
        f.github_config = {}
        flow = self._post(
            b'{"query":"mutation { deleteRepository(input: {repositoryId:'
            b' \\"R_evil\\"}) { clientMutationId } }"}'
        )
        f.request(flow)
        # No 403 -> gate didn't run. (The request would have been
        # blocked if the gate were active.)
        self.assertFalse(
            hasattr(flow, "response") and flow.response is not None
            and flow.response.status_code == 403
        )


if __name__ == "__main__":
    unittest.main()
