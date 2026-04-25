"""mitmproxy addon: enforce allowlist + dispatch to credential handlers.

The addon is configured by three file paths passed as mitmproxy options:

- ``agentbox_credentials`` — JSON describing per-provider credentials,
  one key per credential kind. Currently supports ``github``::

      {"github": {"surrogate": "ghp_...", "real": "ghp_..."}}

  Empty/missing entries mean no handler for that kind. Future kinds
  (Anthropic OAuth, AWS SigV4, ...) get their own handler classes in
  ``handlers.py`` and their own keys here.

- ``agentbox_allowlist`` — YAML with ``domains`` (host-only entries),
  ``url_prefixes`` (host + path + optional methods), and an optional
  ``github:`` block carrying the GraphQL operation allowlist. Drives
  request gating; surrogate handling is decoupled from the allowlist
  so each handler can apply on any allowlisted host that falls in
  its scope. A top-level ``permissive: true`` short-circuits all
  network gating (everything is allowed through) while leaving the
  credential-swap handlers in place -- useful as a default until the
  scoping policy is dialled in.

- ``agentbox_repos`` — JSON list of ``{full_name, node_id}`` entries
  the launcher resolved from the user's PAT (``gh api repos/...``).
  Drives the per-repo scope check on ``api.github.com/graphql``.

Allowlist patterns are fnmatch-style; host matches are case-insensitive.

The ``/graphql`` gate, when ``api.github.com`` is allowlisted, runs
two layers on every POST: the operation allowlist (default-deny;
unknown queries / mutations return ``unsupported_feature`` and are
logged) followed by the per-repo scope check (decodes node IDs and
verifies every repository-targeting value is in the launcher's
allowed-repos set). Each request emits a single structured JSON log
line so operators can ``grep '"event":"graphql"'`` to see what
passed, what blocked, and what shape they may want to extend
coverage for.
"""

from __future__ import annotations

import json
from fnmatch import fnmatch
from pathlib import Path
from collections.abc import Iterator

import yaml
from mitmproxy import ctx, http

from agentbox.proxy.dangerous_operations import check_dangerous
from agentbox.proxy.graphql_operations import (
    OperationVerdict,
    check_operations,
)
from agentbox.proxy.graphql_scope import ScopeVerdict, check_repo_scope
from agentbox.proxy.handlers import GithubCredentialHandler


_GRAPHQL_HOST = "api.github.com"
_GRAPHQL_PATH = "/graphql"


class AgentboxFilter:
    def __init__(self) -> None:
        self.handlers: list[GithubCredentialHandler] = []
        self.domains: list[str] = []
        self.url_prefixes: list[dict] = []
        # GraphQL gate state. When github_config is empty the gate is
        # bypassed (caller didn't configure /graphql scoping).
        self.github_config: dict = {}
        self.allowed_repo_ids: frozenset[str] = frozenset()
        self.allowed_repo_full_names: frozenset[str] = frozenset()
        # Permissive mode: allow all CONNECTs / requests through
        # without consulting domains, url_prefixes, or the GraphQL
        # gate. Credential handlers still run so the GitHub surrogate
        # is swapped for the real PAT on github.com / api.github.com.
        self.permissive: bool = False

    def load(self, loader) -> None:
        loader.add_option(
            "agentbox_credentials", str, "",
            "Path to JSON describing per-provider credentials",
        )
        loader.add_option(
            "agentbox_allowlist", str, "",
            "Path to YAML allowlist with `domains` and `url_prefixes`",
        )
        loader.add_option(
            "agentbox_repos", str, "",
            "Path to JSON list of {full_name, node_id} the agent may "
            "write to via /graphql",
        )

    def configure(self, updates) -> None:
        if "agentbox_credentials" in updates:
            path = ctx.options.agentbox_credentials
            if path:
                data = json.loads(Path(path).read_text("utf-8"))
                self.handlers = list(_build_handlers(data))
                ctx.log.info(
                    f"agentbox: loaded {len(self.handlers)} credential "
                    f"handler(s)"
                )
        if "agentbox_allowlist" in updates:
            path = ctx.options.agentbox_allowlist
            if path:
                data = yaml.safe_load(Path(path).read_text("utf-8")) or {}
                self.permissive = bool(data.get("permissive", False))
                self.domains = [str(d).lower() for d in data.get("domains") or []]
                self.url_prefixes = data.get("url_prefixes") or []
                self.github_config = data.get("github") or {}
                if self.permissive:
                    ctx.log.info(
                        "agentbox: permissive networking active -- "
                        "all hosts allowed; credential swap still runs"
                    )
                else:
                    ctx.log.info(
                        f"agentbox: loaded {len(self.domains)} domain(s), "
                        f"{len(self.url_prefixes)} url prefix rule(s)"
                    )
                    if self.github_config:
                        ops = self.github_config.get("graphql_operations") or {}
                        ctx.log.info(
                            "agentbox: graphql gate active "
                            f"({len(ops.get('queries') or [])} queries, "
                            f"{len(ops.get('mutations') or [])} mutations, "
                            f"{len(ops.get('subscriptions') or [])} subs)"
                        )
        if "agentbox_repos" in updates:
            path = ctx.options.agentbox_repos
            if path:
                data = json.loads(Path(path).read_text("utf-8")) or []
                self.allowed_repo_ids = frozenset(
                    str(r["node_id"]) for r in data if r.get("node_id")
                )
                self.allowed_repo_full_names = frozenset(
                    str(r["full_name"]) for r in data if r.get("full_name")
                )
                ctx.log.info(
                    f"agentbox: loaded {len(self.allowed_repo_ids)} "
                    f"writable repo(s) for graphql gate"
                )

    def http_connect(self, flow: http.HTTPFlow) -> None:
        host = flow.request.pretty_host.lower()
        if not self._host_reachable(host):
            ctx.log.warn(f"agentbox: BLOCKED CONNECT {host}")
            flow.response = http.Response.make(
                403, b"agentbox: host not allowed\n",
                {"Content-Type": "text/plain"},
            )

    def request(self, flow: http.HTTPFlow) -> None:
        if not self._request_allowed(flow.request):
            ctx.log.warn(
                f"agentbox: BLOCKED {flow.request.method} {flow.request.pretty_url}"
            )
            flow.response = http.Response.make(
                403, b"agentbox: request not allowed\n",
                {"Content-Type": "text/plain"},
            )
            return

        if self._is_graphql(flow.request):
            blocked = self._apply_graphql_gate(flow)
            if blocked:
                return

        host = flow.request.pretty_host.lower()
        for handler in self.handlers:
            if handler.matches_host(host):
                handler.handle(flow.request)

    # ------------------------------------------------------------------
    # GraphQL gate
    # ------------------------------------------------------------------

    def _is_graphql(self, request: http.Request) -> bool:
        if self.permissive:
            # Permissive mode bypasses the GraphQL gate too -- the
            # gate is part of the scoping policy that's been switched
            # off; credential swap on /graphql still runs because the
            # handler dispatch is independent of this check.
            return False
        if not self.github_config:
            return False
        if request.method.upper() != "POST":
            return False
        if request.pretty_host.lower() != _GRAPHQL_HOST:
            return False
        path = request.path.split("?", 1)[0]
        return path == _GRAPHQL_PATH

    def _apply_graphql_gate(self, flow: http.HTTPFlow) -> bool:
        """Run Layer 1 (ops) + Layer 2 (scope). Return True if blocked."""
        body = flow.request.get_content() or b""
        ops_cfg = self.github_config.get("graphql_operations") or {}

        op_result = check_operations(body, ops_cfg)
        if op_result.verdict == OperationVerdict.BLOCKED:
            self._log_graphql(
                event="graphql",
                verdict="blocked",
                layer="operations",
                op=op_result.operation_tag,
                detail=op_result.detail,
                size=len(body),
            )
            flow.response = _graphql_403(
                error="unsupported_feature",
                message=(
                    "GraphQL operation is not in the agentbox allowlist. "
                    "If this is a legitimate gh / Octokit call, add the "
                    "field name to `github.graphql_operations` in the "
                    "agentbox allowlist YAML."
                ),
                detail=op_result.detail or "<unknown>",
            )
            return True

        scope_result = check_repo_scope(
            body,
            self.allowed_repo_ids,
            self.allowed_repo_full_names,
        )
        if scope_result.verdict != ScopeVerdict.ALLOWED:
            self._log_graphql(
                event="graphql",
                verdict="blocked",
                layer="scope",
                op=op_result.operation_tag,
                detail=scope_result.detail,
                scope_verdict=scope_result.verdict.value,
                size=len(body),
            )
            flow.response = _graphql_403(
                error=f"scope_{scope_result.verdict.value}",
                message=(
                    "GraphQL request targets a repository the agent "
                    "is not permitted to write to. Pass `--repo "
                    "OWNER/NAME` to the launcher (or add it under "
                    "`github.repos:` in the allowlist) if this is "
                    "intended."
                ),
                detail=scope_result.detail or "<unknown>",
            )
            return True

        # Layer 3: shadow-mode dangerous-ops watchlist. Doesn't block
        # -- just emits a WARN line so operators can tighten config.
        dangerous_patterns = ops_cfg.get("dangerous") or []
        matched = check_dangerous(op_result.operation_tag, dangerous_patterns)
        if matched:
            ctx.log.warn(
                "agentbox graphql warning: " + json.dumps({
                    "event": "graphql_dangerous",
                    "op": op_result.operation_tag,
                    "matched_pattern": matched,
                    "size": len(body),
                })
            )

        log_fields: dict = {
            "event": "graphql",
            "verdict": "allowed",
            "op": op_result.operation_tag,
            "size": len(body),
        }
        if matched:
            # Tag the per-request audit line too -- one grep finds
            # both the WARN and the corresponding ALLOW.
            log_fields["dangerous"] = matched
        self._log_graphql(**log_fields)
        return False

    def _log_graphql(self, **fields: object) -> None:
        # Single JSON-formatted log line per request -- operators can
        # `grep 'agentbox graphql:' | jq` to slice/dice.
        ctx.log.info("agentbox graphql: " + json.dumps(fields))

    # ------------------------------------------------------------------
    # Network allowlist (existing)
    # ------------------------------------------------------------------

    def _host_reachable(self, host: str) -> bool:
        if self.permissive:
            return True
        for pattern in self.domains:
            if fnmatch(host, pattern):
                return True
        for entry in self.url_prefixes:
            host_pattern = str(entry.get("host", "")).lower()
            if host_pattern and fnmatch(host, host_pattern):
                return True
        return False

    def _request_allowed(self, request: http.Request) -> bool:
        if self.permissive:
            return True
        host = request.pretty_host.lower()
        path = request.path
        method = request.method.upper()
        for pattern in self.domains:
            if fnmatch(host, pattern):
                return True
        for entry in self.url_prefixes:
            host_pattern = str(entry.get("host", "")).lower()
            if not host_pattern or not fnmatch(host, host_pattern):
                continue
            if not fnmatch(path, str(entry.get("path", "/*"))):
                continue
            allowed_methods = entry.get("methods")
            if allowed_methods is not None and method not in {str(m).upper() for m in allowed_methods}:
                continue
            return True
        return False


def _build_handlers(data: dict) -> Iterator[GithubCredentialHandler]:
    """Yield handlers for each credential kind present in ``data``.

    Skips kinds that are absent or have empty surrogate/real fields,
    so a session with no GitHub token simply runs zero handlers.
    """
    gh = data.get("github")
    if isinstance(gh, dict) and gh.get("surrogate") and gh.get("real"):
        yield GithubCredentialHandler(
            surrogate=gh["surrogate"],
            real=gh["real"],
            allow_foreign=bool(gh.get("allow_foreign_credentials", False)),
        )


def _graphql_403(error: str, message: str, detail: str) -> http.Response:
    body = json.dumps(
        {"error": error, "message": message, "detail": detail}
    ).encode("utf-8")
    return http.Response.make(
        403, body, {"Content-Type": "application/json"}
    )


addons = [AgentboxFilter()]
