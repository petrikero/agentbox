"""mitmproxy addon: enforce allowlist + dispatch to credential handlers.

The addon is configured by three file paths passed as mitmproxy options:

- ``agentbox_credentials`` — JSON describing per-provider credentials,
  one key per credential kind. Currently supports ``github``::

      {"github": {"surrogate": "ghp_...", "real": "ghp_..."}}

  Empty/missing entries mean no handler for that kind. Future kinds
  (Anthropic OAuth, AWS SigV4, ...) get their own handler classes in
  ``handlers.py`` and their own keys here.

- ``agentbox_allowlist`` — YAML with ``domains`` (host-only entries)
  and ``url_prefixes`` (host + path + optional methods). Drives
  request gating; surrogate handling is decoupled from the allowlist
  so each handler can apply on any allowlisted host that falls in
  its scope. A top-level ``permissive: true`` short-circuits all
  network gating (everything is allowed through) while leaving the
  credential-swap handlers in place -- useful as a default until the
  scoping policy is dialled in. A top-level ``github:`` block, if
  present, replaces the contents of the bundled
  ``github_policy.yaml`` for that session.

  GitHub-specific access policy (GraphQL operation allowlist,
  per-repo scope) is loaded from ``github_policy.yaml`` next to
  this file by default -- regardless of the network allowlist.

- ``agentbox_github_policy`` — JSON describing the resolved GitHub
  access policy::

      {"mode": "scoped",
       "repos": [{"full_name": "owner/repo",
                  "node_id": "R_kgDO...",
                  "issues":        ["*"],
                  "pull_requests": ["*"],
                  "branches":      {"push": ["*"], "create": ["*"], "delete": ["*"]}},
                 ...]}

  ``mode`` is one of ``public`` / ``unrestricted`` / ``scoped`` (the
  ``auto`` value used in the launcher CLI is always resolved before
  reaching the proxy). The per-repo lists are read into
  ``self.repo_policies`` for chunk-3 enforcement; today only
  ``mode`` and the repo identity (full_name + node_id) are
  consulted by the existing GraphQL scope check.

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
import re
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
from agentbox.proxy.mock_llm import MockLLM


_GRAPHQL_HOST = "api.github.com"
_GRAPHQL_PATH = "/graphql"

# REST writes against the repo subtree:
# /repos/{owner}/{name}            -- repo settings
# /repos/{owner}/{name}/issues     -- create / list issues
# /repos/{owner}/{name}/pulls/.../comments
# ...and many more. Any non-GET method against the subtree is a
# write candidate that the scope check needs to consider. We use a
# simple regex on the path because the repo segment is always at a
# fixed depth.
_REST_REPO_PATH_RE = re.compile(r"^/repos/([^/]+)/([^/]+)(?:/.*)?$")

# git smart-HTTP push:
# https://github.com/{owner}/{name}(.git)?/git-receive-pack
# ``.git`` is canonical but GitHub also serves the slash form, so
# we accept both. ``git-upload-pack`` (fetch) is intentionally not
# matched -- reads aren't fenced.
_GIT_PUSH_PATH_RE = re.compile(
    r"^/([^/]+)/([^/]+?)(?:\.git)?/git-receive-pack/?$"
)


_READ_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS"})


def _repo_from_rest_path(
    host: str, method: str, path: str,
) -> str | None:
    """Return ``owner/name`` if this is a REST write to the repo subtree.

    Returns ``None`` if the host isn't api.github.com, the method is
    a read (``GET``, ``HEAD``, or preflight ``OPTIONS``), or the
    path isn't under ``/repos/{owner}/{name}/``.
    """
    if host != _GRAPHQL_HOST:
        return None
    if method in _READ_METHODS:
        return None
    m = _REST_REPO_PATH_RE.match(path)
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}"


def _repo_from_git_push_path(
    host: str, method: str, path: str,
) -> str | None:
    """Return ``owner/name`` if this is a smart-HTTP push to GitHub.

    Returns ``None`` for the fetch counterpart (``git-upload-pack``),
    for non-github.com hosts, or for non-POST methods.
    """
    if host != "github.com":
        return None
    if method != "POST":
        return None
    m = _GIT_PUSH_PATH_RE.match(path)
    if not m:
        return None
    return f"{m.group(1)}/{m.group(2)}"


_BUNDLED_GITHUB_POLICY = Path(__file__).parent / "github_policy.yaml"


def _load_bundled_github_policy() -> dict:
    """Return the bundled GitHub policy dict, or ``{}`` if the file is missing.

    The file ships inside the package, so a missing file is a packaging
    bug rather than user error -- but we soft-fail so the proxy still
    starts (with no GraphQL gate) if someone has been editing the
    install tree.
    """
    if not _BUNDLED_GITHUB_POLICY.is_file():
        return {}
    try:
        return yaml.safe_load(_BUNDLED_GITHUB_POLICY.read_text("utf-8")) or {}
    except yaml.YAMLError:
        return {}


class AgentboxFilter:
    def __init__(self) -> None:
        self.handlers: list[GithubCredentialHandler] = []
        self.domains: list[str] = []
        self.url_prefixes: list[dict] = []
        # GraphQL gate state. Defaults to the bundled github_policy.yaml
        # so the gate runs with curated operation allowlists out of the
        # box; a `github:` block in the user-supplied allowlist replaces
        # this on load.
        self.github_config: dict = _load_bundled_github_policy()
        self.allowed_repo_ids: frozenset[str] = frozenset()
        self.allowed_repo_full_names: frozenset[str] = frozenset()
        # Resolved GitHub access mode (``public`` / ``unrestricted`` /
        # ``scoped``). Read from agentbox_github_policy and used to
        # decide whether the writes-only fence fires.
        self.github_mode: str = "unrestricted"
        # Per-repo policy keyed by full_name -- carries
        # ``{issues, pull_requests, branches}`` lists. Populated by
        # ``configure`` when the launcher passes a github_policy
        # JSON. Chunk 3's enforcement layer reads this; chunk 2
        # only stores it.
        self.repo_policies: dict[str, dict] = {}
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
            "agentbox_github_policy", str, "",
            "Path to JSON with the resolved GitHub access policy "
            "({mode, repos: [{full_name, node_id, issues, "
            "pull_requests, branches}]})",
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
                # User allowlist may override the bundled GitHub policy;
                # otherwise the bundled defaults loaded in __init__ stay.
                if "github" in data:
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
        if "agentbox_github_policy" in updates:
            path = ctx.options.agentbox_github_policy
            if path:
                data = json.loads(Path(path).read_text("utf-8")) or {}
                if isinstance(data, dict):
                    repos = data.get("repos") or []
                    self.github_mode = str(
                        data.get("mode") or "unrestricted"
                    )
                else:
                    # Fail-closed on a malformed policy file. The
                    # launcher always writes a dict; an unexpected
                    # shape means something else corrupted the file
                    # or wrote an obsolete format. Defaulting to
                    # ``public`` (no surrogate handler runs anyway,
                    # and the writes-only fence's bypass case still
                    # wouldn't hand the agent extra power) is safer
                    # than silently flipping to unrestricted.
                    ctx.log.warn(
                        "agentbox: malformed github_policy JSON "
                        f"(expected mapping, got {type(data).__name__}); "
                        f"falling back to mode=public"
                    )
                    repos = []
                    self.github_mode = "public"
                self.allowed_repo_ids = frozenset(
                    str(r["node_id"]) for r in repos if r.get("node_id")
                )
                self.allowed_repo_full_names = frozenset(
                    str(r["full_name"])
                    for r in repos if r.get("full_name")
                )
                self.repo_policies = {
                    str(r["full_name"]): {
                        "issues": list(r.get("issues") or []),
                        "pull_requests": list(r.get("pull_requests") or []),
                        "branches": dict(r.get("branches") or {}),
                    }
                    for r in repos if r.get("full_name")
                }
                ctx.log.info(
                    f"agentbox: github mode={self.github_mode}, "
                    f"{len(self.allowed_repo_ids)} repo(s)"
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
        # If an earlier addon (e.g. MockLLM) already produced a response,
        # don't run the allowlist / credential swap on top of it -- a
        # blocked-host verdict here would clobber the mock's reply.
        # ``getattr`` keeps the duck-typed test flows (which don't set
        # ``response`` at all) flowing through the existing assertions.
        if getattr(flow, "response", None) is not None:
            return
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

        # GitHub writes-only fence. Independent of the GraphQL gate
        # (which only fires on /graphql) so REST writes and git
        # smart-HTTP pushes get the same scope check.
        if self._apply_github_write_gate(flow):
            return

        host = flow.request.pretty_host.lower()
        for handler in self.handlers:
            if handler.matches_host(host):
                handler.handle(flow.request)

    # ------------------------------------------------------------------
    # GraphQL gate
    # ------------------------------------------------------------------

    def _is_graphql(self, request: http.Request) -> bool:
        if self.github_mode != "scoped":
            # Gate runs only in scoped mode -- ``public`` has no token
            # to write with anyway, ``unrestricted`` is the explicit
            # "no per-repo fence" choice. The network allowlist's
            # ``permissive`` flag is independent now: a project can
            # run permissive networking and still benefit from the
            # GraphQL scope check.
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
    # GitHub write fence (REST + git smart-HTTP)
    # ------------------------------------------------------------------

    def _apply_github_write_gate(self, flow: http.HTTPFlow) -> bool:
        """Block writes to repos outside the scoped allow-set.

        Two surfaces, same fence:

        - **REST**: ``api.github.com/repos/{owner}/{name}/...`` with
          any non-GET method. The host's PAT can address every repo
          it has access to via REST; the scope check confines
          writes to the listed repos. (GraphQL writes are caught by
          the dedicated /graphql gate above.)
        - **git smart-HTTP push**: ``github.com/{owner}/{name}.git/
          git-receive-pack``. ``git-upload-pack`` (fetch) is always
          allowed -- reads aren't fenced.

        Bypassed in ``unrestricted`` and ``public`` modes (the user
        opted out of fencing or has no token to write with anyway).
        Returns ``True`` if the request was blocked.
        """
        if self.github_mode != "scoped":
            return False

        request = flow.request
        host = request.pretty_host.lower()
        path = request.path.split("?", 1)[0]
        method = request.method.upper()

        owner_name = _repo_from_rest_path(host, method, path)
        if owner_name is None:
            owner_name = _repo_from_git_push_path(host, method, path)
        if owner_name is None:
            return False

        if owner_name in self.allowed_repo_full_names:
            return False

        ctx.log.warn(
            "agentbox github write: " + json.dumps({
                "event": "github_write",
                "verdict": "blocked",
                "scope": "out_of_scope",
                "method": method,
                "host": host,
                "path": path,
                "target": owner_name,
            })
        )
        body = json.dumps({
            "error": "scope_out_of_scope",
            "message": (
                "agentbox: write to " + owner_name + " denied -- "
                "not in the scoped repos set. Pass --repo "
                "OWNER/NAME to the launcher (or add it under "
                "github.repos: in agentbox.config.yaml) to allow."
            ),
            "detail": owner_name,
        }).encode("utf-8")
        flow.response = http.Response.make(
            403, body, {"Content-Type": "application/json"},
        )
        return True

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


# MockLLM goes first so its `request()` hook runs before AgentboxFilter
# would see the request. When `agentbox_mock_llm_script` is empty the
# addon is inert and AgentboxFilter handles every request as before.
addons = [MockLLM(), AgentboxFilter()]
