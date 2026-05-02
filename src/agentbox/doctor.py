"""``agentbox doctor`` -- read-only validation + runtime-config report.

Runs through everything the launcher would consult, in roughly the
same order it would consult them, and prints what's configured plus
what would be allowed and blocked at runtime. Doesn't build images,
doesn't start the proxy, doesn't run docker -- safe to run anytime.

Exits 0 on a clean report, 1 if any *error*-severity findings showed
up. Warnings are surfaced but don't fail the command (the user can
still launch with warnings).

The pure validators (e.g. ``find_first_from``,
``classify_dockerfile_from``) are exposed at module scope so the
unit tests can exercise them without a Docker / network detour.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from rich.console import Console
from rich.rule import Rule

from agentbox._shared import (
    BASE_IMAGE_TAG,
    BASE_IMAGE_VERSION,
    CONFIG_FILE_NAME,
    DEFAULT_NETWORK_MODE,
    PROJECT_DOCKERFILE_NAME,
    PROJECT_IMAGE_PREFIX,
    PROXY_SIDECAR_IMAGE_TAG,
    _DOCKER_ENV,
    _detect_cwd_github_repo,
    _resolve_real_token,
    _safe_image_tag,
)


# ----------------------------------------------------------------------------
# Issue tracking
# ----------------------------------------------------------------------------


@dataclass
class Issue:
    """A single finding with severity, section label, and message."""

    severity: str  # "warn" | "error"
    section: str
    message: str

    @property
    def is_error(self) -> bool:
        return self.severity == "error"


@dataclass
class _Reporter:
    """Section-oriented printer that also collects findings.

    Each section calls ``ok`` / ``warn`` / ``error`` / ``info`` to
    emit a line. ``warn`` and ``error`` lines also append to
    ``issues`` so the final summary section can list them.
    """

    console: Console
    issues: list[Issue] = field(default_factory=list)
    _section: str = ""

    def header(self, label: str) -> None:
        self._section = label
        self.console.print()
        self.console.print(f"[cyan]>[/] [bold]{label}[/]")

    def ok(self, label: str, value: str = "") -> None:
        self.console.print(f"  [green]v[/] [dim]{label:<10}[/]  {value}")

    def info(self, label: str, value: str = "") -> None:
        self.console.print(f"  [dim]·[/] [dim]{label:<10}[/]  {value}")

    def warn(self, message: str) -> None:
        self.console.print(f"  [yellow]![/] {message}")
        self.issues.append(Issue("warn", self._section, message))

    def error(self, message: str) -> None:
        self.console.print(f"  [red]x[/] {message}")
        self.issues.append(Issue("error", self._section, message))


# ----------------------------------------------------------------------------
# Pure validators (testable without console / subprocess)
# ----------------------------------------------------------------------------


# Captures the image reference of the first ``FROM`` directive in a
# Dockerfile. Tolerates ``--platform=...`` flags between FROM and the
# image (we skip any tokens starting with ``--``). Comments, blank
# lines, and ARG directives before FROM are ignored implicitly.
_FROM_RE = re.compile(
    r"^\s*FROM\s+(?:--\S+\s+)*(\S+)",
    re.MULTILINE | re.IGNORECASE,
)


def find_first_from(dockerfile_text: str) -> str | None:
    """Return the image reference of the first ``FROM`` line, or ``None``.

    Handles ``--platform=...`` flags between ``FROM`` and the image.
    Returns the raw image string (e.g. ``"agentbox-base:local"``,
    ``"node:24-bookworm-slim"``, ``"foo AS builder"``-style returns
    just the image name -- the ``AS`` alias is not captured).
    """
    match = _FROM_RE.search(dockerfile_text)
    return match.group(1) if match else None


@dataclass
class DockerfileFromVerdict:
    """Result of analysing a Dockerfile.agentbox's first FROM line."""

    kind: str  # "ok" | "version-mismatch" | "non-base" | "missing"
    detail: str = ""


def classify_dockerfile_from(
    dockerfile_text: str, expected_version: str
) -> DockerfileFromVerdict:
    """Classify what the project Dockerfile's first FROM is targeting.

    - ``"ok"``: ``FROM agentbox-base:<expected_version>``.
    - ``"version-mismatch"``: ``FROM agentbox-base:<other>`` -- the
      image will still build (assuming the user has that tag locally),
      but they're drifting from the launcher's contract version.
    - ``"non-base"``: ``FROM`` something other than ``agentbox-base``.
      The image won't include the agent runtime; the launcher will
      almost certainly fail unless the user explicitly recreated the
      contract themselves.
    - ``"missing"``: the file has no FROM directive at all -- a build
      error from Docker itself.
    """
    image = find_first_from(dockerfile_text)
    if image is None:
        return DockerfileFromVerdict("missing")

    if not image.startswith("agentbox-base:"):
        return DockerfileFromVerdict("non-base", detail=image)

    version = image.split(":", 1)[1]
    if version != expected_version:
        return DockerfileFromVerdict("version-mismatch", detail=version)

    return DockerfileFromVerdict("ok", detail=version)


# ----------------------------------------------------------------------------
# Section runners
# ----------------------------------------------------------------------------


def _section_config(
    rep: _Reporter, args: argparse.Namespace, config_path: Path | None
) -> None:
    rep.header("Config file")
    if config_path is None:
        default_path = Path.cwd() / CONFIG_FILE_NAME
        rep.info(
            "config",
            f"no {CONFIG_FILE_NAME} at {default_path} "
            "[dim](running with CLI flags + bundled defaults)[/]",
        )
    else:
        rep.ok("config", str(config_path))

    cli_repos = list(args.repo or [])
    rep.info(
        "--repo",
        ", ".join(_repo_entry_name(r) for r in cli_repos)
        if cli_repos else "(none)",
    )


def _section_credentials(
    rep: _Reporter, real_token: str, token_source: str
) -> None:
    rep.header("GitHub credentials (host-side)")
    if real_token:
        rep.ok("source", token_source)
        user = _gh_user(real_token)
        if user:
            rep.info("user", user)
        else:
            rep.warn(
                "could not look up GitHub user via `gh api user` "
                "(the token may be invalid; agentbox would still try "
                "to use it at launch)"
            )
    else:
        rep.warn(
            "no token resolved (set GH_TOKEN or run `gh auth login`); "
            "writes blocked, public reads still work"
        )
    rep.info(
        "surrogate",
        "agent gets ghp_AGENTBOX_SURROGATE_<random24>; real token "
        "stays on host",
    )


def _repo_entry_name(entry: str | dict) -> str:
    """Extract the OWNER/NAME from a config-yaml repos entry (str or dict)."""
    if isinstance(entry, str):
        return entry
    return str(entry.get("name") or "(unnamed)")


def _section_github(
    rep: _Reporter,
    args: argparse.Namespace,
    repos: list[str | dict],
    real_token: str,
    auto_detected: str | None,
) -> None:
    """Resolved GitHub access mode + per-repo policy."""
    rep.header("GitHub access")

    explicit = getattr(args, "github_mode", None)
    rep.info(
        "configured mode",
        explicit if explicit else "(none / auto)",
    )

    # Mirror cli._resolve_github_mode without importing (avoids a
    # cli <- doctor cycle today). Auto + token resolves to scoped
    # regardless of whether repos is empty -- safer than the old
    # auto + token + empty -> unrestricted default.
    if explicit and explicit != "auto":
        resolved = explicit
    elif not real_token:
        resolved = "none"
    else:
        resolved = "scoped"
    rep.ok("resolved mode", resolved)

    if auto_detected:
        rep.info(
            "auto-detected",
            f"{auto_detected} [dim](cwd's GitHub origin -- pre-filled "
            f"because no explicit --repo / config repos and mode is "
            f"auto)[/]",
        )

    if not repos:
        rep.info(
            "repos",
            "(none) [dim]-- in scoped mode, all GraphQL mutations would "
            "403 with scope_out_of_scope[/]",
        )
        return

    rep.ok("count", f"{len(repos)} repo(s)")
    for entry in repos:
        name = _repo_entry_name(entry)
        if isinstance(entry, str):
            rep.info("repo", f"{name} [dim](shorthand: full access)[/]")
        else:
            rep.info("repo", name)
            issues = entry.get("issues")
            prs = entry.get("pull_requests")
            branches = entry.get("branches")
            if issues is not None:
                rep.info("", f"  [dim]issues:[/] {', '.join(map(str, issues))}")
            if prs is not None:
                rep.info("", f"  [dim]pull_requests:[/] {', '.join(map(str, prs))}")
            if isinstance(branches, dict):
                bits = ", ".join(
                    f"{k}={v}" for k, v in branches.items() if v
                )
                if bits:
                    rep.info("", f"  [dim]branches:[/] {bits}")

    if not real_token:
        rep.error(
            "--repo / config repos set but no GitHub token resolved -- "
            "the launcher will exit at startup when it tries to call "
            "`gh api repos/...`"
        )
    else:
        rep.info(
            "resolution",
            "launcher will resolve each via `gh api repos/<owner>/<name> "
            "--jq '{node_id, full_name}'` at startup",
        )


def _section_allowlist(
    rep: _Reporter, args: argparse.Namespace
) -> tuple[dict, str]:
    """Print the allowlist section and return the parsed YAML + source path."""
    rep.header("Network allowlist")
    if args.allowlist:
        src = Path(args.allowlist).expanduser().resolve()
        if not src.is_file():
            rep.error(f"--allowlist file not found: {src}")
            return {}, str(src)
        rep.ok("source", str(src))
    else:
        src = Path(__file__).parent / "proxy" / "allowlist.yaml"
        rep.ok("source", f"{src} [dim](bundled)[/]")

    try:
        data = yaml.safe_load(src.read_text("utf-8")) or {}
    except yaml.YAMLError as exc:
        rep.error(f"allowlist parse error: {exc}")
        return {}, str(src)

    if data.get("permissive"):
        rep.info(
            "mode",
            "permissive [dim]-- all hosts allowed; "
            "domains / url_prefixes / github gate below are INACTIVE[/]",
        )
        return data, str(src)

    n_domains = len(data.get("domains") or [])
    n_prefixes = len(data.get("url_prefixes") or [])
    rep.info("domains", f"{n_domains} entries")
    if n_domains:
        sample = ", ".join(str(d) for d in (data.get("domains") or [])[:5])
        more = "..." if n_domains > 5 else ""
        rep.info("", f"[dim]{sample}{more}[/]")
    rep.info("url_prefixes", f"{n_prefixes} entries")
    return data, str(src)


def _load_github_policy(rep: _Reporter, allowlist_data: dict) -> dict:
    """Resolve which GitHub policy YAML the proxy will load.

    A user-supplied allowlist's ``github:`` block (if present)
    replaces the bundled ``github_policy.yaml`` for that session;
    otherwise the bundled defaults apply.
    """
    if "github" in allowlist_data:
        return allowlist_data.get("github") or {}
    bundled = Path(__file__).parent / "proxy" / "github_policy.yaml"
    if not bundled.is_file():
        rep.error(f"bundled github_policy.yaml missing at {bundled}")
        return {}
    try:
        return yaml.safe_load(bundled.read_text("utf-8")) or {}
    except yaml.YAMLError as exc:
        rep.error(f"github_policy.yaml parse error: {exc}")
        return {}


def _section_graphql_gate(rep: _Reporter, allowlist_data: dict) -> None:
    rep.header("GraphQL gate (api.github.com/graphql)")
    if allowlist_data.get("permissive"):
        rep.info(
            "status",
            "[dim]bypassed -- allowlist is in permissive mode[/]",
        )
        return
    github = _load_github_policy(rep, allowlist_data)
    if not github:
        rep.warn(
            "github policy is empty -- the GraphQL gate is INACTIVE; "
            "all /graphql requests pass through unchecked"
        )
        return
    rep.ok("status", "active")

    ops = github.get("graphql_operations") or {}
    queries = ops.get("queries") or []
    mutations = ops.get("mutations") or []
    subs = ops.get("subscriptions") or []
    dangerous = ops.get("dangerous") or []

    rep.info("queries", f"{len(queries)} pattern(s)")
    if queries:
        rep.info("", f"[dim]{', '.join(map(str, queries))}[/]")
    rep.info("mutations", f"{len(mutations)} pattern(s)")
    if mutations:
        sample = ", ".join(map(str, mutations[:8]))
        more = f" + {len(mutations) - 8} more" if len(mutations) > 8 else ""
        rep.info("", f"[dim]{sample}{more}[/]")
    if not subs:
        rep.info("subscriptions", "(none) [dim]-- always 403[/]")
    else:
        rep.info("subscriptions", f"{len(subs)} pattern(s)")

    if dangerous:
        rep.info("dangerous", f"{len(dangerous)} pattern(s) [dim](shadow-mode WARN)[/]")
        for pat in dangerous:
            rep.info("", f"[dim]{pat}[/]")
    else:
        rep.info("dangerous", "(none) [dim]-- no shadow-mode warnings configured[/]")


def _section_image(rep: _Reporter) -> None:
    rep.header("Container image")
    base_dockerfile_dir = Path(__file__).parent / "sandbox"
    base_dockerfile = base_dockerfile_dir / "Dockerfile"
    if not base_dockerfile.is_file():
        rep.error(f"bundled Dockerfile missing at {base_dockerfile}")
        return

    rep.info("base tag", BASE_IMAGE_TAG)
    if _docker_image_exists(BASE_IMAGE_TAG):
        rep.ok("base cache", "cached locally")
    else:
        rep.info(
            "base cache",
            "not built yet [dim](launcher will build on first run)[/]",
        )

    project_dockerfile = Path.cwd() / PROJECT_DOCKERFILE_NAME
    if not project_dockerfile.is_file():
        rep.info(
            "project",
            f"no {PROJECT_DOCKERFILE_NAME} -- agent will run in "
            f"{BASE_IMAGE_TAG} directly",
        )
        return

    project_tag = f"{PROJECT_IMAGE_PREFIX}:{_safe_image_tag(Path.cwd().name)}"
    rep.ok("project", f"{project_dockerfile.name} -> {project_tag}")
    if _docker_image_exists(project_tag):
        rep.info("project cache", "cached locally")
    else:
        rep.info(
            "project cache",
            "not built yet [dim](launcher will build on first run)[/]",
        )


def _section_dockerfile_agentbox(rep: _Reporter) -> None:
    project_dockerfile = Path.cwd() / PROJECT_DOCKERFILE_NAME
    if not project_dockerfile.is_file():
        # Nothing to validate; covered by the image section already.
        return

    rep.header(f"{PROJECT_DOCKERFILE_NAME} validation")
    text = project_dockerfile.read_text(encoding="utf-8", errors="replace")
    verdict = classify_dockerfile_from(text, BASE_IMAGE_VERSION)
    if verdict.kind == "ok":
        rep.ok("FROM", f"agentbox-base:{verdict.detail}")
    elif verdict.kind == "version-mismatch":
        rep.warn(
            f"FROM agentbox-base:{verdict.detail} -- launcher expects "
            f"agentbox-base:{BASE_IMAGE_VERSION}; either bump your "
            f"Dockerfile.agentbox or rebuild the older base image "
            f"manually"
        )
    elif verdict.kind == "non-base":
        rep.warn(
            f"FROM {verdict.detail} -- not based on agentbox-base. "
            f"The agent runtime (gh, pi, claude, credential helper, "
            f"CA trust) won't be in this image; the launcher will "
            f"likely fail unless you've recreated the contract yourself"
        )
    elif verdict.kind == "missing":
        rep.error(
            f"no FROM directive found in {PROJECT_DOCKERFILE_NAME} -- "
            f"docker build will fail"
        )


def _section_system(rep: _Reporter) -> None:
    rep.header("System prerequisites")
    if shutil.which("docker"):
        rep.ok("docker", _docker_version())
    else:
        rep.error("docker not on PATH -- launcher will fail at image build")
    if shutil.which("gh"):
        rep.ok("gh", _gh_version())
    else:
        rep.warn(
            "gh not on PATH -- needed for `--repo` resolution at startup; "
            "without it, only env-var tokens (GH_TOKEN/GITHUB_TOKEN) work"
        )
    ca_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if ca_path.exists():
        rep.ok("CA cert", str(ca_path))
    else:
        rep.info(
            "CA cert",
            f"not generated yet [dim]({ca_path} -- launcher will "
            f"create on first run)[/]",
        )


def _section_network(rep: _Reporter, args: argparse.Namespace) -> None:
    """Report the resolved network plumbing mode.

    Network mode is a launcher-side plumbing choice (host-subprocess
    proxy vs sidecar netns) and is orthogonal to the allowlist policy
    surfaced by ``_section_allowlist`` / ``_section_graphql_gate``.
    """
    rep.header("Network mode")
    mode = getattr(args, "network", None) or DEFAULT_NETWORK_MODE
    if mode == "permissive":
        rep.ok("mode", "permissive [dim](default)[/]")
        rep.info(
            "plumbing",
            "host-subprocess mitmproxy on a free 127.0.0.1 port; "
            "container reaches it via HTTPS_PROXY",
        )
        rep.info(
            "coverage",
            "HTTPS_PROXY-aware tools only [dim](gh, git, curl, npm, "
            "requests, Anthropic SDK)[/]",
        )
        rep.info(
            "bypass",
            "raw TCP, SSH, DNS exfil, statically-linked binaries -- "
            "none of these are intercepted",
        )
    elif mode == "transparent-shared":
        rep.ok("mode", "transparent-shared")
        rep.info(
            "plumbing",
            "proxy sidecar container; agent runs with "
            "--network container:<sidecar>, sharing its netns",
        )
        rep.info(
            "coverage",
            "every TCP/80+443 packet (iptables REDIRECT) and every "
            "UDP/53 query (DNS sinkhole) -- no env var needed",
        )
        rep.info("sidecar image", PROXY_SIDECAR_IMAGE_TAG)
        if _docker_image_exists(PROXY_SIDECAR_IMAGE_TAG):
            rep.ok("sidecar cache", "cached locally")
        else:
            rep.info(
                "sidecar cache",
                "not built yet [dim](launcher will build on first run)[/]",
            )
    elif mode == "transparent-isolated":
        rep.error(
            "transparent-isolated is reserved for a future Linux-only "
            "macvlan/CNI implementation and is not yet supported -- the "
            "launcher will exit with this message at startup"
        )
    else:
        rep.warn(f"unknown network mode: {mode!r}")


def _section_runtime_summary(
    rep: _Reporter,
    repos: list[str | dict],
    allowlist: dict,
    real_token: str,
) -> None:
    """Final 'this is what runtime will allow / block' summary."""
    rep.header("What this allows / blocks at runtime")
    rep.console.print("  [bold green]Allowed[/]")

    permissive = bool(allowlist.get("permissive"))
    if permissive:
        rep.console.print(
            "    [dim]·[/] Network egress to ANY host (permissive "
            "mode -- domain / url_prefix lists are inactive)"
        )
    else:
        domains = allowlist.get("domains") or []
        rep.console.print(
            f"    [dim]·[/] Network egress to {len(domains)} allowlisted "
            f"host pattern(s) (REST + git over HTTPS)"
        )
    if real_token:
        rep.console.print(
            "    [dim]·[/] GraphQL queries on any repo your host token "
            "can see (token is the outer fence)"
        )
    else:
        rep.console.print(
            "    [dim]·[/] GraphQL queries on public repos only "
            "(no host token resolved)"
        )

    github = _load_github_policy(rep, allowlist)
    ops = github.get("graphql_operations") or {}
    n_mut = len(ops.get("mutations") or [])
    if not permissive and repos and n_mut:
        names = ", ".join(_repo_entry_name(r) for r in repos)
        rep.console.print(
            f"    [dim]·[/] GraphQL writes ({n_mut} listed mutation "
            f"pattern(s)) targeting: {names}"
        )
    if permissive:
        rep.console.print(
            "    [dim]·[/] All GraphQL queries / mutations (gate "
            "bypassed in permissive mode)"
        )
    rep.console.print(
        "    [dim]·[/] git push / fetch via HTTPS to GitHub "
        "(Basic-Auth surrogate -> real swap at the proxy)"
    )

    rep.console.print()
    rep.console.print("  [bold red]Blocked[/]")
    if not permissive:
        rep.console.print(
            "    [dim]·[/] Hosts not on the allowlist (return 403 "
            "`agentbox: request not allowed`)"
        )
        if github:
            rep.console.print(
                "    [dim]·[/] GraphQL operations not in the supported "
                "list (return 403 `unsupported_feature`)"
            )
            if not repos:
                rep.console.print(
                    "    [dim]·[/] All GraphQL writes (no `--repo` / config "
                    "repos set, so scope check denies everything)"
                )
            else:
                rep.console.print(
                    "    [dim]·[/] GraphQL writes targeting any repo other "
                    "than the listed ones (return 403 `scope_out_of_scope`)"
                )
            subs = ops.get("subscriptions") or []
            if not subs:
                rep.console.print(
                    "    [dim]·[/] GraphQL subscriptions (default-deny, "
                    "no patterns configured)"
                )
    rep.console.print(
        "    [dim]·[/] Foreign Authorization headers on scoped "
        "GitHub hosts (in-container attacker can't smuggle their "
        "own token)"
    )


def _section_summary(rep: _Reporter) -> int:
    rep.header("Summary")
    n_err = sum(1 for i in rep.issues if i.is_error)
    n_warn = sum(1 for i in rep.issues if not i.is_error)
    if not rep.issues:
        rep.ok("status", "[green]no issues detected[/] -- ready to run")
        return 0
    if n_err:
        rep.console.print(
            f"  [red]x[/] {n_err} error(s), {n_warn} warning(s)"
        )
    else:
        rep.console.print(f"  [yellow]![/] {n_warn} warning(s)")
    for issue in rep.issues:
        marker = "[red]x[/]" if issue.is_error else "[yellow]![/]"
        rep.console.print(
            f"    {marker} [dim]{issue.section}:[/] {issue.message}"
        )
    return 1 if n_err else 0


# ----------------------------------------------------------------------------
# Subprocess helpers
# ----------------------------------------------------------------------------


def _docker_image_exists(tag: str) -> bool:
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", tag],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=5, check=False, env=_DOCKER_ENV,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _docker_version() -> str:
    try:
        r = subprocess.run(
            ["docker", "--version"],
            capture_output=True, text=True, timeout=5, check=False,
            env=_DOCKER_ENV,
        )
        if r.returncode == 0:
            return r.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "(version unknown)"


def _gh_version() -> str:
    try:
        r = subprocess.run(
            ["gh", "--version"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        if r.returncode == 0:
            # `gh --version` outputs "gh version X.Y.Z (...)\n..."
            return r.stdout.splitlines()[0].strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return "(version unknown)"


def _gh_user(token: str) -> str:
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    try:
        r = subprocess.run(
            ["gh", "api", "user", "--jq", ".login"],
            capture_output=True, text=True, timeout=5, env=env, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    if r.returncode != 0:
        return ""
    return r.stdout.strip()


# ----------------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------------


def _combined_repos(args: argparse.Namespace) -> list[str | dict]:
    """Match the launcher's behaviour: config-file repos came first into
    ``args.repo`` via ``_merge_config_file``; that's already the
    combined list. Entries may be either ``"OWNER/NAME"`` strings
    (CLI ``--repo`` shorthand) or dict-form policy objects (config
    yaml). This helper exists so the section runners don't have to
    reach into argparse internals.
    """
    return list(args.repo or [])


def run(args: argparse.Namespace, config_path: Path | None) -> int:
    """Run all doctor sections and return an exit code (0 ok, 1 errors).

    ``config_path`` is whatever ``cli._merge_config_file`` returned --
    if it's not None, the file has already been merged into
    ``args.repo``.
    """
    console = Console(stderr=True, highlight=False, soft_wrap=True)
    rep = _Reporter(console=console)

    console.print(Rule("agentbox · doctor", style="cyan"))
    console.print(f"  [dim]cwd:        {Path.cwd()}[/]")

    real_token, token_source = _resolve_real_token()
    repos = _combined_repos(args)

    # Mirror the launcher's auto-injection so the doctor report
    # describes the same repos the launcher would resolve. We only
    # inject under the same conditions cli._maybe_inject_cwd_repo
    # uses: auto mode (or unset) + no explicit repos + a token.
    auto_detected: str | None = None
    explicit_mode = getattr(args, "github_mode", None)
    if (
        (not explicit_mode or explicit_mode == "auto")
        and not repos
        and real_token
    ):
        auto_detected = _detect_cwd_github_repo()
        if auto_detected:
            repos = [auto_detected]

    _section_config(rep, args, config_path)
    _section_credentials(rep, real_token, token_source)
    _section_github(rep, args, repos, real_token, auto_detected)
    allowlist_data, _ = _section_allowlist(rep, args)
    _section_graphql_gate(rep, allowlist_data)
    _section_image(rep)
    _section_dockerfile_agentbox(rep)
    _section_network(rep, args)
    _section_system(rep)
    _section_runtime_summary(rep, repos, allowlist_data, real_token)
    return _section_summary(rep)
