"""agentbox launcher: spawn a coding agent in a sandbox container behind a credential-swap proxy.

The launcher:

1. Resolves a real GitHub token from the host (``GH_TOKEN`` /
   ``GITHUB_TOKEN`` env vars, falling back to ``gh auth token``) and
   generates a per-session surrogate.
2. Runs ``docker build`` for the bundled ``agentbox-base`` image; if a
   project-side ``Dockerfile.agentbox`` exists in the cwd, also runs
   ``docker build`` for an ``agentbox-project:<safe-cwd-name>`` image that
   layers project tooling on top of the base. Both build on every launch
   (Docker's layer cache keeps no-op rebuilds near-instant; ``--no-cache``
   forwards through for a clean rebuild).
3. Writes a ``credentials.json`` (per-provider surrogate/real pairs), a
   ``github.json`` (resolved access mode + per-repo policy with
   ``{full_name, node_id, issues, pull_requests, branches}``), and a
   copy of the resolved allowlist to a tempdir.
4. Ensures mitmproxy's CA cert exists, generating it if needed.
5. Starts ``python -m agentbox.proxy`` as a subprocess on a free local port.
6. Runs ``docker run`` with the chosen mode's entrypoint, mounting the cwd
   and the proxy CA, plus the minimal credentials the chosen mode needs
   (``~/.pi`` for pi mode; ``~/.claude`` and ``~/.claude.json`` for claude
   mode, when present; nothing extra for shell), and setting ``HTTPS_PROXY``
   plus per-tool CA env vars.
7. For ``pi -p`` (with session persistence on), spawns a background thread
   that tails the new session JSONL pi writes under ``~/.pi/agent/sessions/``
   and renders tool calls / results inline on stderr via
   ``agentbox.progress``. Pi runs in plain text mode, so the final answer
   flows to stdout untouched.
8. Tears down the proxy and tempdir on exit.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import secrets
import shlex
import shutil
import socket
import string
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import yaml
from rich.console import Console

from agentbox import doctor
from agentbox.progress._render import _DEBUG, _debug
from agentbox.progress.claude import run_claude_stream
from agentbox.progress.pi import tail_session_file
from agentbox._shared import (
    BASE_IMAGE_TAG,
    CONFIG_FILE_NAME,
    DEFAULT_GITHUB_MODE,
    DEFAULT_NETWORK_MODE,
    GITHUB_MODES,
    NETWORK_MODES,
    PROJECT_DOCKERFILE_NAME,
    PROJECT_IMAGE_PREFIX,
    PROXY_SIDECAR_IMAGE_TAG,
    _DOCKER_ENV,
    _detect_cwd_github_repo,
    _resolve_real_token,
    _safe_image_tag,
)

# Init log goes to stderr; rich auto-detects TTY and degrades to plain text
# when piped/redirected.
_console = Console(stderr=True, highlight=False, soft_wrap=True)


def _header(text: str) -> None:
    _console.print(text, style="cyan")


def _step(label: str, value: str = "", *, level: str = "ok") -> None:
    bullet_style = "yellow" if level == "warn" else "green"
    bullet = "!" if level == "warn" else "·"
    _console.print(
        f" [{bullet_style} dim]{bullet}[/] "
        f"[dim]{label:<11}[/]  {value}"
    )


def _short(p: Path | str) -> str:
    s = str(p)
    home = str(Path.home())
    return "~" + s[len(home):] if s.startswith(home) else s


def _github_mode_summary(
    mode: str, repos: list[dict], gh_user: str, auto_detected: str | None,
) -> str:
    """One-line description of the resolved GitHub mode for the banner.

    ``auto_detected`` is the ``owner/name`` injected by
    ``_maybe_inject_cwd_repo``, or ``None``. When set, the summary
    annotates the line so the operator can tell the cwd's origin
    drove the scope (vs an explicit ``--repo`` / config entry).
    """
    if mode == "none":
        return "none  [dim](public reads only — no token resolved)[/]"
    if mode == "unrestricted":
        suffix = f" → {gh_user}" if gh_user else ""
        return (
            f"unrestricted  [dim](token{suffix}; no per-repo fence)[/]"
        )
    if mode == "scoped":
        if not repos:
            return (
                "scoped  [dim](no repos — reads everywhere, "
                "writes nowhere)[/]"
            )
        names = ", ".join(r["full_name"] for r in repos)
        n = len(repos)
        suffix = (
            "; auto-detected from cwd"
            if auto_detected and len(repos) == 1
            and repos[0]["full_name"] == auto_detected
            else ""
        )
        return (
            f"scoped  [dim]({n} repo{'s' if n != 1 else ''}: "
            f"{names}{suffix})[/]"
        )
    return mode


def _network_mode_summary(mode: str) -> str:
    """One-line description of a network mode for the startup banner."""
    if mode == "permissive":
        return (
            "permissive  [dim](host-subprocess proxy on HTTPS_PROXY; "
            "no enforcement at the proxy)[/]"
        )
    if mode == "transparent-shared":
        return (
            "transparent-shared  [dim](sidecar netns + iptables; "
            "every TCP/UDP packet intercepted)[/]"
        )
    return mode  # transparent-isolated bails before this is called


def _proxy_start_failed(log_path: Path) -> None:
    """Print the proxy log inline and exit; keep the log on disk for re-reading."""
    _console.print("\n[red]agentbox: proxy failed to start[/]")
    if log_path.exists():
        text = log_path.read_text(encoding="utf-8", errors="replace").rstrip()
        _console.print(f"[dim]── {log_path} ──[/]")
        _console.print(text or "[dim](empty)[/]")
        _console.print("[dim]── end ──[/]")
    else:
        _console.print(f"[dim](no proxy log at {log_path})[/]")
    sys.exit(1)

MODES: dict[str, dict] = {
    "pi": {
        "entrypoint": "pi",
        "default_args": [],
        "resume_hint": "agentbox pi -- --continue",
    },
    "claude": {
        "entrypoint": "claude",
        "default_args": [],
        "resume_hint": "agentbox claude -- --continue",
    },
    "shell": {
        "entrypoint": "bash",
        "default_args": [],
        "resume_hint": None,
    },
}

def main(argv: list[str] | None = None) -> None:
    try:
        _main(argv)
    except KeyboardInterrupt:
        print("\nagentbox: interrupted", file=sys.stderr)
        sys.exit(130)


def _main(argv: list[str] | None) -> None:
    args = _parse_args(argv)
    config_path = _merge_config_file(args)

    # Container workdir override: CLI > config > None. When None, the
    # default in _run_agent kicks in (mirror the host cwd under
    # /agentbox/). Validated up-front -- including under doctor mode
    # -- so a typo surfaces immediately rather than at docker-run time.
    workdir_override: str | None = getattr(args, "workdir", None)
    if workdir_override is not None:
        workdir_override = _validate_container_workdir(workdir_override)
        args.workdir = workdir_override  # store normalized value

    # Resolve network mode: CLI flag > config file > default. Default
    # stays permissive so today's local-dev flow keeps working unchanged.
    network_mode = getattr(args, "network", None) or DEFAULT_NETWORK_MODE
    args.network = network_mode  # so doctor and downstream see the resolved value

    if network_mode == "transparent-isolated":
        sys.exit(
            "agentbox: --network transparent-isolated is reserved for a "
            "future Linux-only macvlan/CNI implementation and is not yet "
            "supported. Use --network transparent-shared for "
            "cross-platform full-TCP interception, or --network "
            "permissive (default) for HTTPS_PROXY-based proxying."
        )

    if args.mode == "doctor":
        # Doctor is a read-only inspector: don't build images, don't
        # start the proxy, don't run docker. Just analyse what's
        # configured and report.
        sys.exit(doctor.run(args, config_path))

    _header(f"agentbox · {args.mode}")
    if config_path is not None:
        _step("config", _short(config_path))
    image_tag = _ensure_image(
        no_cache=args.no_cache, cwd=Path.cwd(), network_mode=network_mode,
    )

    real_token, token_source = _resolve_real_token()
    gh_user = _lookup_gh_user(real_token) if real_token else ""
    if real_token:
        _step(
            "token",
            f"{token_source}" + (f" → {gh_user}" if gh_user else ""),
        )
    else:
        _step(
            "token",
            "none — public reads only (set GH_TOKEN or `gh auth login`)",
            level="warn",
        )
    surrogate = _generate_gh_surrogate()

    workdir = Path(tempfile.mkdtemp(prefix="agentbox-"))
    cleanup_workdir = [True]
    atexit.register(
        lambda: shutil.rmtree(workdir, ignore_errors=True)
        if cleanup_workdir[0] else None
    )

    _write_credentials(workdir / "credentials.json", surrogate, real_token)
    allowlist_summary = _copy_allowlist(
        workdir / "allowlist.yaml", source=args.allowlist,
    )
    _step("network", _network_mode_summary(network_mode))
    _step("allowlist", allowlist_summary)

    auto_detected = _maybe_inject_cwd_repo(args, real_token)
    resolved_repos = _resolve_repos(args.repo, real_token)
    github_mode = _resolve_github_mode(
        getattr(args, "github_mode", None), real_token,
    )
    args.github_mode = github_mode  # so doctor and downstream see resolved value
    _write_github_policy(workdir / "github.json", github_mode, resolved_repos)
    _step(
        "github",
        _github_mode_summary(
            github_mode, resolved_repos, gh_user, auto_detected,
        ),
    )

    ca_path = _ensure_mitmproxy_ca()

    # Resolve --mock-llm / --mock-llm-transcript before starting the
    # proxy. The resolved paths are absolute on the host: in permissive
    # mode the proxy runs as a host subprocess so it reads them directly;
    # in transparent-shared mode the script is staged into workdir and
    # the sidecar reads it from /agentbox/proxy/mock_llm.py (transcript
    # writing is unsupported in sidecar mode -- the sidecar's workdir
    # bind-mount is read-only).
    mock_llm_host_path: str | None = None
    mock_transcript_host_path: str | None = None
    if args.mock_llm is not None:
        resolved = Path(args.mock_llm).expanduser().resolve()
        if not resolved.is_file():
            sys.exit(f"agentbox: --mock-llm script not found: {resolved}")
        if network_mode == "transparent-shared":
            staged = workdir / "mock_llm.py"
            shutil.copy(resolved, staged)
            staged.chmod(0o644)
            mock_llm_host_path = str(staged)
            _step("mock-llm", _short(resolved))
        else:
            mock_llm_host_path = str(resolved)
            _step("mock-llm", _short(resolved))
    if args.mock_llm_transcript is not None:
        if network_mode != "permissive":
            sys.exit(
                "agentbox: --mock-llm-transcript is supported only with "
                "--network permissive (the sidecar's workdir mount is "
                "read-only). Drop the flag or switch network modes."
            )
        if args.mock_llm is None:
            sys.exit(
                "agentbox: --mock-llm-transcript requires --mock-llm"
            )
        mock_transcript_host_path = str(
            Path(args.mock_llm_transcript).expanduser().resolve()
        )

    sidecar_name: str | None = None
    port: int = 0
    if network_mode == "permissive":
        port = _find_free_port()
        t0 = time.monotonic()
        proxy = _start_proxy(
            workdir, port,
            mock_llm=mock_llm_host_path,
            mock_transcript=mock_transcript_host_path,
        )
        atexit.register(lambda: _terminate(proxy))
        if not _wait_for_port(port, timeout=15):
            cleanup_workdir[0] = False  # keep proxy.log around for the user
            _proxy_start_failed(workdir / "proxy.log")
        _step(
            "proxy",
            f"127.0.0.1:{port} [dim](ready in {time.monotonic() - t0:.1f}s)[/]",
        )
    else:  # transparent-shared
        sidecar_name = f"agentbox-proxy-{os.getpid()}"
        t0 = time.monotonic()
        _start_sidecar(sidecar_name, workdir, ca_path)
        atexit.register(lambda: _stop_sidecar(sidecar_name))
        if not _wait_for_sidecar_ready(sidecar_name, timeout=20):
            cleanup_workdir[0] = False  # keep proxy.log around for the user
            _dump_sidecar_logs(sidecar_name, workdir / "proxy.log")
            _proxy_start_failed(workdir / "proxy.log")
        _step(
            "sidecar",
            f"{sidecar_name} [dim](ready in {time.monotonic() - t0:.1f}s)[/]",
        )

    rc = _run_agent(
        args.mode, port, surrogate, real_token, ca_path,
        args.mode_args, image_tag=image_tag, workdir=workdir,
        container_workdir=workdir_override,
        network_mode=network_mode, sidecar_name=sidecar_name,
    )

    hint = MODES[args.mode].get("resume_hint")
    if hint:
        _console.print(f"\n[dim]agentbox: resume with  {hint}[/]")

    sys.exit(rc)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="agentbox",
        description=(
            "Run a coding agent in a sandbox container behind a "
            "credential-swap proxy."
        ),
    )
    parser.add_argument(
        "mode", nargs="?", default="pi",
        choices=[*MODES, "doctor"],
        help=(
            "What to launch: pi (default), shell, claude. "
            "Or `doctor` to run a read-only validation + runtime-config "
            "report instead of starting the agent."
        ),
    )
    parser.add_argument(
        "--no-cache", action="store_true",
        help=(
            "Pass `--no-cache` to `docker build` for the base and "
            "project images, forcing a clean rebuild from scratch. "
            "Without this flag, every launch still runs `docker "
            "build` -- Docker's layer cache makes a no-op build "
            "fast -- but layer reuse is enabled."
        ),
    )
    parser.add_argument(
        "--allowlist", default=None, metavar="PATH",
        help=(
            "Path to a custom allowlist.yaml. Defaults to the bundled "
            "permissive allowlist (Anthropic, GitHub, npm, PyPI). The file "
            "is copied to the proxy's tempdir at launch, so post-launch "
            "edits don't affect the running session."
        ),
    )
    parser.add_argument(
        "--repo", action="append", default=[], metavar="OWNER/NAME",
        help=(
            "GitHub repository the agent is permitted to write to via "
            "/graphql. Repeatable. Reads (queries) are governed by the "
            "host's PAT scopes -- this flag only widens the GraphQL "
            "scope check for mutations. Unset = no GraphQL writes. "
            "Additive over `github.repos` from the config file."
        ),
    )
    parser.add_argument(
        "--config", default=None, metavar="PATH",
        help=(
            "Path to a agentbox.config.yaml. If omitted, agentbox looks "
            "for `agentbox.config.yaml` in the current working directory "
            "and silently runs without it if absent. Pass an explicit "
            "path to require the file (the launcher exits if it's "
            "missing or malformed)."
        ),
    )
    parser.add_argument(
        "--workdir", default=None, metavar="PATH",
        help=(
            "Override the container-side workdir (an absolute POSIX "
            "path). By default the host cwd is mirrored under "
            "`/agentbox/` (e.g. C:\\code\\foo -> /agentbox/c/code/foo); "
            "pass --workdir /app to mount it at /app instead. Useful "
            "when project tooling embeds container paths into build "
            "artifacts and you want them stable across hosts. CLI "
            "wins over the config file's `workdir:` key."
        ),
    )
    parser.add_argument(
        "--network", default=None, choices=list(NETWORK_MODES), metavar="MODE",
        help=(
            "Network plumbing mode. permissive (default): host-subprocess "
            "proxy on HTTPS_PROXY env var; tools that ignore the env "
            "bypass freely; the proxy itself does no enforcement. "
            "transparent-shared: proxy sidecar with iptables REDIRECT in "
            "a shared netns -- intercepts every TCP/UDP packet leaving "
            "the agent, no env var needed. transparent-isolated: reserved "
            "for a Linux-only macvlan/CNI implementation; not yet "
            "supported."
        ),
    )
    parser.add_argument(
        "--github-mode", default=None, choices=list(GITHUB_MODES),
        metavar="MODE",
        help=(
            "GitHub access mode. auto (default) resolves based on token "
            "presence and `github.repos:` from config: no token -> none "
            "(public reads only); token + no repos -> unrestricted (full "
            "PAT capability); token + repos -> scoped (writes fenced to "
            "listed repos). Explicit values: none, unrestricted, scoped. "
            "Wins over `github.mode` from the config file."
        ),
    )
    parser.add_argument(
        "--mock-llm", default=None, metavar="PATH",
        help=(
            "Path to a Python module that scripts mock LLM responses. "
            "When set, the proxy short-circuits requests to known LLM "
            "hosts (api.anthropic.com, api.openai.com, api.z.ai) with "
            "replies from this script instead of forwarding upstream. "
            "Test/CI affordance: lets the real `pi` / `claude` binaries "
            "run e2e in the sandbox without any network or API key. "
            "See proxy/mock_llm.py for the script API."
        ),
    )
    parser.add_argument(
        "--mock-llm-transcript", default=None, metavar="PATH",
        help=(
            "Append a JSONL transcript of every intercepted LLM "
            "request/response to this path. Only meaningful with "
            "--mock-llm. Useful for asserting on what the agent asked "
            "the model in e2e tests. Permissive network mode only."
        ),
    )
    parser.add_argument(
        "mode_args", nargs=argparse.REMAINDER,
        help="Args forwarded to the agent (use -- to separate)",
    )
    args = parser.parse_args(argv)
    if args.mode_args and args.mode_args[0] == "--":
        args.mode_args = args.mode_args[1:]
    return args


def _lookup_gh_user(token: str) -> str:
    """Best-effort lookup of the GitHub login that owns ``token``.

    Uses ``gh api user`` with the resolved token forced via env. Returns
    ``""`` on any failure (no network, ``gh`` missing, bad token, ...) so the
    caller can fall back to printing just the source.
    """
    env = os.environ.copy()
    env["GH_TOKEN"] = token
    try:
        result = subprocess.run(
            ["gh", "api", "user", "--jq", ".login"],
            capture_output=True, text=True, timeout=3, env=env, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return ""
    if result.returncode != 0:
        return ""
    return result.stdout.strip()


def _generate_gh_surrogate() -> str:
    """Generate a per-session GitHub-token-shaped surrogate.

    The string is deliberately *not* format-preserving: it embeds the
    literal ``AGENTBOX_SURROGATE`` so it is trivially greppable in any log
    or process listing and never confused for a real PAT. The ``ghp_``
    prefix is kept so tools that prefix-validate tokens still accept it.
    """
    alphabet = string.ascii_letters + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(24))
    return f"ghp_AGENTBOX_SURROGATE_{suffix}"


def _write_credentials(path: Path, surrogate: str, real_token: str) -> None:
    """Write the per-session credentials JSON consumed by the proxy filter.

    Schema is keyed by credential kind so each handler in
    ``agentbox.proxy.handlers`` reads its own block. Scopes and header
    names live in the handler, not in this file -- the launcher only
    decides *which* handler to enable and *what* surrogate/real pair to
    hand it.
    """
    data: dict = {}
    if real_token:
        data["github"] = {
            "surrogate": surrogate,
            "real": real_token,
        }
    path.write_text(json.dumps(data), encoding="utf-8")


_REPO_OP_KEYS: tuple[str, ...] = ("issues", "pull_requests")
_BRANCH_OP_KEYS: tuple[str, ...] = ("push", "create", "delete")


def _validate_repo_policy_dict(config_path: Path, entry: dict) -> None:
    """Validate the dict-form ``github.repos[]`` entry shape.

    Exits with a clear error on any structural problem. The accepted
    shape is::

        - name: owner/repo                  # required string
          issues:        [comment, ...]     # optional list of strings
          pull_requests: [comment, ...]     # optional list of strings
          branches:                          # optional mapping
            push:   ["agent/*"]              # optional list of strings
            create: ["agent/*"]              # optional list of strings
            delete: ["agent/*"]              # optional list of strings

    The op vocabulary itself is intentionally not validated here --
    chunk-3 enforcement reads these lists, and we'd rather pass an
    unknown op token through to the proxy (where it'll just never
    match an operation) than reject it at config-load time and lock
    users out of agentbox upgrades that introduce new op tokens.
    """
    name = entry.get("name")
    if not isinstance(name, str) or not name:
        sys.exit(
            f"agentbox: {config_path}: 'github.repos[]' dict entry "
            f"missing required string field 'name', got {entry!r}"
        )
    for key in _REPO_OP_KEYS:
        if key not in entry:
            continue
        value = entry[key]
        if not isinstance(value, list) or not all(
            isinstance(v, str) for v in value
        ):
            sys.exit(
                f"agentbox: {config_path}: 'github.repos[].{key}' must "
                f"be a list of strings, got {value!r}"
            )
    if "branches" in entry:
        branches = entry["branches"]
        if not isinstance(branches, dict):
            sys.exit(
                f"agentbox: {config_path}: 'github.repos[].branches' "
                f"must be a mapping, got {branches!r}"
            )
        for key in _BRANCH_OP_KEYS:
            if key not in branches:
                continue
            value = branches[key]
            if not isinstance(value, list) or not all(
                isinstance(v, str) for v in value
            ):
                sys.exit(
                    f"agentbox: {config_path}: "
                    f"'github.repos[].branches.{key}' must be a list "
                    f"of strings, got {value!r}"
                )


def _merge_config_file(args: argparse.Namespace) -> Path | None:
    """Load ``agentbox.config.yaml`` and fold its values into ``args``.

    Resolution order:

    - ``--config PATH`` overrides everything; the file must exist or
      the launcher exits.
    - Otherwise, ``./agentbox.config.yaml`` is consulted if present;
      a missing file is a silent no-op (the common case for users
      who haven't set one up yet).

    Today ``github.{mode,repos}``, ``network``, and ``workdir`` are
    read. ``github.repos`` is *additive* over ``--repo`` CLI flags
    (file entries first, CLI appended); ``github.mode``, ``network``,
    and ``workdir`` only apply when the matching CLI flag wasn't
    given. Other top-level keys are silently kept aside for future
    schema growth -- a typo in an unknown section won't surface as
    an error here, by design, so configs from a newer agentbox load
    on an older one.

    ``github.repos[]`` accepts two entry shapes:

    - String shorthand: ``"owner/name"`` -- writes-only fence applies
      but every operation is allowed inside.
    - Dict form: ``{name, issues?, pull_requests?, branches?}`` --
      per-operation allowlist; absent keys default to ``["*"]``
      (full access). The chunk-3 enforcement layer reads these
      lists; chunk 2 just preserves them through the pipeline.

    TODO(policy-language): the per-repo dict-form fields above are
    still relatively flat. We eventually want richer expressions
    like ``branches_matching: ["agent/*", "!main"]``,
    ``issue_authors: [@me]``, ``dangerous_overrides: [...]``. The
    scope check (Layer 2) already decodes per-object DB IDs inside
    node IDs, so the enforcement substrate is in place. See
    matching markers in ``proxy/graphql_scope.py``,
    ``proxy/github_policy.yaml``, and ``docs/design.md``.

    Returns the resolved path of the config file used (for the
    startup banner), or ``None`` if no config was loaded.
    """
    explicit = args.config is not None
    if explicit:
        path = Path(args.config).expanduser().resolve()
        if not path.is_file():
            sys.exit(f"agentbox: config file not found: {path}")
    else:
        path = Path.cwd() / CONFIG_FILE_NAME
        if not path.is_file():
            return None

    try:
        data = yaml.safe_load(path.read_text("utf-8")) or {}
    except yaml.YAMLError as exc:
        sys.exit(f"agentbox: invalid YAML in {path}: {exc}")

    if not isinstance(data, dict):
        sys.exit(f"agentbox: {path} must be a YAML mapping at top level")

    github = data.get("github") or {}
    if not isinstance(github, dict):
        sys.exit(f"agentbox: {path}: 'github:' must be a mapping")

    if "mode" in github:
        config_mode = github.get("mode")
        if config_mode is not None and config_mode not in GITHUB_MODES:
            sys.exit(
                f"agentbox: {path}: unknown 'github.mode:' value "
                f"{config_mode!r}; expected one of "
                f"{', '.join(GITHUB_MODES)}"
            )
        if getattr(args, "github_mode", None) is None:
            args.github_mode = config_mode

    config_repos = github.get("repos") or []
    if not isinstance(config_repos, list):
        sys.exit(f"agentbox: {path}: 'github.repos:' must be a list")
    for r in config_repos:
        if isinstance(r, str):
            continue
        if isinstance(r, dict):
            _validate_repo_policy_dict(path, r)
            continue
        sys.exit(
            f"agentbox: {path}: 'github.repos[]' entries must be "
            f"strings or mappings, got {r!r}"
        )

    # Additive: file entries first, CLI flags appended. Order matters
    # only for the startup log line ("repos: ...") -- the proxy
    # treats the set as unordered. Mixed str / dict entries are
    # preserved as-is and normalised later in `_resolve_repos`.
    args.repo = list(config_repos) + list(args.repo or [])

    # Network mode: validated at config-load time so a typo in the YAML
    # surfaces here rather than as a confusing later failure. Unlike
    # other config keys (which we silently keep aside for forward-compat),
    # an unknown network mode is rejected -- silently degrading to a
    # different security posture is exactly the foot-gun this validation
    # exists to prevent. CLI flag wins over file when both are set.
    if "network" in data:
        config_network = data.get("network")
        if config_network is not None and config_network not in NETWORK_MODES:
            sys.exit(
                f"agentbox: {path}: unknown 'network:' value "
                f"{config_network!r}; expected one of "
                f"{', '.join(NETWORK_MODES)}"
            )
        if getattr(args, "network", None) is None:
            args.network = config_network

    # Container workdir override: a user-supplied absolute POSIX path
    # the launcher mounts the host cwd at instead of the default
    # /agentbox/<mirrored-host-path>. Validated at use-time in _main
    # so both the file value and any CLI value run through the same
    # check. CLI flag wins over file when both are set.
    if "workdir" in data:
        config_workdir = data.get("workdir")
        if config_workdir is not None and not isinstance(config_workdir, str):
            sys.exit(f"agentbox: {path}: 'workdir:' must be a string")
        if config_workdir and getattr(args, "workdir", None) is None:
            args.workdir = config_workdir
    return path


_DEFAULT_REPO_POLICY: dict = {
    "issues": ["*"],
    "pull_requests": ["*"],
    "branches": {"push": ["*"], "create": ["*"], "delete": ["*"]},
}


def _normalize_repo_entry(entry: str | dict) -> dict:
    """Lift a config-yaml ``github.repos[]`` entry into the canonical dict.

    String shorthand expands to the full-access policy; dict-form
    entries inherit defaults for keys they don't specify. The
    returned dict carries the per-repo policy and the spec to
    resolve to a node ID.
    """
    if isinstance(entry, str):
        return {"name": entry, **_DEFAULT_REPO_POLICY}
    out: dict = {"name": entry["name"]}
    out["issues"] = list(entry.get("issues", _DEFAULT_REPO_POLICY["issues"]))
    out["pull_requests"] = list(
        entry.get("pull_requests", _DEFAULT_REPO_POLICY["pull_requests"])
    )
    branches_default = _DEFAULT_REPO_POLICY["branches"]
    branches = entry.get("branches") or {}
    out["branches"] = {
        key: list(branches.get(key, branches_default[key]))
        for key in _BRANCH_OP_KEYS
    }
    return out


def _resolve_repos(
    repos: list[str | dict], real_token: str,
) -> list[dict]:
    """Resolve each ``OWNER/NAME`` (or dict-form policy) to a full repo entry.

    Hits ``GET /repos/{owner}/{name}`` with the user's real PAT via
    ``gh api`` so the proxy can verify GraphQL writes target only
    these repos. A 404, network failure, or missing PAT exits the
    launcher: we'd rather refuse to start than silently load a
    permissive (empty allow-set) GraphQL gate when the user clearly
    asked for one.

    Each input entry may be either an ``OWNER/NAME`` string
    (shorthand for the full-access per-repo policy) or a dict
    ``{name, issues?, pull_requests?, branches?}`` from the
    config-yaml. Returned dicts carry ``{full_name, node_id,
    issues, pull_requests, branches}`` -- ready to write to
    ``github.json`` and consume in the proxy.
    """
    if not repos:
        return []
    if not real_token:
        sys.exit(
            "agentbox: --repo requires a host GitHub token "
            "(set GH_TOKEN or run `gh auth login`)"
        )
    env = os.environ.copy()
    env["GH_TOKEN"] = real_token
    resolved: list[dict] = []
    for raw in repos:
        normalized = _normalize_repo_entry(raw)
        spec = normalized["name"]
        if "/" not in spec:
            sys.exit(f"agentbox: --repo expects OWNER/NAME, got {spec!r}")
        try:
            result = subprocess.run(
                [
                    "gh", "api", f"repos/{spec}",
                    "--jq", "{node_id: .node_id, full_name: .full_name}",
                ],
                capture_output=True, text=True, timeout=10, env=env, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            sys.exit(f"agentbox: failed to resolve --repo {spec}: {exc}")
        if result.returncode != 0:
            err = result.stderr.strip() or result.stdout.strip()
            sys.exit(f"agentbox: failed to resolve --repo {spec}: {err}")
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            sys.exit(
                f"agentbox: gh api repos/{spec} returned non-JSON: {exc}"
            )
        node_id = payload.get("node_id")
        full_name = payload.get("full_name")
        if not isinstance(node_id, str) or not isinstance(full_name, str):
            sys.exit(
                f"agentbox: gh api repos/{spec} missing node_id/full_name "
                f"({payload!r})"
            )
        resolved.append({
            "full_name": full_name,
            "node_id": node_id,
            "issues": normalized["issues"],
            "pull_requests": normalized["pull_requests"],
            "branches": normalized["branches"],
        })
    return resolved


def _resolve_github_mode(
    explicit: str | None, real_token: str,
) -> str:
    """Map (explicit mode, token presence) onto a concrete mode.

    Explicit ``none``/``unrestricted``/``scoped`` always wins.
    ``auto`` (or unset) resolves per the table:

    +--------------+----------------+
    | token        | resolved mode  |
    +==============+================+
    | absent       | ``none``       |
    | present      | ``scoped``     |
    +--------------+----------------+

    The auto default is **scoped** even when ``repos`` is empty:
    "read everywhere, write nowhere" beats "write everywhere
    your PAT can reach" as a safe default. The launcher tries
    to pre-fill ``repos`` with the cwd's GitHub origin (see
    ``_maybe_inject_cwd_repo``) so the common case -- agentbox
    spawned inside a working tree -- gets writes to that one
    repo. Pass ``--github-mode unrestricted`` (or set
    ``github.mode: unrestricted`` in the config file) for the
    old behaviour.
    """
    if explicit and explicit != "auto":
        return explicit
    if not real_token:
        return "none"
    return "scoped"


def _maybe_inject_cwd_repo(
    args: argparse.Namespace, real_token: str,
) -> str | None:
    """Pre-fill ``args.repo`` from the cwd's GitHub origin in auto mode.

    When the user hasn't specified an explicit mode (or chose
    ``auto``) and hasn't listed any repos via ``--repo`` / config
    yaml, we try to detect the cwd's GitHub origin and prepend it
    as a string-shorthand entry. The result is the "default mode
    is read/write the current repo, read-only the rest" behaviour
    callers expect.

    Returns the injected ``owner/name``, or ``None`` if no injection
    was made (already explicit, repos already listed, no token, or
    cwd has no recognised GitHub origin).
    """
    explicit = getattr(args, "github_mode", None)
    if explicit and explicit != "auto":
        return None
    if args.repo:
        return None
    if not real_token:
        return None
    cwd_repo = _detect_cwd_github_repo()
    if not cwd_repo:
        return None
    args.repo = [cwd_repo]
    return cwd_repo


def _write_github_policy(
    path: Path, mode: str, repos: list[dict],
) -> None:
    """Write the GitHub access policy JSON consumed by the proxy filter.

    Schema::

        {
          "mode": "<none|unrestricted|scoped>",
          "repos": [
            {full_name, node_id, issues, pull_requests, branches},
            ...
          ]
        }

    ``mode`` is the resolved value (never ``auto`` -- that's
    expanded by ``_resolve_github_mode``). Chunk-3 enforcement
    reads this same shape; chunk 2 only produces it.
    """
    payload = {"mode": mode, "repos": repos}
    path.write_text(json.dumps(payload), encoding="utf-8")


def _copy_allowlist(dst: Path, source: str | None = None) -> str:
    """Copy the active allowlist to ``dst`` and return a one-line summary.

    ``source`` is an optional override (the ``--allowlist`` CLI arg). When
    None, falls back to the bundled default at
    ``agentbox/proxy/allowlist.yaml``.
    """
    if source is not None:
        src = Path(source).expanduser().resolve()
        if not src.is_file():
            sys.exit(f"agentbox: allowlist file not found: {src}")
    else:
        src = Path(__file__).parent / "proxy" / "allowlist.yaml"
        if not src.exists():
            sys.exit(f"agentbox: bundled allowlist missing at {src}")
    shutil.copy(src, dst)
    try:
        data = yaml.safe_load(src.read_text("utf-8")) or {}
    except yaml.YAMLError:
        return f"(parse error — see {src})"

    if data.get("permissive"):
        # Permissive mode: domain / prefix / GraphQL-gate fields in the
        # YAML are inert. Don't print a domain count -- it would imply
        # scoping that isn't being enforced.
        if source is None:
            return (
                "permissive [dim](default — all hosts allowed; "
                "pass --allowlist to scope down)[/]"
            )
        return f"permissive  [dim]({_short(src)})[/]"

    n_domains = len(data.get("domains") or [])
    n_prefixes = len(data.get("url_prefixes") or [])
    parts = [f"{n_domains} domains"]
    if n_prefixes:
        parts.append(f"{n_prefixes} url_prefixes")
    summary = ", ".join(parts)
    if source is not None:
        summary += f"  [dim]({_short(src)})[/]"
    return summary


def _find_free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _ensure_mitmproxy_ca() -> Path:
    ca_dir = Path.home() / ".mitmproxy"
    cert_path = ca_dir / "mitmproxy-ca-cert.pem"
    if cert_path.exists():
        return cert_path
    t0 = time.monotonic()
    ca_dir.mkdir(parents=True, exist_ok=True)
    port = _find_free_port()
    log_path = ca_dir / "agentbox-bootstrap.log"
    log = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(
        [sys.executable, "-c",
         "from mitmproxy.tools.main import mitmdump; "
         "import sys; sys.exit(mitmdump() or 0)",
         "--listen-host", "127.0.0.1", "--listen-port", str(port), "-q"],
        stdout=log, stderr=subprocess.STDOUT,
    )
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline and not cert_path.exists():
        time.sleep(0.2)
    _terminate(proc)
    log.close()
    if not cert_path.exists():
        sys.exit(
            f"agentbox: failed to generate mitmproxy CA cert; see {log_path}"
        )
    _step("ca", f"generated mitmproxy CA in {time.monotonic() - t0:.1f}s")
    return cert_path


def _start_proxy(
    workdir: Path,
    port: int,
    *,
    mock_llm: str | None = None,
    mock_transcript: str | None = None,
) -> subprocess.Popen:
    log = (workdir / "proxy.log").open("a", encoding="utf-8")
    cmd = [
        sys.executable, "-m", "agentbox.proxy",
        "--port", str(port),
        "--credentials", str(workdir / "credentials.json"),
        "--allowlist", str(workdir / "allowlist.yaml"),
        "--github-policy", str(workdir / "github.json"),
    ]
    if mock_llm:
        cmd += ["--mock-llm", mock_llm]
    if mock_transcript:
        cmd += ["--mock-llm-transcript", mock_transcript]
    return subprocess.Popen(
        cmd, stdout=log, stderr=subprocess.STDOUT,
    )


def _wait_for_port(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def _run_docker_build(cmd: list[str], spinner_text: str) -> tuple[int, str]:
    """Run ``docker build`` with output captured and a spinner shown.

    Returns ``(returncode, combined_output)``. The spinner clears as
    soon as the build exits. The caller decides what to do with the
    captured output -- typically discard on success and dump on
    failure.
    """
    with _console.status(spinner_text, spinner="dots"):
        proc = subprocess.run(
            cmd,
            env=_DOCKER_ENV,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            check=False,
        )
    return proc.returncode, proc.stdout or ""


def _ensure_image(no_cache: bool, cwd: Path, network_mode: str) -> str:
    """Build the agentbox-base (and project image, if any) for this run.

    Two-tier model:

    - **agentbox-base** (``BASE_IMAGE_TAG``) is the agent runtime: gh,
      pi, claude, the credential helper, mitmproxy CA trust. Always
      built first; project images ``FROM`` this tag.
    - **agentbox-project:<safe-cwd>** is built from the project's
      ``Dockerfile.agentbox`` if one exists in ``cwd``, layering the
      project's toolchain on top of the base. If no project Dockerfile
      is present, agentbox runs the agent in the base image directly --
      zero-config startup for projects that don't need extra tools.

    When ``network_mode == "transparent-shared"``, also builds the
    proxy sidecar image (``agentbox-proxy-sidecar:local``). Permissive
    mode never touches the sidecar image.

    ``docker build`` runs on every launch. Docker's layer cache makes
    a no-op build very fast, so we always re-run it rather than try
    to detect whether the inputs changed. Pass ``no_cache=True`` to
    forward ``--no-cache`` and force a clean rebuild from scratch.

    Build output is captured and only surfaced on failure -- a
    successful no-op build stays silent behind the spinner.

    Returns the image tag to ``docker run``: the project tag when one
    was built, otherwise the base tag.
    """
    base_dockerfile_dir = Path(__file__).parent / "sandbox"
    base_dockerfile = base_dockerfile_dir / "Dockerfile"
    if not base_dockerfile.exists():
        sys.exit(
            f"agentbox: bundled Dockerfile missing at {base_dockerfile}"
        )

    cache_args = ["--no-cache"] if no_cache else []

    # Tier 1: agentbox-base.
    t0 = time.monotonic()
    rc, output = _run_docker_build(
        ["docker", "build", *cache_args, "-t", BASE_IMAGE_TAG,
         str(base_dockerfile_dir)],
        f"[dim]building {BASE_IMAGE_TAG} from bundled Dockerfile…[/]",
    )
    if rc != 0:
        if output:
            sys.stderr.write(output)
            if not output.endswith("\n"):
                sys.stderr.write("\n")
        sys.exit(
            f"agentbox: failed to build {BASE_IMAGE_TAG} (exit {rc})"
        )
    base_secs = time.monotonic() - t0

    # Tier 2: project image (only if Dockerfile.agentbox exists in cwd).
    project_dockerfile = cwd / PROJECT_DOCKERFILE_NAME
    if not project_dockerfile.is_file():
        _step(
            "image",
            f"{BASE_IMAGE_TAG} [dim](base built in {base_secs:.1f}s, "
            f"no {PROJECT_DOCKERFILE_NAME})[/]",
        )
        return BASE_IMAGE_TAG

    project_tag = f"{PROJECT_IMAGE_PREFIX}:{_safe_image_tag(cwd.name)}"
    t0 = time.monotonic()
    rc, output = _run_docker_build(
        [
            "docker", "build", *cache_args,
            "-t", project_tag,
            "-f", str(project_dockerfile),
            str(cwd),
        ],
        f"[dim]building {project_tag} from {PROJECT_DOCKERFILE_NAME}…[/]",
    )
    if rc != 0:
        if output:
            sys.stderr.write(output)
            if not output.endswith("\n"):
                sys.stderr.write("\n")
        sys.exit(
            f"agentbox: failed to build {project_tag} from "
            f"{project_dockerfile} (exit {rc}). "
            f"Make sure {PROJECT_DOCKERFILE_NAME} starts with "
            f"`FROM {BASE_IMAGE_TAG}`."
        )
    _step(
        "image",
        f"{project_tag} [dim](built in {time.monotonic() - t0:.1f}s, "
        f"FROM {BASE_IMAGE_TAG} built in {base_secs:.1f}s)[/]",
    )
    return project_tag


def _build_sidecar_image(*, no_cache: bool) -> None:
    """Build the proxy sidecar image (used by network=transparent-shared).

    Uses ``src/agentbox`` as the build context with ``-f
    sandbox/proxy/Dockerfile`` so the Dockerfile can COPY the
    ``agentbox.proxy`` package into the image without escaping the
    context. Layer cache makes a no-op rebuild near-instant; pass
    ``no_cache=True`` to forward ``--no-cache``.
    """
    pkg_root = Path(__file__).parent  # .../src/agentbox
    sidecar_dockerfile = pkg_root / "sandbox" / "proxy" / "Dockerfile"
    if not sidecar_dockerfile.exists():
        sys.exit(
            f"agentbox: bundled sidecar Dockerfile missing at "
            f"{sidecar_dockerfile}"
        )
    cache_args = ["--no-cache"] if no_cache else []
    t0 = time.monotonic()
    rc, output = _run_docker_build(
        [
            "docker", "build", *cache_args,
            "-t", PROXY_SIDECAR_IMAGE_TAG,
            "-f", str(sidecar_dockerfile),
            str(pkg_root),
        ],
        f"[dim]building {PROXY_SIDECAR_IMAGE_TAG}…[/]",
    )
    if rc != 0:
        if output:
            sys.stderr.write(output)
            if not output.endswith("\n"):
                sys.stderr.write("\n")
        sys.exit(
            f"agentbox: failed to build {PROXY_SIDECAR_IMAGE_TAG} "
            f"(exit {rc})"
        )
    _step(
        "sidecar",
        f"{PROXY_SIDECAR_IMAGE_TAG} "
        f"[dim](built in {time.monotonic() - t0:.1f}s)[/]",
    )


def _stage_sidecar_files(workdir: Path, ca_path: Path) -> Path:
    """Prepare workdir + CA for the sidecar's UID 4242.

    Two pieces, both required for the sidecar's mitmproxy (UID 4242)
    to read its inputs:

    1. **Workdir perms.** ``tempfile.mkdtemp`` creates the directory
       0o700 owned by the host UID. The sidecar's mitmproxy bind-mounts
       it ro at ``/agentbox/proxy``; without a chmod here the sidecar
       can't even traverse the dir, let alone read credentials.json /
       allowlist.yaml / github.json. We relax to dir 0o755 + files
       0o644. The data inside (surrogate-mapped real PAT, allowlist,
       repo list) is per-session and the workdir lives under /tmp on
       a single-user host -- bounded blast radius.

    2. **CA private key.** ``~/.mitmproxy/mitmproxy-ca.pem`` is the
       CA's *private key*, mode 0o600 owned by the host user. The
       sidecar's mitmproxy in transparent mode needs both cert and
       key to terminate TLS, but UID 4242 can't read 0o600 owned by a
       different UID. We stage a per-session copy under
       ``workdir/mitmproxy-ca/`` with mode 0o644 and bind-mount that
       at ``/home/mitmproxy/.mitmproxy``. Copy lives only as long as
       the workdir (atexit cleanup) -- the host's long-lived
       ``~/.mitmproxy/`` keeps its 0o600 perms intact.

    Returns the staged CA directory so the caller can pass it to
    ``docker run -v``.
    """
    workdir.chmod(0o755)
    for fname in ("credentials.json", "allowlist.yaml", "github.json"):
        path = workdir / fname
        if path.exists():
            path.chmod(0o644)

    src_dir = Path(ca_path).parent
    dst_dir = workdir / "mitmproxy-ca"
    dst_dir.mkdir(mode=0o755, exist_ok=True)
    dst_dir.chmod(0o755)
    for fname in ("mitmproxy-ca.pem", "mitmproxy-ca-cert.pem"):
        src = src_dir / fname
        if not src.exists():
            sys.exit(f"agentbox: missing CA file {src}")
        dst = dst_dir / fname
        shutil.copy(src, dst)
        dst.chmod(0o644)
    return dst_dir


def _start_sidecar(name: str, workdir: Path, ca_path: Path) -> None:
    """Start the proxy sidecar container.

    Mounts the per-session workdir (credentials, allowlist, repos JSON)
    read-only at ``/agentbox/proxy``, and a per-session CA directory
    (staged copy of the host CA, see ``_stage_sidecar_files``)
    read-only at ``/home/mitmproxy/.mitmproxy`` so the sidecar
    uses the same CA the agent already trusts.

    The sidecar boots as root because installing iptables NAT rules
    requires ``CAP_NET_ADMIN``, and there is no way to grant a cap
    to a non-root user under ``--security-opt=no-new-privileges``
    (file capabilities are silently stripped on exec). The
    privileged window is bounded:

    - ``--cap-drop=ALL`` then ``--cap-add`` only ``NET_ADMIN`` (for
      iptables) and ``SETUID``/``SETGID`` (so the entrypoint can
      drop to UID 4242 right after iptables setup -- without these
      caps, root cannot setuid to a non-root UID and the privilege
      drop would silently fail).
    - ``--security-opt=no-new-privileges`` blocks any setuid-binary
      escalation that might survive the cap drop.
    - The DNS sinkhole binds a non-privileged port (5353); the
      entrypoint's iptables redirect UDP/53 -> 5353 so the long-lived
      processes don't need ``CAP_NET_BIND_SERVICE`` either.

    The agent container -- the actual hostile-code boundary -- runs
    as ``--user agentbox`` (UID 1000) with ``--cap-drop=ALL`` and
    zero capabilities; see ``_run_agent``.
    """
    sidecar_ca_dir = _stage_sidecar_files(workdir, ca_path)
    cmd = [
        "docker", "run", "-d", "--rm",
        "--name", name,
        "--cap-drop=ALL",
        "--cap-add=NET_ADMIN",
        "--cap-add=SETUID",
        "--cap-add=SETGID",
        "--security-opt=no-new-privileges",
        "-v", f"{workdir.as_posix()}:/agentbox/proxy:ro",
        "-v", f"{sidecar_ca_dir.as_posix()}:/home/mitmproxy/.mitmproxy:ro",
        PROXY_SIDECAR_IMAGE_TAG,
    ]
    rc = subprocess.call(
        cmd, env=_DOCKER_ENV,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    if rc != 0:
        sys.exit(f"agentbox: failed to start sidecar (exit {rc})")


def _wait_for_sidecar_ready(name: str, timeout: float) -> bool:
    """Poll until the sidecar entrypoint touches its readiness sentinel.

    The entrypoint writes ``/run/agentbox/proxy-ready`` once mitmproxy
    is accepting connections on its transparent listen port. Polled via
    ``docker exec`` rather than a TCP probe since the sidecar's listen
    ports are inside its netns and not published to the host.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rc = subprocess.call(
            ["docker", "exec", name, "test", "-f",
             "/run/agentbox/proxy-ready"],
            env=_DOCKER_ENV,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if rc == 0:
            return True
        # Bail early if the container has already exited.
        rc_state = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", name],
            env=_DOCKER_ENV,
            capture_output=True, text=True, check=False,
        )
        if rc_state.returncode == 0 and rc_state.stdout.strip() == "false":
            return False
        time.sleep(0.2)
    return False


def _stop_sidecar(name: str) -> None:
    """Best-effort sidecar teardown for atexit."""
    subprocess.run(
        ["docker", "stop", "--time", "2", name],
        env=_DOCKER_ENV,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        check=False,
    )


def _dump_sidecar_logs(name: str, log_path: Path) -> None:
    """Write the sidecar's docker logs to ``log_path`` for the failure report."""
    try:
        logs = subprocess.run(
            ["docker", "logs", name],
            env=_DOCKER_ENV,
            capture_output=True, text=True, errors="replace", check=False,
            timeout=5,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return
    log_path.write_text(
        (logs.stdout or "") + (logs.stderr or ""),
        encoding="utf-8", errors="replace",
    )


def _progress_mode_for(mode: str, mode_args: list[str]) -> str | None:
    """Return ``"pi"`` / ``"claude"`` / ``None`` for live-progress dispatch.

    Both trackers require the agent to be running in print mode
    (``-p`` / ``--print``) so stdout is non-interactive and we don't
    fight a TTY for control. Pi additionally requires session
    persistence (``--no-session`` opts out, leaving no file to tail).
    Claude has no such opt-out: when it runs ``-p`` the launcher
    appends ``--output-format stream-json --verbose`` so there's
    always something to parse.
    """
    if not any(a in ("-p", "--print") for a in mode_args):
        return None
    if mode == "pi" and "--no-session" not in mode_args:
        return "pi"
    if mode == "claude":
        return "claude"
    return None


_CLAUDE_MANAGED_SETTINGS_PATH = "/etc/claude-code/managed-settings.json"


def _write_claude_managed_settings(path: Path) -> None:
    """Write a Claude Code managed-settings file that puts claude in auto mode.

    Claude has an ``auto`` permission mode that auto-approves tool calls
    with a model-side safety check (vs. ``bypassPermissions``, which
    skips checks entirely). The agentbox container provides physical
    isolation, but the host cwd is bind-mounted in, so the agent has
    write access to the user's source tree -- ``auto`` keeps a
    semantic guardrail on top of that without requiring per-call
    prompts. We set it via a managed (policy) settings file at a
    system path, separate from ``~/.claude/``, so the host bind-mount
    of the user's own settings is untouched.
    """
    path.write_text(
        json.dumps({
            "permissions": {"defaultMode": "auto"}
        }),
        encoding="utf-8",
    )


def _resolve_git_identity() -> dict[str, str]:
    """Return host git user.name / user.email, omitting unset keys.

    Reads only the host's *global* gitconfig (``git config --global``).
    Per-repo overrides in the user's cwd flow through naturally via
    the cwd bind-mount; lifting them to the container's global level
    would shadow the per-repo intent the user set on the host.
    """
    identity: dict[str, str] = {}
    for key in ("user.name", "user.email"):
        try:
            result = subprocess.run(
                ["git", "config", "--global", key],
                capture_output=True, text=True, timeout=3, check=False,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return identity
        if result.returncode == 0:
            value = result.stdout.strip()
            if value:
                identity[key] = value
    return identity


def _write_git_config(path: Path, identity: dict[str, str]) -> None:
    """Write the per-session gitconfig mounted into the container.

    Two pieces:

    1. ``[safe] directory = *`` -- the bind-mounted host repo at the
       container's cwd surfaces as root-owned (Docker Desktop's
       UID-translation default), but the agent runs as the
       unprivileged ``agentbox`` user. Without this whitelist, every
       git command in the sandbox trips git's ``safe.directory``
       check. ``*`` is appropriate here: the sandbox is single-user,
       every mounted path belongs to the host user who launched it,
       and the cross-user attack scenario the check exists to
       prevent doesn't apply.

    2. ``[user]`` block -- the host's user.name / user.email when
       resolved. Forwarding only this section keeps host-specific
       knobs (credential helpers, ``commit.gpgsign``,
       ``core.autocrlf``) out of the container, where they would
       conflict with the agentbox credential helper or fail outright.
    """
    lines = ["[safe]\n", "\tdirectory = *\n"]
    if identity:
        lines.append("[user]\n")
        if "user.name" in identity:
            lines.append(f"\tname = {identity['user.name']}\n")
        if "user.email" in identity:
            lines.append(f"\temail = {identity['user.email']}\n")
    path.write_text("".join(lines), encoding="utf-8")


def _ensure_claude_workspace_trusted(
    claude_json: Path, container_cwd: str,
) -> None:
    """Mark the container's cwd as trusted in the host's ``~/.claude.json``.

    Claude Code shows a "Is this a project you trust?" dialog the first
    time it sees a workspace path, recording acceptance under
    ``projects.<cwd>.hasTrustDialogAccepted`` in ``~/.claude.json``. The
    key is per-project state -- there is no managed-settings or env-var
    bypass, and the dialog deliberately runs before repo-controlled
    settings load (security advisory ``GHSA-mmgp-wc2j-qcv7``).

    The container cwd mirrors the host cwd under ``/agentbox/...`` (see
    ``_host_to_container_path``), so each project gets its own trust
    entry. Entries are inert outside the container -- no host project
    has cwd ``/agentbox/<host-path>``.

    Writes are atomic and skipped when the value is already set, so
    this is a no-op on subsequent launches of the same project. If the
    file doesn't exist, it's created with just this entry; the
    bind-mount in ``_run_agent`` is conditional on the file existing,
    so creating it here is also what makes the mount happen on the
    very first run.
    """
    try:
        data = json.loads(claude_json.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            data = {}
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    projects = data.setdefault("projects", {})
    if not isinstance(projects, dict):
        projects = {}
        data["projects"] = projects
    entry = projects.setdefault(container_cwd, {})
    if not isinstance(entry, dict):
        entry = {}
        projects[container_cwd] = entry
    if entry.get("hasTrustDialogAccepted") is True:
        return

    entry["hasTrustDialogAccepted"] = True
    tmp = claude_json.with_suffix(claude_json.suffix + ".agentbox-tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    os.replace(tmp, claude_json)


_CONTAINER_MOUNT_ROOT = "/agentbox"


def _host_to_container_path(host_path: Path) -> str:
    """Mirror a host filesystem path under ``/agentbox`` inside the container.

    Each project gets its own container path so per-cwd state (pi
    session dirs, Claude project entries, ...) doesn't collide across
    projects when launched through agentbox.

    Examples:
        ``C:\\code\\agentbox`` -> ``/agentbox/c/code/agentbox``
        ``/home/user/proj``    -> ``/agentbox/home/user/proj``

    The drive letter is lowercased; the rest of the path keeps its
    original case so Linux-side tools see the same names the host did.
    """
    posix = host_path.as_posix()
    if len(posix) >= 2 and posix[1] == ":":
        drive = posix[0].lower()
        rest = posix[2:].lstrip("/")
        suffix = f"{drive}/{rest}" if rest else drive
    else:
        suffix = posix.lstrip("/")
    if not suffix:
        return _CONTAINER_MOUNT_ROOT
    return f"{_CONTAINER_MOUNT_ROOT}/{suffix}"


# Container paths agentbox already bind-mounts; an override that lands
# on or under any of these would either be hidden or overwrite our own
# state, so refuse it up front.
_RESERVED_CONTAINER_PATHS = (
    "/home/agentbox",
    "/etc/claude-code",
    "/usr/local/share/ca-certificates",
)


def _validate_container_workdir(raw: str) -> str:
    """Validate a user-supplied container workdir override.

    Returns the normalized value (no trailing slash). Exits with a
    helpful message on any of: not a string, not absolute, root,
    or landing under a path agentbox already mounts internally.
    """
    if not isinstance(raw, str) or not raw:
        sys.exit(
            "agentbox: container workdir override must be a non-empty string"
        )
    if not raw.startswith("/"):
        sys.exit(
            f"agentbox: container workdir override must be an absolute "
            f"POSIX path (start with '/'), got {raw!r}"
        )
    normalized = raw.rstrip("/") or "/"
    if normalized == "/":
        sys.exit(
            "agentbox: container workdir override cannot be '/' "
            "(would shadow the entire container filesystem)"
        )
    for reserved in _RESERVED_CONTAINER_PATHS:
        if normalized == reserved or normalized.startswith(reserved + "/"):
            sys.exit(
                f"agentbox: container workdir {normalized!r} would "
                f"conflict with the internal mount under {reserved!r}"
            )
    return normalized


def _run_agent(
    mode: str,
    port: int,
    surrogate: str,
    real_token: str,
    ca_path: Path,
    mode_args: list[str],
    *,
    image_tag: str,
    workdir: Path,
    container_workdir: str | None = None,
    network_mode: str = DEFAULT_NETWORK_MODE,
    sidecar_name: str | None = None,
) -> int:
    cfg = MODES[mode]
    cwd = Path.cwd().resolve()
    container_cwd = container_workdir or _host_to_container_path(cwd)
    home = Path.home()
    pi_dir = home / ".pi"
    if mode == "pi":
        pi_dir.mkdir(exist_ok=True)
    claude_dir = home / ".claude"
    claude_json = home / ".claude.json"

    progress = _progress_mode_for(mode, mode_args)
    # Snapshot existing session files so the pi watcher can pick out
    # the new one pi creates. Only relevant for ``progress == "pi"``.
    # pi names the session subdir from its cwd by replacing ``/`` with
    # ``--``, so e.g. ``/agentbox/c/code/agentbox`` -> ``--agentbox--c--code--agentbox``.
    session_dir = pi_dir / "agent" / "sessions" / container_cwd.replace("/", "--")
    session_snapshot: set[str] = set()
    if progress == "pi":
        session_dir.mkdir(parents=True, exist_ok=True)
        session_snapshot = {
            p.name for p in session_dir.iterdir() if p.suffix == ".jsonl"
        }

    proxy_url = f"http://host.docker.internal:{port}"
    container_ca = "/usr/local/share/ca-certificates/agentbox-ca.crt"
    container_name = f"agentbox-{os.getpid()}"

    cmd: list[str] = [
        "docker", "run", "--rm",
        "--name", container_name,
        "--entrypoint", cfg["entrypoint"],
        # Hardening: drop all Linux capabilities, forbid privilege
        # escalation via setuid binaries, and run as the non-root `agent`
        # user (uid 1000) baked into agentbox-base. Project Dockerfile.agentbox
        # builds still run as root since we override the user only at
        # `docker run` time, not in the image.
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user", "agentbox",
    ]
    if progress is not None:
        # Don't pass -it when we're rendering progress: docker would
        # put our terminal in raw mode, so ^C becomes a literal 0x03
        # byte forwarded to the container instead of a SIGINT to our
        # Python parent -- ``_on_interrupt`` would never fire and the
        # user couldn't stop the agent without ``docker kill`` from
        # another shell. Both pi -p and claude -p are non-interactive
        # so this is fine.
        pass
    elif sys.stdin.isatty() and sys.stdout.isatty():
        cmd.append("-it")

    cmd += [
        "-v", f"{cwd.as_posix()}:{container_cwd}",
        "-w", container_cwd,
        "-v", f"{Path(ca_path).as_posix()}:{container_ca}:ro",
        "-e", f"NODE_EXTRA_CA_CERTS={container_ca}",
        "-e", f"GIT_SSL_CAINFO={container_ca}",
        "-e", f"SSL_CERT_FILE={container_ca}",
        "-e", f"REQUESTS_CA_BUNDLE={container_ca}",
        "-e", f"CURL_CA_BUNDLE={container_ca}",
    ]
    # Forward terminal capability env vars so color rendering inside the
    # container matches the host. Without these, docker -it defaults TERM
    # to plain "xterm" and drops COLORTERM, so 24-bit-color UIs (claude,
    # rich-based tools) fall back to a 16-color palette.
    for var in ("TERM", "COLORTERM", "LANG", "LC_ALL"):
        val = os.environ.get(var)
        if val:
            cmd += ["-e", f"{var}={val}"]
    if mode == "pi":
        cmd += ["-v", f"{pi_dir.as_posix()}:/home/agentbox/.pi"]

    git_identity = _resolve_git_identity()
    git_config_path = workdir / "gitconfig"
    _write_git_config(git_config_path, git_identity)
    cmd += [
        "-v",
        f"{git_config_path.as_posix()}:/home/agentbox/.gitconfig:ro",
    ]

    if network_mode == "permissive":
        # HTTPS_PROXY-aware tools (gh, git, curl, npm, requests, the
        # Anthropic SDK, ...) all route through the host-subprocess
        # proxy. Tools that ignore HTTPS_PROXY bypass freely -- this
        # is the documented permissive-mode contract.
        cmd += [
            "-e", f"HTTPS_PROXY={proxy_url}",
            "-e", f"HTTP_PROXY={proxy_url}",
            "-e", "NO_PROXY=localhost,127.0.0.1",
        ]
    else:  # transparent-shared
        # Share the sidecar's network namespace. iptables REDIRECT in
        # the sidecar catches every TCP/80+443 packet leaving the
        # agent; the DNS sinkhole catches UDP/53. No HTTPS_PROXY env
        # -- tools think they're talking directly to the upstream and
        # the kernel quietly rewrites the destination.
        if sidecar_name is None:
            sys.exit(
                "agentbox: internal error -- transparent-shared without "
                "sidecar_name"
            )
        cmd += ["--network", f"container:{sidecar_name}"]

    if mode == "claude":
        # Mark the container's cwd as already-trusted so claude doesn't
        # show the "Is this a project you trust?" prompt on first run.
        # Writes (or creates) the host's ~/.claude.json; the entry is
        # inert outside the container.
        _ensure_claude_workspace_trusted(claude_json, container_cwd)
        if claude_dir.exists():
            cmd += ["-v", f"{claude_dir.as_posix()}:/home/agentbox/.claude"]
        if claude_json.exists():
            # Claude Code stores credentials/login state in ~/.claude.json,
            # not under ~/.claude/. Without this mount the container's claude
            # is logged out and falls back to OAuth via platform.claude.com.
            cmd += ["-v", f"{claude_json.as_posix()}:/home/agentbox/.claude.json"]
        # Put claude into auto permission mode (auto-approve with a
        # model-side safety check) via a managed settings file. Lives
        # at a system path that's independent of ~/.claude/, so the
        # host's user settings (mounted above) are untouched.
        managed = workdir / "claude-managed-settings.json"
        _write_claude_managed_settings(managed)
        cmd += [
            "-v",
            f"{managed.as_posix()}:{_CLAUDE_MANAGED_SETTINGS_PATH}:ro",
        ]

    if real_token:
        cmd += ["-e", f"GH_TOKEN={surrogate}"]

    if network_mode == "permissive" and not _is_docker_desktop():
        cmd += ["--add-host=host.docker.internal:host-gateway"]

    cmd.append(image_tag)
    cmd.extend(cfg["default_args"])
    cmd.extend(mode_args)
    if progress == "claude":
        # Claude needs stream-json on stdout for the parser to have
        # anything to read. ``--verbose`` makes claude emit thinking
        # / tool_use blocks on every assistant turn, which is what
        # we render in the live view.
        cmd.extend(["--output-format", "stream-json", "--verbose"])

    _step("workdir", f"{_short(cwd)} → {container_cwd}")
    credentials = [c for c in (
        "~/.pi" if mode == "pi" else None,
        "~/.claude" if mode == "claude" and claude_dir.exists() else None,
        "~/.claude.json" if mode == "claude" and claude_json.exists() else None,
    ) if c]
    if credentials:
        _step("credentials", ", ".join(credentials))
    if git_identity:
        parts: list[str] = []
        if "user.name" in git_identity:
            parts.append(git_identity["user.name"])
        if "user.email" in git_identity:
            parts.append(f"<{git_identity['user.email']}>")
        _step("git", " ".join(parts))
    launch_cmd = shlex.join([cfg["entrypoint"], *cfg["default_args"], *mode_args])
    _console.print()
    _console.print(f"[bold cyan]$[/] {launch_cmd}")
    _console.print()  # blank line before agent output

    # When claude progress is on we capture stdout to parse the
    # stream-json events; when pi progress is on or interactive
    # mode we let stdout flow straight through.
    popen_stdout = subprocess.PIPE if progress == "claude" else None
    proc = subprocess.Popen(
        cmd, env=_DOCKER_ENV, stdout=popen_stdout,
        text=(progress == "claude"),
        encoding="utf-8" if progress == "claude" else None,
        errors="replace" if progress == "claude" else None,
        bufsize=1 if progress == "claude" else -1,
    )
    interrupts = 0

    watcher: threading.Thread | None = None
    watcher_stop: threading.Event | None = None
    claude_result: list[str] = []  # populated by the claude watcher
    if progress == "pi":
        if _DEBUG:
            _debug(
                _console,
                f"cli: progress mode pi; session_dir={session_dir}, "
                f"pre-existing={len(session_snapshot)} jsonl file(s), "
                f"docker pid={proc.pid}",
            )
        watcher_stop = threading.Event()
        watcher = threading.Thread(
            target=tail_session_file,
            args=(session_dir, session_snapshot, proc, _console, watcher_stop),
            daemon=True,
        )
        watcher.start()
    elif progress == "claude":
        if _DEBUG:
            _debug(
                _console,
                f"cli: progress mode claude; docker pid={proc.pid}",
            )
        watcher_stop = threading.Event()

        def _run_claude_watcher() -> None:
            claude_result.append(
                run_claude_stream(proc, _console, watcher_stop)
            )

        watcher = threading.Thread(
            target=_run_claude_watcher, daemon=True,
        )
        watcher.start()

    def _on_interrupt() -> bool:
        """Handle ^C; return True if caller should also force-exit."""
        nonlocal interrupts
        interrupts += 1
        if interrupts == 1:
            _console.print(
                "\n[yellow]agentbox: stopping container "
                "(Ctrl-C again to force-kill)[/]"
            )
            # Some agents (e.g. pi -p) ignore TTY ^C; ask docker to send
            # SIGTERM directly to the container's PID 1.
            subprocess.Popen(
                ["docker", "stop", "--time", "5", container_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env=_DOCKER_ENV,
            )
            return False
        _console.print("[red]agentbox: force-killing container[/]")
        subprocess.run(
            ["docker", "kill", container_name],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False, env=_DOCKER_ENV,
        )
        proc.terminate()
        return True

    try:
        while True:
            try:
                # Poll instead of blocking on proc.wait(). On Windows the
                # WaitForSingleObject inside wait() can defer signal handlers
                # until it returns, so ^C wouldn't interrupt promptly.
                if proc.poll() is not None:
                    rc = proc.returncode
                    break
                time.sleep(0.2)
            except KeyboardInterrupt:
                if _on_interrupt():
                    rc = 130
                    break
    finally:
        if watcher_stop is not None:
            watcher_stop.set()
        if watcher is not None:
            # Claude's parser may still be flushing; give it longer
            # than the pi tailer needs.
            join_timeout = 10 if progress == "claude" else 2
            watcher.join(timeout=join_timeout)
    if progress == "claude" and claude_result:
        # Mirror pi's pipe-friendly behaviour: live progress went to
        # stderr (the rich console), the final answer goes to stdout
        # so ``agentbox claude -- -p "..." | jq`` works.
        sys.stdout.write(claude_result[0])
        if not claude_result[0].endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
    return rc


def _is_docker_desktop() -> bool:
    return sys.platform in ("win32", "darwin")


def _terminate(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


if __name__ == "__main__":
    main()
