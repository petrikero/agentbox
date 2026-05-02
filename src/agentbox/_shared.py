"""Constants and small helpers shared between ``cli`` and ``doctor``.

This module exists so the launcher (``cli``) and the inspector
(``doctor``) can both import the same primitives without forming
a circular import. Anything launcher-specific (image building,
proxy lifecycle, agent invocation) stays in ``cli``; anything
inspector-specific (validators, the report renderer) stays in
``doctor``.
"""

from __future__ import annotations

import os
import subprocess


# ---------------------------------------------------------------------------
# Image / config constants
# ---------------------------------------------------------------------------

# agentbox-base bundles the agent runtime (gh, pi, claude, the credential
# helper, mitmproxy CA trust). Project-specific toolchains layer on top
# via a project-side ``Dockerfile.agentbox``.
#
# While agentbox is local-only (no published registry), we use the tag
# ``agentbox-base:local`` instead of a numbered version: userland
# Dockerfiles say ``FROM agentbox-base:local`` and never need editing
# when the base contract changes. The launcher re-runs ``docker build``
# on every invocation (layer cache keeps no-op rebuilds near-instant);
# pass ``--no-cache`` for a clean rebuild. When agentbox eventually
# publishes registry-hosted versions, this becomes a semver pin and
# userland Dockerfiles bump explicitly.
# ``:local`` is preferred over ``:latest`` because Docker treats
# ``:latest`` specially (auto-pulls from registries) -- ``:local`` makes
# it obvious that this image is built locally and never pulled.
BASE_IMAGE_VERSION = "local"
BASE_IMAGE_TAG = f"agentbox-base:{BASE_IMAGE_VERSION}"
PROJECT_IMAGE_PREFIX = "agentbox-project"
PROJECT_DOCKERFILE_NAME = "Dockerfile.agentbox"
CONFIG_FILE_NAME = "agentbox.config.yaml"

# Sidecar image for the transparent-shared network mode -- a small
# Linux image with iptables, mitmproxy, and the agentbox.proxy package.
# Built lazily on launch only when --network transparent-shared is in
# use; permissive mode never touches it.
PROXY_SIDECAR_IMAGE_TAG = f"agentbox-proxy-sidecar:{BASE_IMAGE_VERSION}"

# Network-plumbing modes accepted by --network and the `network:` config
# key. `permissive` (default) keeps today's behaviour: host-subprocess
# proxy on HTTPS_PROXY env var, no enforcement at the proxy. The
# `transparent-shared` mode runs the proxy as a sidecar container in a
# shared network namespace, with iptables redirecting all TCP/80+443
# and a UDP/53 sinkhole, so non-HTTPS_PROXY-aware tools can't bypass.
# `transparent-isolated` is a Linux-only macvlan/CNI variant reserved
# for future work; selecting it today exits with a friendly error.
NETWORK_MODES: tuple[str, ...] = (
    "permissive",
    "transparent-shared",
    "transparent-isolated",
)
DEFAULT_NETWORK_MODE = "permissive"

# GitHub access modes accepted by --github-mode and the `github.mode`
# config key. `auto` (default) resolves to one of the other three based
# on token presence and `github.repos:` content:
#
#   - no token             -> none           (public reads only)
#   - token, repos empty   -> unrestricted   (full PAT capability)
#   - token, repos non-empty -> scoped       (writes fenced to listed repos)
#
# Explicit `mode:` always wins. `mode: scoped` with empty `repos:` is
# valid -- reads-everywhere, writes-nowhere.
GITHUB_MODES: tuple[str, ...] = (
    "none",
    "unrestricted",
    "scoped",
    "auto",
)
DEFAULT_GITHUB_MODE = "auto"


# Windows + Git Bash (MSYS) rewrites Unix-style path arguments to native
# binaries: ``-v /agentbox:/agentbox`` becomes ``-v C:/Program Files/Git/agentbox:...``,
# breaking every docker mount spec. ``MSYS_NO_PATHCONV=1`` disables that
# rewrite for the docker subprocess we're about to spawn. No-op on
# macOS/Linux. Pass as ``env=_DOCKER_ENV`` on every docker call.
_DOCKER_ENV: dict[str, str] = {**os.environ, "MSYS_NO_PATHCONV": "1"}


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def _safe_image_tag(name: str) -> str:
    """Sanitise ``name`` for use as a Docker image tag suffix.

    Docker tags accept ``[a-zA-Z0-9_.-]`` and may not start with ``.``
    or ``-``. Lowercases, replaces other characters with ``-``, strips
    leading dots/hyphens, and falls back to ``"default"`` for empty
    results so the build never tries to tag with an invalid string.
    """
    safe = "".join(
        c if c.isalnum() or c in ("_", "-", ".") else "-"
        for c in name.lower()
    ).lstrip(".-")
    return safe or "default"


def _resolve_real_token() -> tuple[str, str]:
    """Return ``(token, source)`` for the resolved GitHub token.

    ``source`` is a short human-readable label for startup logging.
    Returns ``("", "")`` if no credential is available. Resolution
    order: ``GH_TOKEN`` env var, then ``GITHUB_TOKEN`` env var, then
    ``gh auth token`` (when ``gh`` is installed and logged in).
    """
    if token := os.environ.get("GH_TOKEN"):
        return token, "GH_TOKEN env var"
    if token := os.environ.get("GITHUB_TOKEN"):
        return token, "GITHUB_TOKEN env var"
    try:
        result = subprocess.run(
            ["gh", "auth", "token"],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return "", ""
    if result.returncode != 0:
        return "", ""
    token = result.stdout.strip()
    return (token, "gh auth token") if token else ("", "")
