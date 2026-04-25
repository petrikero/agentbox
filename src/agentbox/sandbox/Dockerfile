# agentbox-base image. Project-specific toolchains layer on top via a
# project-side `Dockerfile.agentbox` that does `FROM agentbox-base:local`
# and adds whatever it needs (e.g. .NET, Go, Java, Rust). What this
# image guarantees -- the contract project Dockerfiles can rely on:
#
#   - bash is the default shell; CA certs at /usr/local/share/ca-certificates/
#   - `gh` on PATH (uses GH_TOKEN=<surrogate> via the agentbox proxy)
#   - `pi` and `claude` on PATH
#   - `git-credential-agentbox` on PATH; system gitconfig already wires it up
#     for github.com / gist.github.com so `git push` over HTTPS works
#   - WORKDIR /work; image contains a non-root `agentbox` user (uid 1000)
#     and the launcher runs the container as `agentbox` via `docker run --user`.
#     Build-time stays root so project Dockerfile.agentbox files can install
#     packages without ceremony.
#
# While agentbox is local-only the tag is `:local`. The launcher
# re-runs `docker build` on every invocation (layer cache makes a
# no-op rebuild near-instant), so contract changes are picked up
# automatically; pass `--no-cache` for a clean rebuild. Numbered
# versions return when there's a published registry image to pin
# against.
FROM node:24-bookworm-slim AS node
FROM python:3.14-slim-bookworm

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s /usr/local/lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates git curl wget less \
      ripgrep fd-find jq \
      openssh-client gnupg \
      sqlite3 tree unzip xz-utils zstd \
      procps \
      bash-completion nano \
 && ln -s /usr/bin/fdfind /usr/local/bin/fd \
 && rm -rf /var/lib/apt/lists/*

ARG TARGETARCH=amd64
RUN curl -fsSL "https://github.com/mikefarah/yq/releases/latest/download/yq_linux_${TARGETARCH}" -o /usr/local/bin/yq \
 && chmod +x /usr/local/bin/yq

# gh CLI: picks up GH_TOKEN automatically, so the agentbox surrogate flows
# straight through to the proxy with no extra wiring.
RUN GH_VERSION=$(curl -fsSL https://api.github.com/repos/cli/cli/releases/latest | jq -r .tag_name | sed 's/^v//') \
 && curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VERSION}/gh_${GH_VERSION}_linux_${TARGETARCH}.tar.gz" \
    | tar -xz -C /tmp \
 && mv "/tmp/gh_${GH_VERSION}_linux_${TARGETARCH}/bin/gh" /usr/local/bin/gh \
 && rm -rf "/tmp/gh_${GH_VERSION}_linux_${TARGETARCH}"

RUN npm install -g \
      @mariozechner/pi-coding-agent@latest \
      @anthropic-ai/claude-code@latest

# Git credential helper: emit x-access-token:$GH_TOKEN so https git
# operations against GitHub authenticate via the agentbox surrogate. The
# proxy decodes Basic Auth and swaps the surrogate for the real PAT.
# Scoped to github.com/gist.github.com to avoid leaking the surrogate
# elsewhere. With this helper in place, plain `git clone
# https://github.com/owner/repo.git` works -- no URL-embedded creds
# needed, no token persisted to .git/config.
RUN printf '#!/bin/sh\n[ "$1" = get ] || exit 0\nprintf "username=x-access-token\\npassword=%%s\\n" "$GH_TOKEN"\n' \
      > /usr/local/bin/git-credential-agentbox \
 && chmod +x /usr/local/bin/git-credential-agentbox \
 && git config --system credential.https://github.com.helper agentbox \
 && git config --system credential.https://gist.github.com.helper agentbox

# Non-root runtime identity. The base image still builds as root so
# project-side Dockerfile.agentbox can `apt-get install` etc. without
# friction; the launcher switches to `agentbox` at `docker run` time via
# `--user agentbox`. Pre-create the mount points so a Linux-native bind
# over /home/agentbox/.pi etc. doesn't end up root-owned.
RUN groupadd --gid 1000 agentbox \
 && useradd  --uid 1000 --gid 1000 --create-home --shell /bin/bash agentbox \
 && install -d -o agentbox -g agentbox \
      /home/agentbox/.pi /home/agentbox/.claude /work

COPY --chown=agentbox:agentbox bashrc /home/agentbox/.bashrc

WORKDIR /work
