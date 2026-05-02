# agentbox internals

This document covers implementation structure. The README is intentionally focused on usage.

## Launch Flow

`agentbox` is a Python launcher around Docker plus a mitmproxy-based credential-swap proxy.

For each agent run, the launcher:

1. Builds `agentbox-base:local`, then builds `agentbox-project:<cwd>` if `Dockerfile.agentbox` exists.
2. Resolves a host GitHub token from `GH_TOKEN`, `GITHUB_TOKEN`, or `gh auth token`, in that order.
3. Mints a per-session surrogate token and writes proxy state into a temporary directory.
4. Copies the resolved allowlist into the same temporary directory.
5. Ensures the mitmproxy CA exists, then starts the proxy on a loopback port.
6. Starts `docker run` with the current directory mirrored under `/agentbox/` (e.g. `C:\code\agentbox` -> `/agentbox/c/code/agentbox`), `GH_TOKEN` set to the surrogate, proxy env vars configured, and the mitmproxy CA exposed to common toolchains.
7. Stops the proxy and removes temporary files on exit.

## Runtime Pieces

The base image contains the agent runtime: `bash`, `git`, `gh`, `pi`, `claude`, the GitHub credential helper, common CLI tools, and CA plumbing. A project can add tools with `Dockerfile.agentbox`, layered on top of `agentbox-base:local`.

Every invocation rebuilds the base image and, when present, the project image. Docker layer cache makes no-op rebuilds cheap; `--no-cache` bypasses that cache for both tiers.

The container runs as the `agentbox` user with dropped Linux capabilities and `no-new-privileges`. The host working tree is mounted at the mirrored path under `/agentbox/` (so per-project state in tools like Claude Code stays separated by host cwd). Agent state is mounted from the host when present:

- `~/.pi` -> `/home/agentbox/.pi`
- `~/.claude` -> `/home/agentbox/.claude`
- `~/.claude.json` -> `/home/agentbox/.claude.json`

Claude Code runs with a managed settings file mounted at `/etc/claude-code/managed-settings.json` that sets `permissions.defaultMode` to `auto` (auto-approve with a model-side safety check). This is non-interactive and leaves the user's host settings untouched.

## Credential Proxy

The container sees a surrogate GitHub token, not the real host token. Surrogates use the `ghp_AGENTBOX_SURROGATE_...` shape so prefix-validating tools accept them and logs remain easy to inspect. The proxy receives both values in per-session state, swaps surrogate credentials to the real token for GitHub traffic, and strips foreign credentials on scoped GitHub hosts.

The proxy handles Bearer auth and Base64-decoded Basic auth, which covers both GitHub API calls and git HTTPS credential flows. The real GitHub PAT is held by the proxy for the duration of the session; GitHub App based short-lived installation tokens are future work.

The proxy runs through `python -m agentbox.proxy`, backed by mitmproxy and the `agentbox.proxy.filter` addon. GitHub GraphQL write scope is resolved by the launcher into `repos.json`; the proxy checks writes against those repo IDs before forwarding.

The current networking mode is permissive: the launcher sets `HTTP_PROXY` and `HTTPS_PROXY`, so only tools that honor those env vars are routed through the proxy. More complete network plumbing is scaffolded in the codebase but should be treated as upcoming.

## CA Handling

mitmproxy requires the container to trust its CA. The launcher ensures `~/.mitmproxy/mitmproxy-ca-cert.pem` exists, bind-mounts it into the container, and sets tool-specific CA environment variables such as `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and `CURL_CA_BUNDLE`.

Tools that use only the system CA bundle can need project-image setup, such as copying the mounted CA into the system trust store and running `update-ca-certificates`.

## Progress Rendering

For `pi` runs with sessions enabled, the launcher watches the new JSONL file under `~/.pi/agent/sessions/` and renders tool progress on stderr. The final answer remains on stdout.

Claude progress uses stream parsing in `agentbox.progress.claude` when Claude is run in non-interactive mode.

## Directory Layout

```text
agentbox/
|-- README.md
|-- pyproject.toml
|-- docs/
|   |-- design.md
|   \-- internals.md
|-- tests/
|   |-- test_cli_config.py
|   |-- test_cli_image.py
|   |-- test_dangerous_operations.py
|   |-- test_doctor.py
|   |-- test_filter.py
|   |-- test_graphql_operations.py
|   |-- test_graphql_scope.py
|   |-- test_handlers.py
|   |-- test_network_mode.py
|   \-- test_node_id.py
\-- src/agentbox/
    |-- _shared.py
    |-- cli.py
    |-- doctor.py
    |-- progress/
    |   |-- claude.py
    |   |-- pi.py
    |   \-- _render.py
    |-- sandbox/
    |   |-- Dockerfile
    |   |-- bashrc
    |   \-- proxy/
    |       |-- Dockerfile
    |       |-- dns.py
    |       \-- entrypoint.py
    \-- proxy/
        |-- __main__.py
        |-- dangerous_operations.py
        |-- filter.py
        |-- graphql_operations.py
        |-- graphql_scope.py
        |-- handlers.py
        |-- node_id.py
        \-- allowlist.yaml
```

## Main Modules

`src/agentbox/cli.py` owns argument parsing, config loading, image builds, proxy lifecycle, and `docker run`.

`src/agentbox/doctor.py` is the read-only configuration inspector used by `agentbox doctor`.

`src/agentbox/proxy/` contains the mitmproxy entry point, credential handlers, GitHub GraphQL operation checks, repo-scope checks, and dangerous-operation warnings.

`src/agentbox/progress/` contains renderers for live agent progress.

`src/agentbox/sandbox/` contains Docker build inputs for the base agent image and the upcoming proxy-sidecar networking path.

## Development Commands

```sh
uv sync
uv run ruff check
uv run pyright
uv run python -m unittest discover tests
```

`pyproject.toml` owns the `ruff` and `pyright` configuration.

## Implementation Limitations

- The current networking path depends on proxy environment variables; raw TCP, SSH, DNS, and tools that ignore those variables can bypass it.
- Agent OAuth/session credentials from `~/.pi`, `~/.claude`, and `~/.claude.json` are mounted directly into the container.
- GraphQL write scoping is per repo, not per PR, issue, or branch.
- git smart-HTTP push bodies are not parsed, so branch protection and push restrictions should be enforced with GitHub rulesets.
