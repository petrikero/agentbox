# agentbox

> ⚠️ **Experimental:** This project is experimental and under active development. Use with caution. The security model has not been independently audited, interfaces may change without notice, and the limitations listed below (notably permissive networking and unisolated agent credentials) mean you should not rely on it for protection against untrusted code or prompts in production settings.

Run AI coding agents like [pi](https://www.npmjs.com/package/@mariozechner/pi-coding-agent) and [Claude Code](https://www.npmjs.com/package/@anthropic-ai/claude-code) in a Docker sandbox while keeping your host GitHub token out of the agent container.

The security model draws from the [Airut project](https://github.com/airutorg/airut).

```sh
agentbox pi "Initial prompt"
agentbox claude
agentbox shell
```

## Install

Requirements: Docker, Python 3.13+, and one of `uv`, `pipx`, or `pip`.

```sh
uv tool install .
# or: pipx install .
# or: pip install .
```

This installs the `agentbox` command on your machine.

## Run

```sh
agentbox # same as: agentbox pi
agentbox pi "fix the failing test"
agentbox claude -- -p "explain this repo"
agentbox shell
agentbox doctor
agentbox --no-cache pi "start from a clean sandbox image"
```

Use `--` before agent arguments that begin with a dash, as in the Claude example above.

Modes:

| Mode     | Runs     | Notes                                                                 |
|----------|----------|-----------------------------------------------------------------------|
| `pi`     | `pi`     | Default mode.                                                         |
| `claude` | `claude` | Runs Claude Code in `auto` permission mode.                           |
| `shell`  | `bash`   | Opens an interactive shell in the sandbox.                            |
| `doctor` | none     | Checks configuration and prerequisites without launching a container.  |

Your current directory is available inside the sandbox. Supported agent login and session state persists across runs.

## GitHub Access

agentbox can use your host GitHub login or token without exposing the real token to the agent container. If no GitHub credential is available, public reads may still work, but private repo access and authenticated writes will fail.

Authenticated GitHub writes are blocked unless you scope them to repos:

```sh
agentbox --repo OWNER/NAME pi "open a PR"
```

`--repo` is repeatable. You can also put repo scopes in `agentbox.config.yaml`:

```yaml
github:
  repos:
    - my-org/my-repo
```

CLI `--repo` values are additive with `github.repos`.

## Custom Toolchain

Place a `Dockerfile.agentbox` in the directory where you run `agentbox` to add project-specific tools:

```dockerfile
FROM agentbox-base:local

RUN apt-get update \
 && apt-get install -y --no-install-recommends make \
 && rm -rf /var/lib/apt/lists/*
```

Without `Dockerfile.agentbox`, agentbox runs the default image directly. It includes `bash`, `git`, `gh`, `rg`, `fd`, `jq`, `yq`, `sqlite3`, `pi`, and `claude`.

## Networking

Networking is permissive today. Treat agentbox as credential isolation, not complete network isolation. Stronger network isolation modes are still in progress.

## Doctor

```sh
agentbox doctor
```

`doctor` checks your local configuration, project image setup, repo scopes, and system prerequisites. It does not build images or launch an agent.

## Current Limitations

- Networking is currently permissive; do not rely on it to block outbound traffic.
- Agent OAuth/session credentials are not isolated yet in this version.
- GitHub write scoping is per repo today, not per PR, issue, or branch.
- Use GitHub rulesets or branch protection for protected branches.
- Some package managers may need extra setup in `Dockerfile.agentbox` for HTTPS trust.

More documentation: [internals](docs/internals.md), [threat model and design notes](docs/design.md).
