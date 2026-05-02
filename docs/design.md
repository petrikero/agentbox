# agentbox — design notes

`agentbox` is a Python launcher that runs an AI coding agent inside a Docker sandbox with a credential-isolating proxy in front of GitHub. This doc captures the threat model, the option space we walked through, and why agentbox is built the way it is.

## Threat model

The container runs an LLM agent. Assume the agent is hostile in the prompt-injection sense: any string it sees (web fetch result, dependency README, issue body, tool output) could contain instructions to exfiltrate credentials or push malicious changes. Anything credential-shaped that lands inside the container should be assumed exfiltratable.

Consequences:

- "Just put a PAT in the env" is fine only if the PAT's blast radius is acceptable.
- Read access has confidentiality risk (private repo contents leaking) but no integrity risk.
- Write access is the dangerous surface — needs scoping that the agent can't bypass.

## Constraints that drove the design

Three constraints, accumulated over the course of the design conversation, narrowed the option space sharply:

1. **No real credentials inside the agent container.** Anything credential-shaped in the container is assumed exfiltratable. Long-lived tokens in env are a non-starter.
2. **Cross-agent compatibility.** The same sandbox should host pi, Claude Code, Codex, and whatever comes next. Agent-specific enforcement (pi tools, MCP servers, Claude Code hooks, Codex policies) doesn't generalize and would need to be reimplemented per-agent.
3. **Read broadly, write narrowly.** Reads (PRs, issues, history, clones) should be frictionless. Writes (push, comment, create PR) should be scopeable per-repo and ideally per-branch / per-PR.

The combination of (1) and (2) eliminates wrapper-style enforcement (push gates, host-side daemons reached only via a special tool registered in the agent). The only enforcement layer that satisfies both is the **network**: every agent eventually hits HTTPS to talk to GitHub, regardless of its tool model. (3) then dictates that the network enforcement be richer than IP allowlisting — it needs host + path + method visibility, and eventually GraphQL operation scoping.

## What surfaces need scoping

Two distinct surfaces, with very different scoping mechanisms:

1. **Git protocol** (push/pull/clone over HTTPS). Branch-level scoping is feasible.
2. **GitHub API** (PRs, issues, reviews, comments, releases). Per-PR or per-label scoping is not natively expressible at the credential level; needs proxy-level enforcement.

## Scoping primitives, by enforcement layer

### GitHub-native (server enforces, declarative)

| Primitive | What it scopes | What it cannot scope |
|---|---|---|
| Fine-grained PAT | Per-repo + per-permission (`contents: read`, `issues: write`, …) | Specific branches, PR numbers, labels |
| Repository ruleset | Branch/tag refs by fnmatch pattern + actor bypass list | API surfaces other than push |
| GitHub App + installation token | Repo + permission at install time, plus per-token narrowing via `permissions` and `repositories` fields in the access-token request | Specific PR numbers, labels |
| Required PR review + CODEOWNERS | Merge gating on protected branches | Anything pre-merge |

A repository ruleset targeting `main` with "Restrict pushes" and a bypass list excluding the agent's actor means GitHub itself rejects pushes to `main` from the agent — no proxy required. As of Sept 2025, rulesets also support an *exempt bypass* type for trusted automation that silently skips enforcement.

What GitHub cannot enforce natively:

- Per-PR-number scoping ("only PR #42")
- Per-label scoping ("only PRs with label `agent-allowed`")
- Fine distinctions like "issues yes, PRs no" beyond the coarse permission flags

Those need a proxy.

### Network proxy (you enforce, in front of the agent)

- Host-, path-, method-, and (with body inspection) operation-level allowlist.
- Surrogate-credential swap: container holds a fake; proxy injects the real one only on allowed requests.
- Per-PR scoping via REST URL patterns (`/repos/X/Y/issues/{N}/comments`) and, for GraphQL, by decoding GitHub's node IDs to extract the embedded repo.
- Cross-agent: every agent goes through the proxy because every agent uses HTTPS.

### Host-side wrapper / push gate (rejected on cross-agent grounds)

- Wrapped tools (`pr_comment`, `push_branch`) implemented as host-side RPC: the strongest possible isolation, but requires per-agent integration (pi tools, Claude Code MCP server, Codex plugin). Doesn't satisfy the cross-agent constraint.
- Push gate (file-based intent + host watcher): same problem, plus only covers git push, not the API surface.

### Agent-side convention (weak — relies on agent compliance)

- CLAUDE.md rules like "never push to main." Useful as a hint, *not* a security boundary — prompt injection bypasses it instantly.

## Airut: prior art worth studying

[airut](https://github.com/airutorg/airut) is the most thoroughly designed open implementation of the proxy-with-surrogates pattern, and it directly inspired agentbox. It's overkill for a single-user launcher but the design choices are instructive.

### Architecture

- Each task runs in a fresh **rootless Podman** container with `--cap-drop=ALL`, `no-new-privileges`, isolated workspace.
- The container has **no default route** other than the proxy IP. The proxy listens only on 80/443. SSH, raw TCP, anything else: `connection refused`. No iptables, no `CAP_NET_ADMIN` needed.
- A **DNS responder inside the proxy** returns the proxy IP for every A query unconditionally and never forwards upstream — DNS exfiltration impossible, direct-IP bypass attempts also land at the proxy.
- Enforcement is **mitmproxy** (`mitmdump`, no web UI) with a custom Python addon. Transparent because of the DNS spoofing — works with every tool (Node, Go, curl, Python, git) without `HTTP_PROXY`.

### Allowlist as code, in the default branch

Allowlist lives at `.airut/network-allowlist.yaml` in the **repo's default branch** — *not* the agent's workspace. The agent can edit the workspace copy but the change has no effect until merged. Branch protection becomes the enforcement mechanism for the security policy itself.

This is the single most "borrowable" idea even at the smallest scale: keep the policy in a config file the host reads, not in the container's mounted workspace, so the agent can't widen its own scope mid-task. agentbox's launcher copies the resolved allowlist to a tempdir at launch time, so edits to the source after launch don't take effect on a running session.

Allowlist syntax (which agentbox borrows wholesale):

```yaml
domains:
  - "*.github.com"

url_prefixes:
  - host: api.anthropic.com
    path: /v1/messages*
    methods: [POST]
  - host: api.github.com
    path: /repos/your-org/your-repo*
  - host: api.github.com
    path: /graphql
    methods: [POST]
    graphql:
      queries: ["*"]
      mutations:
        - createIssue
        - createPullRequest
```

Patterns are fnmatch wildcards. Hosts case-insensitive (RFC 4343), paths case-sensitive. Per-prefix method filtering. CONNECT unconditionally blocked. Absolute-form HTTP requests with mismatched `Host` headers blocked. Redirects not auto-followed (the next request gets allowlist-checked again). agentbox today implements `domains` and `url_prefixes` (without methods filtering yet — a follow-up); the GraphQL operation allowlist is a future addition.

### Three credential modes

Real credentials never live in the container. Three escalating tiers:

**`masked_secrets` — surrogate tokens for PATs / API keys.** Container gets a *format-preserving surrogate* (`ghp_yyy…` of the same length and prefix as the real `ghp_xxx…`). Proxy holds the real value. On allowed hosts, the proxy swaps surrogate→real in matching headers. **This is what agentbox implements.**

```yaml
masked_secrets:
  GH_TOKEN:
    value: !env GH_TOKEN
    scopes: ["api.github.com", "*.githubusercontent.com"]
    headers: ["Authorization"]
    allow_foreign_credentials: false   # default
```

`allow_foreign_credentials: false` is a key defense: on allowlisted hosts, any `Authorization` header that does *not* contain the surrogate is **stripped entirely**, so the agent can't sneak its own attacker-supplied token through. The proxy decodes Base64 Basic Auth payloads to find the surrogate too — that's how `git push`/`git fetch` work, since `gh auth git-credential` sends `x-access-token:TOKEN` as Basic Auth. agentbox handles Bearer + Basic Auth swap today; foreign-credential stripping is a follow-up.

**`signing_credentials` — AWS SigV4 re-signing.** Container gets fake AWS keys. Agent signs with the fake. Proxy verifies the signature, then re-signs with real credentials. Real keys never leave the proxy. Not implemented in agentbox (no current AWS surface).

**`github_app_credentials` — proxy-managed token rotation.** Proxy holds the GitHub App private key and `installation_id`. Container gets a `ghs_yyy…` surrogate. On the first GitHub request, the proxy generates a JWT (RS256, 9-minute lifetime), exchanges it for a 1-hour installation token, caches the token, and substitutes it. Cache refreshes 5 minutes before expiry. Compared to a long-lived PAT: 1-hour blast radius even at the proxy, automatic rotation, higher rate limits, per-mint permission/repo narrowing. **agentbox doesn't implement this yet — it uses a long-lived PAT held by the proxy, which is acceptable because the container never sees it.** Migration to App-minted tokens is the natural next iteration.

### GraphQL repository scoping — the answer to "specific PRs only"

The most interesting piece for "limit writes to specific targets." GitHub's GraphQL has a brutal property: an installation token can perform some mutations on **any public repo** regardless of the App's scope, and `Query.repository(owner, name)` can read any public repo. The mutation `addComment(input: {subjectId: …})` doesn't even name a repo — just a node ID.

Airut's proxy enforces a four-layer scope check on every GraphQL request:

- **Layer 0 — `repository(owner, name)` selections.** Walks the AST for any `repository` field, extracts owner/name (including chained `organization(login).repository(name)`), matches case-insensitively. Anything that can't be resolved (e.g. inside a fragment spread) is fail-secure blocked.
- **Layer 1 — `repositoryId` field.** At token refresh, the proxy calls `GET /installation/repositories` to learn node IDs and `owner/name` for allowed repos. Any `repositoryId` in the AST or variables that's not in the set → 403.
- **Layer 2 — `repositoryNameWithOwner`.** Some mutations (e.g. `createCommitOnBranch`) take `branch.repositoryNameWithOwner`. Same check, against full names.
- **Layer 3 — node-ID ownership decoding.** GitHub's new-format node IDs are `TYPE_PREFIX + "_" + base64(msgpack([0, repo_db_id, ...]))`. The proxy decodes the msgpack payload of every `*Id`/`*Ids`/`id` field, extracts the embedded repo database ID, and verifies it matches an allowed repo. So `addComment(input: {subjectId: PR_node_id})` is checked by decoding the PR node ID to its parent repo ID. Unknown node-ID formats → block.

This is exactly the "comment only on PRs in this repo" enforcement, done at the proxy with no per-PR config. **agentbox now implements all four layers** (`src/agentbox/proxy/{node_id,graphql_scope}.py`, ported from airut and kept close to the upstream so fixes flow both ways). The launcher resolves each `--repo OWNER/NAME` to its node ID via `gh api repos/{owner}/{name}` at startup and writes a `repos.json` next to `credentials.json`/`allowlist.yaml`; the proxy reads it and enforces scope on every `POST /graphql` to `api.github.com`. Per-PR / per-issue / per-branch is the next step (the YAML schema already parses-and-ignores `pull_requests`, `issues`, `branches` fields under `github.repos[]`).

A second layer runs *before* the scope check: a default-deny **GraphQL operation allowlist** (`src/agentbox/proxy/graphql_operations.py`). Top-level field names not on the configured `queries` / `mutations` / `subscriptions` lists are blocked with a structured `unsupported_feature` 403 and a JSON log line, so operators have a feed for "what GitHub feature do we need to extend coverage for next?" The default operation list ships in the bundled `github_policy.yaml` (loaded by the proxy independently of the network `allowlist.yaml`) and covers the common `gh` PR / issue / review flow plus broad reads (`viewer`, `repository`, `search`, ...).

A third layer is **shadow-mode only**: a `dangerous:` watchlist (`src/agentbox/proxy/dangerous_operations.py`) that runs after Layer 2 says ALLOW. Patterns are fnmatch-style and match the full `<type>/<field>` operation tag. Matches don't block — they emit a structured WARN line (`agentbox graphql warning: {…json…}`) and decorate the per-request audit line with a `"dangerous"` field. The default list flags `mergePullRequest` and `createCommitOnBranch` (the most consequential mutations in the bundled supported-mutations set); operators add patterns like `mutation/delete*` or `mutation/transferRepository` if they broaden the supported list. The point is to surface "scope check passed, but is this what you really wanted?" without forcing the operator to pick exact policy up front — they iterate the YAML based on what shows up in the WARN feed.

### Other airut details worth absorbing

- The container uses `gh auth git-credential` so `git push` flows through HTTPS Basic Auth, which the proxy already handles. No SSH agent plumbing.
- Logs distinguish `[masked: N]` (replacements done) and `[dropped: N]` (foreign credentials stripped).
- The whole proxy is a self-contained Python package (`airut/_bundled/proxy/`) — usable as direct reference for agentbox.

## Other approaches in the wild

- **Anthropic's official claude-code devcontainer** ([init-firewall.sh](https://github.com/anthropics/claude-code/blob/main/.devcontainer/init-firewall.sh)) uses iptables + ipset: default-deny outbound, allowlist specific domains via `dig`, fetches GitHub IP ranges from `api.github.com/meta`. Coarse — TCP layer, no path/method/credential handling. Token sits in env in the container.
- **Andrew Lock's "Docker AI agent" post** describes the same proxy-injects-auth pattern as airut but in less detail. Notably flags commit signing as unsolved — workaround: produce unsigned commits in the sandbox, rebase-sign on the host.
- **trailofbits/claude-code-devcontainer, IVIJL/devbox, sandvault, agent-infra/sandbox** — container-isolation focused (rootless DinD, default-deny firewall). Rely on "no real credentials in the container" + "branch protection on main" rather than per-write proxy scoping.
- **Devin / OpenHands / Cursor background agents** — typically a dedicated GitHub App with installation token, agent works in an isolated worker, opens PRs. Narrowing comes from App installation scope plus required PR review, not proxy enforcement.

## Credential rotation: PAT vs GitHub App

A practical question: how dynamic can the credential be? Can a fresh token be minted per session with no manual GitHub steps?

**Fine-grained PATs are effectively static.** They can be created programmatically via `POST /user/personal-access-tokens`, but that endpoint requires authentication with… another PAT — chicken-and-egg. Scopes, permissions, and expiry are picked at creation; the token string is shown once. Classic PATs can't be created via API at all — UI only.

In practice fine-grained PATs are one-time-setup-then-rotate-manually credentials. **Workable when the PAT lives only at the proxy** — exfiltration risk is bounded to the proxy host, and rotating quarterly is a manageable manual chore. This is agentbox's current setup.

**GitHub Apps are the seamless answer.** One-time UI setup (name the App, pick permissions, generate a private key, install on the desired repos), and after that the App's private key + installation ID can mint a fresh 1-hour installation token programmatically:

1. Sign a JWT locally with the private key (RS256, ≤10-minute lifetime).
2. `POST /app/installations/{id}/access_tokens` with the JWT.
3. Receive a `ghs_…` token, valid for 1 hour.

Per-session rotation is essentially free — no UI, no manual steps, automatic expiry. Optional `permissions` and `repositories` fields on the access-token request let you narrow further per token. This is exactly why airut uses a GitHub App: rotation cost is amortized into the proxy.

For agentbox specifically, the App migration changes the proxy's responsibility: instead of holding a static PAT, hold a private key + installation ID and refresh tokens on demand (5-minute refresh margin, in-process cache). The container's surrogate stays stable across rotations — agent never notices. Per-session permission narrowing (`permissions: {contents: read}` for read-only sessions) becomes trivial.

## The chosen design

Given the constraints, the design space collapses to **a host-side proxy that holds the real credential and substitutes a per-session surrogate into the container's environment.** That's the only mechanism that simultaneously:

- Keeps real creds out of the container (constraint 1)
- Operates below the agent layer so it works regardless of which agent runs (constraint 2)
- Can scope by host + path + method (and eventually GraphQL operation) for the read/write split (constraint 3)

Two further choices flowed from there:

**Where the proxy lives.** A sidecar container is portable but adds compose complexity. A long-lived host process is fast across sessions but requires a host-side install. A **per-session subprocess of a Python launcher** matches single-user usage best: lifecycle = session, single artifact to install (`uv tool install ./agentbox`), easy iteration, no compose. Multiple concurrent sessions simply run multiple launchers, each with its own proxy on its own free port.

**How the container reaches the proxy.** Explicit `HTTPS_PROXY` env var (regular mitmproxy mode) is the simplest and is respected by `git`, `gh`, `curl`, npm, Python, and Node-based agents. Transparent DNS spoofing (airut's approach) is more universal but adds Docker networking complexity not warranted at this scale. We'll switch only if we find a tool that ignores `HTTPS_PROXY`.

### Architecture

```
host
├── agentbox CLI                       # launcher process, user-facing entry point
│   ├─ generates GH surrogate         # ghp_<random36> per session
│   ├─ writes credentials.json        # per-kind: github -> {surrogate, real}
│   ├─ writes github.json             # {mode, repos: [{full_name, node_id, issues, pull_requests, branches}]}
│   ├─ writes allowlist.yaml          # per-session policy (copy of source)
│   ├─ ensures ~/.mitmproxy CA exists
│   ├─ spawns subprocess:
│   │      python -m agentbox.proxy
│   │      ├─ mitmdump on 127.0.0.1:<free port>
│   │      └─ filter.py addon (allowlist + handler dispatch)
│   └─ runs docker run with:
│      - HTTPS_PROXY=http://host.docker.internal:<port>
│      - GH_TOKEN=<surrogate>
│      - mitmproxy CA bind-mounted at /usr/local/share/ca-certificates/agentbox-ca.crt
│      - per-tool CA env vars (NODE_EXTRA_CA_CERTS, GIT_SSL_CAINFO, ...)
│      - cwd mirrored under /agentbox/ (e.g. C:\code\agentbox -> /agentbox/c/code/agentbox)
│      - ~/.pi mounted at /home/agentbox/.pi
│      - ~/.claude mounted at /home/agentbox/.claude (if it exists on the host)
└── ~/.pi, ~/.claude (host)           # agent state + credentials, mounted into container
```

The launcher is the user-facing entry point (`agentbox`). The proxy runs as its child subprocess. On exit (Ctrl+C or container completion), `atexit` handlers terminate the proxy and clean up the tempdir.

### Layout

```
agentbox/
├── pyproject.toml                  # uv-installable, defines `agentbox` script
├── tests/
│   ├── test_filter.py              # allowlist + handler dispatch
│   └── test_handlers.py            # per-provider credential handlers
└── src/agentbox/
    ├── __init__.py
    ├── cli.py                      # launcher: surrogate gen, proxy spawn, docker run
    ├── progress.py                 # session-file tail + tool-call render for `pi -p`
    ├── sandbox/
    │   ├── Dockerfile              # agentbox-base: agent runtime (gh, pi, claude, helper, CA trust)
    │   └── bashrc                  # in-container shell init / banner
    │   # Project toolchains live in a project-side `Dockerfile.agentbox`
    │   # that does `FROM agentbox-base:<version>` and adds whatever the
    │   # project needs (.NET, Go, language servers, etc.). The launcher
    │   # builds this at start-up if present, otherwise runs the agent
    │   # in agentbox-base directly.
    └── proxy/
        ├── __init__.py
        ├── __main__.py             # `python -m agentbox.proxy` -> mitmdump
        ├── filter.py               # mitmproxy addon: allowlist + handler dispatch
        ├── handlers.py             # GithubCredentialHandler (+ future providers)
        ├── allowlist.yaml          # default network policy
        └── github_policy.yaml      # GraphQL operation allowlist + per-repo scope schema
```

### Inline progress for `pi -p`

When `agentbox pi -p "<prompt>"` runs (and the user hasn't passed `--no-session`), the launcher spawns a watcher thread that:

1. Snapshots existing files in the pi session dir for the current cwd before launch (pi names it by replacing `/` with `--` in its cwd, e.g. `/agentbox/c/code/agentbox` -> `~/.pi/agent/sessions/--agentbox--c--code--agentbox/`).
2. Polls the directory for the new `.jsonl` pi creates (always written, since pi defaults to session persistence).
3. Tails the file from the host as pi appends to it, parsing each event and printing a single-line summary on stderr (model change, thinking summary, tool calls with arguments, tool results).
4. Pi runs in plain `--mode text`, so the final assistant answer flows to stdout untouched — `agentbox pi -p ... | pbcopy` still copies just the answer.

This sidesteps several layers of buffering you'd hit if you tried to stream pi's `--mode json` stdout through Docker's pipes (Node fully-buffers `process.stdout` when piped, and the docker `-t` workaround is unreliable on Windows). The session file is a regular bind-mounted file growing in real time.

`AGENTBOX_DEBUG=1` enables watcher heartbeat logs — useful when no progress shows up and you want to know whether the watcher's running, found the file, or has hit an error.

### Surrogate swap mechanics

The launcher generates a surrogate token (`ghp_AGENTBOX_SURROGATE_<24 random alphanumeric>` — keeps the `ghp_` prefix so prefix-validating tools accept it, embeds the literal `AGENTBOX_SURROGATE` so it's trivially greppable in any log or process listing). It writes a `credentials.json` to the proxy's tempdir, keyed by *credential kind* — one block per provider, each consumed by a corresponding handler class in `agentbox.proxy.handlers`:

```json
{
  "github": {
    "surrogate": "ghp_AGENTBOX_SURROGATE_yyy...",
    "real": "ghp_realtoken..."
  }
}
```

The proxy filter (`filter.py`) does, for each request:

1. **Allowlist check.** Match host + path + method against the allowlist; 403 with a `agentbox: …` body if no match.
2. **Handler dispatch.** Iterate the configured credential handlers. For each handler whose `matches_host(host)` is true, invoke `handle(request)`. The `GithubCredentialHandler` owns its own scope list (`api.github.com`, `github.com`, `*.github.com`, `*.githubusercontent.com`, `*.pkg.github.com`) and the `Authorization` swap mechanics — Bearer/`token` inline, plus Base64 Basic Auth (how `git push`/`gh auth git-credential` send tokens).
3. **Foreign-credential stripping.** Same handler, same scoped hosts: any `Authorization` header that doesn't contain the known surrogate is dropped entirely. Prevents an in-container attacker (or prompt-injected agent) from sneaking their own `Bearer <attacker_token>` past the proxy on an allowlisted host. Set `allow_foreign_credentials: true` on the JSON block to opt out (matches airut semantics); the secure default is to strip.

The dispatch model means each handler runs *only* on hosts in its own scope. An allowlisted-but-unrelated host (npm, PyPI, `api.anthropic.com`) passes through untouched even when a GitHub handler is configured. Adding a new provider is a new handler class plus a new top-level key in `credentials.json`; there is no shared "scopes/headers" config to keep in sync between launcher and filter.

If `GH_TOKEN`/`GITHUB_TOKEN` is unset on the host, the launcher writes `credentials.json` without a `github` block and zero handlers run — the container has no GitHub credential at all (reads of public repos still work; private reads and writes fail at upstream auth).

### CA cert handling

mitmproxy MITMs HTTPS, which requires the container to trust mitmproxy's self-signed CA. The launcher:

- Ensures `~/.mitmproxy/mitmproxy-ca-cert.pem` exists, generating it via a one-shot `mitmdump` if not.
- Bind-mounts the cert into the container at `/usr/local/share/ca-certificates/agentbox-ca.crt`.
- Sets per-tool env vars so non-system-CA tools find it: `GIT_SSL_CAINFO`, `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`.

This covers `git`, `gh`, `curl`, Node-based agents (pi/Claude/Codex), and Python `requests`. Tools that read **only** the system CA bundle (notably `apt-get`) won't trust the proxy until the image runs `update-ca-certificates` after copying the cert in. That requires a Dockerfile change, deferred for now.

### Networking

Three plumbing modes, selectable per-session via `--network MODE` or the `network:` key in `agentbox.config.yaml`. Default is `permissive` — today's behaviour, formalised. Network mode controls *plumbing*; the allowlist YAML controls *policy*; the two are orthogonal.

#### `permissive` (default)

```
agent container ─HTTPS_PROXY─→ host.docker.internal:<port> ─→ mitmproxy ─→ upstream
```

`host.docker.internal` resolves to the host from inside Docker Desktop containers automatically. On native Linux Docker, the launcher adds `--add-host=host.docker.internal:host-gateway`. The proxy binds to `127.0.0.1:<free-port>` on the host; the port is picked at launch via `socket.bind(("127.0.0.1", 0))` so concurrent agentbox sessions don't collide.

The bundled `allowlist.yaml` ships with `permissive: true`, which short-circuits all five enforcement layers (host/path/method, GraphQL ops gate, GraphQL repo scope, dangerous-ops watchlist, foreign-credential stripping stays on as a credential-isolation property). Cred surrogate swap still runs. So in the default configuration the proxy is a pure pass-through — present so the surrogate→real swap and CA termination work, not as an enforcement boundary. Anything that ignores `HTTPS_PROXY` (raw TCP, SSH, DNS exfil, statically-linked binaries) bypasses entirely. Cross-platform.

#### `transparent-shared`

```
agent container (same netns as sidecar)
   │  ┌──────────────────────────────────┐
   ├─→│ iptables NAT REDIRECT (TCP/80+443) │─→ mitmproxy ─→ upstream
   └─→│ DNS sinkhole (UDP/53)              │
      └──────────────────────────────────┘
```

The proxy runs as a sidecar container; the agent container starts with `--network container:<sidecar-name>` so the two share a network namespace. The sidecar's entrypoint installs iptables NAT rules redirecting all TCP/80 and TCP/443 traffic to a transparent-mode mitmproxy listener (which recovers the original destination via `SO_ORIGINAL_DST` and reads SNI for HTTPS), and binds a tiny UDP/53 DNS responder that answers every A query with the netns's own IP and NXDOMAINs AAAA. No `HTTPS_PROXY` env var; the agent has no way of knowing it's being intercepted. Tools that ignore `HTTPS_PROXY` are caught at the kernel level. DNS exfiltration is impossible. Raw TCP to non-allowlisted IPs lands at the proxy regardless of destination IP.

mitmproxy runs under a dedicated UID; an iptables `--uid-owner ... -j RETURN` rule lets its own upstream traffic skip the redirect (otherwise it would loop). The agent has `--cap-drop=ALL`, so it cannot rewrite iptables rules; the sidecar holds `CAP_NET_ADMIN` and `CAP_NET_BIND_SERVICE` for its initial setup.

Cross-platform — Docker Desktop's underlying VM is Linux, so iptables in the sidecar works identically on Win/Mac/Linux. Cost vs. `transparent-isolated`: the agent and sidecar share `lo`, so the agent could try to address the proxy via `127.0.0.1:8080` directly. With `mitmdump` (no web UI) this is the same hardened HTTP listener that's the entire enforcement point — not a real escape. Don't bind anything else to localhost in the sidecar without thinking about it.

#### `transparent-isolated` (reserved, not yet implemented)

Linux-only variant where the agent and sidecar live in separate netns and reach each other via macvlan or a custom CNI bridge. Strictly stronger than shared-netns — the agent cannot address the sidecar's `127.0.0.1` at all. Out of scope for the initial implementation; selecting it today exits with a friendly "not yet supported" message at startup. The CLI flag and config value exist as scaffold so the switch lands cleanly when the macvlan/CNI work is done.

#### Image build

Permissive mode builds only `agentbox-base` (and the project image if a `Dockerfile.agentbox` is present). Transparent-shared additionally builds `agentbox-proxy-sidecar:local` from `src/agentbox/sandbox/proxy/Dockerfile`, with `src/agentbox` as the build context so the Dockerfile can `COPY` the `agentbox.proxy` package into the image. Layer cache makes both no-op rebuilds near-instant; `--no-cache` forwards through to both.

### Per-session policy

The default network allowlist (`agentbox/src/agentbox/proxy/allowlist.yaml`) is permissive — Anthropic, GitHub, npm, PyPI as `domains:` entries. Override per session:

```
agentbox --allowlist /path/to/custom.yaml
```

The custom file is copied to the proxy's tempdir at launch, so edits to the source file after launch don't affect the running session — agent self-widening attempts hit the snapshot, not the live policy.

For tighter scoping, the allowlist supports `url_prefixes:` entries with host + path + optional methods:

```yaml
url_prefixes:
  - host: api.github.com
    path: /repos/your-org/your-repo*
    methods: [GET]
  - host: api.github.com
    path: /repos/your-org/your-repo/issues/*/comments
    methods: [POST]
```

GitHub-specific access policy is decoupled from the network allowlist and lives in a top-level `github:` block in `agentbox.config.yaml`:

```yaml
github:
  mode: auto    # none | unrestricted | scoped | auto (default)
  repos:
    - owner/short-form                  # full-access shorthand
    - name: owner/explicit-form         # per-op allowlist
      issues:        [comment, create]
      pull_requests: [comment, review, merge]
      branches:
        push:   ["agent/*"]
        create: ["agent/*"]
```

`mode: auto` resolves based on token presence and `repos:` content — no token → `none`, token + empty repos → `unrestricted`, token + non-empty repos → `scoped`. Explicit `mode:` always wins. The CLI mirror is `--github-mode {none,unrestricted,scoped,auto}`. The launcher resolves the merged config (CLI flags additive over yaml) into `workdir/github.json` (`{mode, repos: [{full_name, node_id, issues, pull_requests, branches}]}`) and hands that to the proxy via `--github-policy`. The curated GraphQL operation allowlist lives in a separate bundled file (`proxy/github_policy.yaml`), loaded by the proxy regardless of the network mode.

## Current limitations and follow-ups

- **System CA trust requires a Dockerfile change.** Without `update-ca-certificates` baked into the image after the cert mount, tools that ignore the env vars (apt, some package managers) fail TLS verification. Deferred.
- **Container still runs as root.** The launcher applies `--cap-drop=ALL` and `--security-opt=no-new-privileges` so even in-container "root" can't open raw sockets, mount, or bypass setuid restrictions, but uid 0 inside the container still has DAC override on the bind-mounted `~/.pi` and `~/.claude` (which are root-owned in the image). Mapping the container to a non-root uid (e.g. uid 1000 with a user-writable home) is the next step; needs Dockerfile work to create the user and re-own `/root` paths.
- **GraphQL scope checks are per-repo, not per-PR.** The `--repo OWNER/NAME` gate covers all four airut layers (repository(owner,name), repositoryId, repositoryNameWithOwner, node-ID ownership) so writes can't address repos outside the list, but per-PR / per-issue / per-branch narrowing inside a repo isn't enforced yet (the YAML schema reserves the fields). That's the next step.
- **No comprehensive policy language yet.** The current "list of full-names" schema is a stand-in for a richer per-repo policy: PR/issue allowlists by number or author (`@me`), branch globs (`agent/*`, `!main`), per-repo operation subsets (`operations: [addComment, createPullRequest]`), per-repo dangerous-ops overrides. The decoder already extracts per-object DB IDs from node IDs, so the enforcement substrate exists; the missing pieces are the surface language, the launcher-side resolution (`gh api repos/X/Y/pulls/N --jq .id` per allowlisted PR), and the scope-check extension to match `(repo_db_id, object_db_id)` tuples. Search the codebase for `TODO(policy-language)` for the hook points.
- **GraphQL operation list is curated, not exhaustive.** Anything outside the bundled list returns `unsupported_feature` and a structured log line, so adding a missing field is a one-line YAML edit -- but expect to extend the list as new `gh` subcommands are exercised. Watch the proxy log for `"verdict":"blocked","layer":"operations"` entries.
- **No GitHub App support.** Today the proxy holds a long-lived PAT. A GitHub App with proxy-managed token rotation would give 1-hour blast radius and per-mint permission/repo narrowing.
- **Agent OAuth credentials are bind-mounted directly.** `~/.pi` and `~/.claude` are passed straight through from the host, so real refresh tokens enter the container. Five replacement patterns are detailed in the file-backed OAuth section below.
- **No per-branch push enforcement at the proxy.** git's smart HTTP protocol carries refs in a binary body the proxy doesn't parse. Use repository rulesets server-side.
- **No method filter on `domains:` entries.** `domains:` is a host-only allow; method filtering only applies to `url_prefixes:`. To restrict methods on a host, use `url_prefixes:` with a wildcard path.

## Future work: file-backed OAuth credentials (Claude Code, pi)

**Current state.** agentbox bind-mounts the host's `~/.pi` and (if present) `~/.claude` directly into the container. Real refresh tokens enter the container; in-container refreshes overwrite the host file with rotated tokens. This is acceptable as a starting point because it keeps the surface small and lets us validate the proxy approach end-to-end against real agents on real subscriptions before adding complexity. `ANTHROPIC_API_KEY` is intentionally **not** forwarded — the subscription/OAuth path is the supported flow.

**The plan.** Lift the file-bind compromise via the patterns below, in the layered order in the recommendation section.

The current proxy handles GitHub-PAT-style static bearer tokens. Several agents — Claude Code on Pro/Max, pi using OAuth providers, Codex — instead store credentials in a file the agent both reads *and* writes, and refresh them proactively against an OAuth `/oauth/token` endpoint. Two new problems vs. the GitHub case:

1. **The credentials file.** Mounting the host's `~/.claude/` or `~/.pi/agent/auth.json` directly puts the real refresh token in the container and lets in-container refreshes overwrite the host file with rotated tokens — possibly mid-rotation by another host process.
2. **The refresh flow.** If the container ever calls `POST /v1/oauth/token`, the proxy must either swap the surrogate refresh token for the real one and rewrite the response (so the container receives new *surrogates*, not new real tokens) or block the refresh.

### How each agent stores credentials

**pi** (`@mariozechner/pi-coding-agent`):

- File: `~/.pi/agent/auth.json` (mounted as `/home/agentbox/.pi/agent/auth.json` today).
- Format: per-provider entries, either `{type: "api_key", key}` or `{type: "oauth", access, refresh, expires}`.
- Refresh: in `core/auth-storage.js` `refreshOAuthTokenWithLock` — when `getApiKey()` is called and the token is past `expires`, pi grabs an flock, calls the provider's refresh, writes the result back. Concurrent pi processes serialize via the lock.
- Anthropic OAuth refresh: `POST https://platform.claude.com/v1/oauth/token` with `grant_type=refresh_token` (`pi-ai/dist/utils/oauth/anthropic.js`).
- Alternative: `ANTHROPIC_API_KEY` env var (no refresh).

**Claude Code**:

- File: `~/.claude/.credentials.json` on Linux (the container case); macOS keychain; Windows-via-WSL same as Linux.
- Schema: `{accessToken, refreshToken, expiresAt, scopes}`. Refresh tokens rotate on each use; Claude Code does write-back.
- Proactive refresh: roughly every 5 minutes or on 401, controlled by `CLAUDE_CODE_API_KEY_HELPER_TTL_MS` (which gates the API-key helper, separate from OAuth expiry).
- Same Anthropic OAuth endpoint.
- Two static alternatives:
  - `ANTHROPIC_API_KEY` (Console-issued static key).
  - `CLAUDE_CODE_OAUTH_TOKEN` — long-lived OAuth token minted via `claude setup-token` on the host, designed for CI use.

**Codex**: `https://auth.openai.com/oauth/token` with the same `grant_type=refresh_token` shape (`pi-ai/dist/utils/oauth/openai-codex.js`). Same dynamics.

### Five patterns, in increasing complexity

**Pattern 1 — API keys only.** Use `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` instead of OAuth. Static bearer, no refresh, behaves like a GitHub PAT in agentbox. Adding it is a new handler class in `proxy/handlers.py` (its own host scopes, its own surrogate prefix `sk-ant-…` / `sk-…`) plus a new top-level key in `credentials.json` that the launcher fills from the host env. Costs you Pro/Max billing.

**Pattern 2 — long-lived surrogate in the file, proxy refreshes silently.** The recommended path. Mechanics:

- Launcher reads the host's real `auth.json` / `.credentials.json` at session start, extracts `{access, refresh, expires}`.
- Launcher writes a surrogate credentials file to the session tempdir with surrogate access + surrogate refresh + far-future `expiresAt` (e.g. now + 1 year).
- Mount strategy: keep the existing `~/.pi:/home/agentbox/.pi` bind, but **override the single auth file** with a second mount targeting the surrogate: `-v /tmp/agentbox-…/auth.json:/home/agentbox/.pi/agent/auth.json`. Same trick for `~/.claude/.credentials.json`.
- Proxy holds the real `{access, refresh, expires}` plus the surrogate→real mapping. Swaps the surrogate Bearer token for the real one on `api.anthropic.com` / `api.openai.com`. When the *real* access token is within ~5 min of expiry, the proxy refreshes against the OAuth endpoint with the real refresh token, rotates the real pair in memory, and persists the latest real refresh token back to the host file under a flock.
- Container never refreshes — its `expiresAt` is far in the future, so the surrogate stays stable across the session.

This is airut's `github_app_credentials` pattern (proxy-managed token rotation) applied to Anthropic OAuth. **Cleanest answer for "no creds in container."**

The risk: assumes the agent trusts the file's `expiresAt`. If Claude Code or pi sanity-checks ("expiresAt > N hours from now is suspicious, force refresh"), pattern 2 falls through to pattern 3. Verify experimentally. From source, neither does this today, but both could.

**Pattern 3 — bidirectional response rewrite.** Fallback for pattern 2 if any agent insists on refreshing:

- Container's surrogate file has a normal expiry (~30–60 min).
- Container hits `POST /v1/oauth/token` with surrogate refresh.
- Proxy swaps surrogate→real refresh, forwards to upstream.
- Upstream returns new real `{access_token, refresh_token, expires_in}`.
- Proxy generates new surrogates for the new real values, updates in-memory mapping, **rewrites the response body** to contain the new surrogates, forwards to container.
- Container writes the new surrogates to the surrogate-tempdir mount. Real values never enter the container.
- At session end, launcher persists the latest real refresh token back to the host.

mitmproxy supports response rewriting cleanly. More state (the in-memory mapping mutates on each refresh; the host file needs sync because refresh tokens rotate). ~50–100 extra lines on top of the current filter.

**Pattern 4 — precompute a long-lived OAuth token (Claude Code only).** Run `claude setup-token` on the host; treat the resulting `CLAUDE_CODE_OAUTH_TOKEN` like an API key — surrogate in env, proxy swaps on `api.anthropic.com`. Pattern 1 mechanics, OAuth billing. Useful as a Claude-Code-specific shortcut.

**Pattern 5 — periodic host-side refresh.** Scheduled-rotation variant of pattern 2: proxy refreshes the real token every ~30 min regardless of demand. Same security; simpler reasoning if you want to avoid ever blocking a request on the OAuth endpoint. Costs a few unnecessary refreshes per session.

### Recommendation

Layer the rollout:

1. **Add API-key surrogate handling** to the existing replacement map. `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` from host env get format-preserving surrogates injected into container env, scoped to `api.anthropic.com` / `api.openai.com`. Unblocks pi-with-API-key and any env-driven agent.
2. **Implement pattern 2** for file-backed cases. Launcher reads the host credentials files, writes surrogate versions to the session tempdir, overlays via single-file bind mounts, hands real values to the proxy. Proxy refreshes on demand within 5 min of expiry, persists rotations back under a flock.
3. **Upgrade specific paths to pattern 3** if testing finds an agent refuses far-future `expiresAt`. Doesn't change the launcher; only the filter addon gains a `response()` hook for `platform.claude.com/v1/oauth/token`.
4. **Optional pattern 4** for Claude Code: if `CLAUDE_CODE_OAUTH_TOKEN` is set on the host, treat as an API key and skip the file overlay.

### Things to verify before committing to pattern 2

- Does pi's `getApiKey()` honor `expiresAt` of "in 1 year"? Source skim says yes (`Date.now()` comparison only), but smoke-test.
- Same for Claude Code's OAuth path. The 5-minute helper TTL is a separate mechanism (API-key helpers, not OAuth refresh) but confirm it doesn't force refresh independent of `expiresAt`.
- Does pi tolerate `auth.json` on a docker bind mount with the host file overlaid? `proper-lockfile` flock should work on bind mounts; smoke-test.
- Does `~/.claude/.credentials.json` mode 600 propagate through Docker bind mount? Claude Code may refuse to read otherwise.

## References

- [airut on GitHub](https://github.com/airutorg/airut)
- [airut.org landing page](https://airut.org/)
- [airut spec/masked-secrets.md](https://github.com/airutorg/airut/blob/main/spec/masked-secrets.md)
- [airut spec/github-app-credential.md](https://github.com/airutorg/airut/blob/main/spec/github-app-credential.md)
- [airut spec/network-sandbox.md](https://github.com/airutorg/airut/blob/main/spec/network-sandbox.md)
- [airut spec/pr-workflow-tool.md](https://github.com/airutorg/airut/blob/main/spec/pr-workflow-tool.md)
- [airut config/airut.example.yaml](https://github.com/airutorg/airut/blob/main/config/airut.example.yaml)
- [Andrew Lock — Running AI agents safely in a microVM using docker sandbox](https://andrewlock.net/running-ai-agents-safely-in-a-microvm-using-docker-sandbox/)
- [Anthropic claude-code init-firewall.sh](https://github.com/anthropics/claude-code/blob/main/.devcontainer/init-firewall.sh)
- [GitHub Docs — Available rules for rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets)
- [GitHub Docs — Creating rulesets for a repository](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository)
- [GitHub Changelog — Ruleset exemptions (Sept 2025)](https://github.blog/changelog/2025-09-10-github-ruleset-exemptions-and-repository-insights-updates/)
- [trailofbits/claude-code-devcontainer](https://github.com/trailofbits/claude-code-devcontainer)
- [IVIJL/devbox](https://github.com/IVIJL/devbox)
