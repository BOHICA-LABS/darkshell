# DarkShell

[![License](https://img.shields.io/badge/License-Apache_2.0-blue)](LICENSE)
[![CI](https://github.com/BOHICA-LABS/darkshell/actions/workflows/ci.yml/badge.svg)](https://github.com/BOHICA-LABS/darkshell/actions/workflows/ci.yml)
[![Fork Validation](https://github.com/BOHICA-LABS/darkshell/actions/workflows/ci_fork_validation.yml/badge.svg)](https://github.com/BOHICA-LABS/darkshell/actions/workflows/ci_fork_validation.yml)

DarkShell is a fork of [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) with
enhanced developer experience for the [DarkClaw](https://github.com/BOHICA-LABS/DarkClaw)
factory ecosystem. It adds fast file transfer, direct command execution, first-class
MCP server management, full sandbox observability, and declarative blueprint-based
sandbox creation — without changing OpenShell's kernel-enforced security model.

> **Everything we add is additive.** No security downgrades, no isolation weakening.
> Landlock, seccomp, network namespaces, OPA policy, and SSRF protection are
> inherited unchanged from upstream.

## What DarkShell Adds

| Feature | OpenShell | DarkShell |
|---------|-----------|-----------|
| **File upload** | Full tar every time (30s+ for 2GB) | rsync delta — only changed files (< 2s) |
| **Command execution** | SSH session per command (200-500ms) | `exec` with ControlMaster reuse (< 20ms) |
| **MCP servers** | Manual proxy + policy + port forward | `darkshell mcp add` — one command |
| **Sandbox setup** | 5+ manual commands | Blueprint YAML — one file, one command |
| **Observability** | After-the-fact log retrieval | Real-time `sandbox watch` event stream |
| **Upload preview** | Blind transfer | `--dry-run` shows what would change |
| **Download** | Full workspace download | `--include`/`--exclude` filtering |
| **Progress** | Silent transfer | Progress bar with bytes, rate, ETA |

## Quick Start

### Prerequisites

- **Docker** — Docker Desktop (or a Docker daemon) must be running
- **Rust 1.88+** — `rustup install stable`

### Build from Source

```bash
git clone https://github.com/BOHICA-LABS/darkshell.git
cd darkshell
cargo build --workspace
```

The `darkshell` binary will be at `target/debug/darkshell`.

### Verify

```bash
# All upstream OpenShell commands work identically
darkshell --help
darkshell sandbox list
darkshell gateway status

# DarkShell-enhanced commands
darkshell sandbox exec my-sandbox -- git status
darkshell sandbox upload my-sandbox ./src --rsync
darkshell sandbox download my-sandbox /workspace --include "*.rs"
darkshell sandbox watch my-sandbox --type command,network
darkshell mcp add my-sandbox --name perplexity --command "npx perplexity-mcp"
darkshell sandbox create --from-blueprint factory.yaml
```

## Blueprint Example

Define your complete sandbox environment in one file:

```yaml
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: dark-factory-agent
spec:
  image: ghcr.io/bohica-labs/darkshell-factory:latest
  policy: policies/factory-agent.yaml
  providers:
    - github
    - anthropic
  mcp_servers:
    - name: perplexity
      transport: bridge
      command: npx -y @anthropic/perplexity-mcp
      env: [PERPLEXITY_API_KEY]
    - name: tally
      transport: in-sandbox
      command: /opt/mcp-servers/tally
  forwards:
    - "8080"
    - "3000"
  resources:
    cpu: "2"
    memory: "4Gi"
  upload:
    - "./src:/sandbox/workspace"
```

```bash
darkshell sandbox create --from-blueprint factory.yaml
```

## Architecture

DarkShell adds 3 new crates alongside the upstream OpenShell workspace:

```
openshell-cli ──→ darkshell-blueprint  (schema + orchestration)
              ──→ darkshell-mcp        (bridge daemon + policy + logging)
              ──→ darkshell-observe    (event streaming + filtering)
              ──→ openshell-core ──→ openshell-sandbox ──→ openshell-server
                                      (UNCHANGED except one narrow
                                       inference logging hook behind
                                       a feature flag — ADR-011)
```

All DarkShell code lives in the CLI crate or new crates. The sandbox runtime
(Landlock, seccomp, netns, proxy, OPA) is never modified.

See [docs/architecture.md](docs/architecture.md) for the full architecture document
with 11 ADRs, component map, and deployment topology.

## MCP Bridge Architecture

DarkShell bridges MCP servers into sandboxes without weakening isolation:

```
HOST                                    SANDBOX
┌─────────────────────────┐            ┌──────────────────────┐
│ MCP Bridge Daemon       │  port fwd  │ Agent (Claude Code)  │
│ ├─ Perplexity (stdio)   │───────────→│ localhost:9100       │
│ │  has PERPLEXITY_KEY   │            │                      │
│ ├─ Playwright (stdio)   │───────────→│ localhost:9101       │
│ │  has browser binary   │            │                      │
│ └─ Tool policy enforce  │            │ Tally (in-sandbox)   │
│    + tool call logging  │            │ (filesystem only)    │
└─────────────────────────┘            └──────────────────────┘
```

Credentials stay on the host. The agent sees HTTP endpoints. Bridge-layer
policy and logging provide compensating controls since port-forwarded traffic
bypasses the sandbox OPA proxy.

## Development

```bash
# Install tools
just setup

# Run full CI locally
just ci

# Run DarkShell integration tests only
just test-darkshell

# Check fork integrity
just fork-check

# Generate coverage report
just coverage

# Prepare a release
just release 0.1.0
```

## Testing

| Suite | Command | Tests |
|-------|---------|-------|
| All tests | `cargo test --workspace` | 494+ |
| DarkShell unit | `cargo test -p darkshell-mcp -p darkshell-observe -p darkshell-blueprint` | 257 |
| DarkShell integration | `cargo test -p openshell-cli --test 'darkshell_*'` | 51 |
| MCP bridge E2E | `cargo test -p darkshell-mcp --test '*'` | 13 |
| Upstream | `cargo test -p openshell-core -p openshell-sandbox -p openshell-server` | 170+ |

## Upstream Compatibility

DarkShell tracks [NVIDIA/OpenShell](https://github.com/NVIDIA/OpenShell) `main` branch:

```bash
# Check upstream drift
git fetch upstream
git log develop..upstream/main --oneline | head

# Merge upstream changes
git merge upstream/main
```

**Merge strategy:**
- Internal crate names match upstream (`openshell-*`) for clean merges
- DarkShell code lives in separate files and new crates — minimal conflict surface
- Only `openshell-cli/src/main.rs` and `openshell-cli/src/ssh.rs` have DarkShell
  additions alongside upstream code
- CI validates fork integrity on every PR

## Security Model

DarkShell inherits OpenShell's kernel-enforced security:

| Layer | Mechanism | DarkShell Impact |
|-------|-----------|-----------------|
| Filesystem | Landlock LSM (`restrict_self()` — irreversible) | Unchanged |
| Syscalls | seccomp BPF (`PR_SET_NO_NEW_PRIVS` — irreversible) | Unchanged |
| Network | Namespace + OPA-evaluated HTTP proxy | Unchanged |
| SSRF | Loopback/link-local always blocked | Unchanged |
| Credentials | Provider-based injection, never in sandbox | Extended (MCP credential isolation) |

**One exception:** A narrow observability hook in `proxy.rs` captures inference
request/response content for logging. It's behind the `darkshell-inference-log`
feature flag, uses `try_send()` (never blocks), and compiles to zero code when
disabled. See [ADR-011](docs/architecture.md#adr-011).

## Documentation

| Document | Description |
|----------|-------------|
| [KICKSTART.md](KICKSTART.md) | Upstream analysis, all 32 enhancements, fork strategy |
| [Product Brief](docs/product-brief.md) | What, who, scope, success criteria |
| [PRD](docs/prd.md) | 38 functional + 18 non-functional requirements |
| [Architecture](docs/architecture.md) | Components, interfaces, 11 ADRs, deployment topology |
| [Story Index](docs/stories/00-index.md) | 33 stories across 7 epics, dependency DAG |
| [Adversarial Spec Review](docs/adversarial-spec-review.md) | 22 spec findings (all resolved) |
| [Adversarial Code Review](docs/adversarial-code-review.md) | 64 code findings (all remediated) |

## Relationship to DarkClaw

```
DarkClaw (orchestration)
  │
  ├── Uses darkshell (if available) — enhanced features
  │     ├── Delta upload, exec, progress, blueprints
  │     ├── MCP bridge + management (factory MCP servers)
  │     └── Observability (live watch, OTel, audit logs)
  │
  └── Falls back to openshell — upstream, always works
        └── Full tar upload, SSH for commands, manual MCP setup
```

DarkClaw detects which binary is available at runtime. DarkShell enhancements are
additive — DarkClaw gains speed and observability when DarkShell is installed but
never requires it.

## License

Apache 2.0 — same as upstream. See [LICENSE](LICENSE) and [NOTICE](NOTICE).

This project is a fork of [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell).
Copyright 2025-2026 NVIDIA CORPORATION & AFFILIATES.
