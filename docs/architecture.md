---
document_type: architecture
version: "1.0"
prd_version: "1.0"
status: draft
---

# Architecture Document: DarkShell

> **Context Engineering Principle — Extended ToC Pattern:**
> Each section provides a concise summary with references to full detail. The
> Component Map (Section 3b) is machine-readable YAML for automated agent consumption.
> Structural decisions frontloaded; implementation detail in KICKSTART.md source
> analysis sections.

## 1. System Overview

DarkShell is an enhancement layer on top of NVIDIA OpenShell. It does NOT replace or
modify any OpenShell component. Instead, it adds new code paths alongside existing ones
within the same crate structure.

```
┌─────────────────────────────────────────────────────────────────┐
│  HOST                                                           │
│                                                                 │
│  ┌─────────────────────────────────────────────────────┐       │
│  │  darkshell CLI (openshell-cli crate)                │       │
│  │  ┌───────────┬───────────┬───────────┬────────────┐ │       │
│  │  │ Upstream  │ DarkShell │ DarkShell │ DarkShell  │ │       │
│  │  │ commands  │ file xfer │ mcp mgmt  │ blueprints │ │       │
│  │  │ (unchanged│ (rsync,   │ (add/list │ (create    │ │       │
│  │  │  tar,ssh) │  progress)│  /remove) │  --from)   │ │       │
│  │  └───────────┴───────────┴───────────┴────────────┘ │       │
│  └───────────────────┬─────────────────────────────────┘       │
│                      │ gRPC                                     │
│  ┌───────────────────▼─────────────────────────────────┐       │
│  │  Gateway (openshell-server crate) — UNCHANGED       │       │
│  │  Sandbox lifecycle, provider storage, policy mgmt   │       │
│  └───────────────────┬─────────────────────────────────┘       │
│                      │ k3s pod                                  │
│  ┌─────────────────────────────────────────────────────┐       │
│  │  MCP Bridge Daemon (NEW — darkshell-mcp crate)      │       │
│  │  stdio-to-HTTP proxy, credential injection,         │       │
│  │  auto port-forward into sandbox                     │       │
│  └──────────┬──────────────────────────────────────────┘       │
│             │ port forward                                      │
│─────────────┼───────────────────────────────────────────────────│
│  SANDBOX    │ (kernel boundary: Landlock + seccomp + netns)     │
│             ▼                                                   │
│  ┌─────────────────────────────────────────────────────┐       │
│  │  Sandbox Runtime (openshell-sandbox crate) — UNCHANGED      │
│  │  proxy.rs, opa.rs, landlock.rs, seccomp.rs, netns.rs        │
│  └─────────────────────────────────────────────────────┘       │
│                                                                 │
│  ┌─────────────────────────────────────────────────────┐       │
│  │  Observability Collector (NEW — darkshell-observe)  │       │
│  │  eBPF probes, log aggregation, OTel export          │       │
│  │  (runs on HOST, reads sandbox via eBPF/log tailing) │       │
│  └─────────────────────────────────────────────────────┘       │
└─────────────────────────────────────────────────────────────────┘
```

**Key principle:** The sandbox runtime code (`openshell-sandbox`) is NEVER modified.
All DarkShell code lives in the CLI crate, new crates, or host-side daemons.

## 2. Architecture Patterns

- [x] **Modular Monolith** — DarkShell extends the existing OpenShell workspace of
  crates. New capabilities are added as modules within `openshell-cli` or as new
  crates (`darkshell-mcp`, `darkshell-observe`, `darkshell-blueprint`).
- [x] **Request-Response** — CLI commands are synchronous request-response. MCP bridge
  and observability use long-lived connections.
- [x] **Hybrid sync/async** — CLI operations are async (tokio). MCP bridge daemon is
  a long-running async process. eBPF collection is async with channel-based event
  delivery.

**Layering (strictly acyclic, matching upstream):**
```
openshell-cli ──→ darkshell-blueprint ──→ openshell-core
              ──→ darkshell-mcp ─────────→ openshell-core
              ──→ darkshell-observe ─────→ openshell-core
              ──→ openshell-core ──→ openshell-sandbox ──→ openshell-server
```

`openshell-cli` depends on all three new crates. New crates depend on
`openshell-core` for shared types but NEVER on `openshell-sandbox` or
`openshell-server` (those are upstream and unchanged). `darkshell-blueprint`
also depends on `darkshell-mcp` (to orchestrate MCP bridge setup during
blueprint creation).

## 3. System Components

| ID | Component | Responsibility | Technology | Dependencies |
|----|-----------|---------------|------------|--------------|
| COMP-001 | CLI Enhancement Layer | New commands (exec, mcp, blueprint) and enhanced upload/download in openshell-cli | Rust, clap, tokio, indicatif | openshell-core, COMP-002, COMP-003, COMP-004 |
| COMP-002 | Rsync Transfer Module | Delta upload via rsync-over-SSH alongside existing tar transfer | Rust, rsync (external binary), SSH ProxyCommand | openshell-core (SSH config) |
| COMP-003 | MCP Bridge Daemon | Host-side stdio-to-HTTP proxy for MCP servers with credential isolation | Rust, tokio, hyper, JSON-RPC | openshell-core (providers, forward) |
| COMP-004 | Blueprint Engine | Parse blueprint YAML, orchestrate sandbox creation with full configuration | Rust, serde_yaml | openshell-core, COMP-003 |
| COMP-005 | Observability Collector | eBPF probes for file/process tracing, log aggregation, OTel export | Rust, aya (eBPF), opentelemetry, tracing | None (host-side, reads sandbox state) |
| COMP-006 | Progress Reporter | Wrap tar/rsync streams with progress bars showing bytes, rate, ETA | Rust, indicatif | openshell-core (transfer streams) |
| COMP-007 | Policy Tools | Validate policy YAML, test policy queries, network diagnostics | Rust, regorus (OPA) | openshell-core (policy types) |
| COMP-008 | Lifecycle Manager | Snapshots, health checks, resource limits, image save with sanitization | Rust, tar, k8s API | openshell-core (uses gateway gRPC API via client stubs in openshell-cli) |
| COMP-UPSTREAM-001 | Gateway (unchanged) | Sandbox lifecycle, provider storage, policy management | Rust, tonic (gRPC), k3s | — |
| COMP-UPSTREAM-002 | Sandbox Runtime (unchanged) | Proxy, OPA, Landlock, seccomp, netns | Rust, regorus, landlock, seccompiler | — |
| COMP-UPSTREAM-003 | SSH Transport (unchanged) | ProxyCommand tunnel, tar upload/download | Rust, openssh | — |

## 3b. Component Map (Machine-Readable)

```yaml
components:
  - id: COMP-001
    name: "CLI Enhancement Layer"
    layer: presentation
    purity: effectful-shell
    criticality: CRITICAL
    dependencies: [openshell-core, COMP-002, COMP-003, COMP-004, COMP-006]
    interfaces_provided: [IF-001, IF-002, IF-003, IF-004, IF-005]
    interfaces_consumed: [IF-010, IF-011]
    crate: openshell-cli
    files:
      - src/run.rs          # New command handlers alongside existing
      - src/ssh.rs           # New transfer functions alongside existing
      - src/main.rs          # New clap subcommands
      - src/mcp.rs           # NEW — MCP CLI commands
      - src/blueprint.rs     # NEW — Blueprint parsing and orchestration
      - src/progress.rs      # NEW — Progress bar wrapping
    requirements: [FR-001, FR-002, FR-003, FR-004, FR-005, FR-006, FR-007]

  - id: COMP-002
    name: "Rsync Transfer Module"
    layer: infrastructure
    purity: effectful-shell
    criticality: CRITICAL
    dependencies: [openshell-core]
    interfaces_provided: [IF-006]
    interfaces_consumed: [IF-010]
    crate: openshell-cli
    files:
      - src/ssh.rs           # sandbox_sync_up_rsync() alongside sandbox_sync_up()
    requirements: [FR-001]

  - id: COMP-003
    name: "MCP Bridge Daemon"
    layer: infrastructure
    purity: effectful-shell
    criticality: CRITICAL
    dependencies: [openshell-core]
    interfaces_provided: [IF-007, IF-008]
    interfaces_consumed: [IF-010, IF-011]
    crate: darkshell-mcp
    files:
      - src/lib.rs           # Public API re-exports
      - src/bridge.rs        # stdio-to-HTTP proxy daemon
      - src/registry.rs      # MCP server registration and lifecycle
      - src/credential.rs    # Credential injection from provider system
      - src/policy.rs        # Auto-generate network policy entries for MCP endpoints
    requirements: [FR-008, FR-009, FR-010, FR-011, FR-013, FR-020, FR-038]

  - id: COMP-004
    name: "Blueprint Engine"
    layer: business-logic
    purity: mixed
    criticality: CRITICAL
    dependencies: [openshell-core, COMP-003]
    interfaces_provided: [IF-009]
    interfaces_consumed: [IF-010, IF-011, IF-007]
    crate: darkshell-blueprint
    files:
      - src/lib.rs           # Public API
      - src/schema.rs        # Blueprint YAML schema + validation
      - src/orchestrator.rs  # Create sandbox from blueprint (image + policy + providers + MCP + forwards)
    requirements: [FR-015, FR-016]

  - id: COMP-005
    name: "Observability Collector"
    layer: infrastructure
    purity: effectful-shell
    criticality: MEDIUM
    dependencies: [openshell-core]  # Needs gateway API to discover sandbox PID/cgroup
    interfaces_provided: [IF-012, IF-013]
    interfaces_consumed: [IF-010]   # Queries gateway for sandbox container PID namespace
    crate: darkshell-observe
    platform_requirements:
      - "Linux kernel 5.8+ for eBPF features"
      - "CAP_BPF or root for eBPF probes"
      - "Graceful degradation to log-only on macOS/WSL/older kernels"
    files:
      - src/lib.rs           # Public API
      - src/watch.rs         # Live event stream (sandbox watch)
      - src/file_audit.rs    # eBPF/fanotify file access logging
      - src/process_trace.rs # eBPF process tree tracing
      - src/otel.rs          # OpenTelemetry metrics and trace export
      - src/baseline.rs      # Behavioral baseline computation + alerting
      - src/inference_log.rs # Inference request/response logging (receives events from proxy.rs hook)
    requirements: [FR-017, FR-018, FR-019, FR-021, FR-022, FR-023]
    # Note: FR-020 (MCP tool call logging) is in COMP-003 (bridge layer)
    # Note: FR-022 uses narrow hook in proxy.rs (ADR-011) — only sandbox crate modification

  - id: COMP-006
    name: "Progress Reporter"
    layer: presentation
    purity: pure-core
    criticality: HIGH
    dependencies: []
    interfaces_provided: [IF-014]
    interfaces_consumed: []
    crate: openshell-cli
    files:
      - src/progress.rs      # ProgressBar wrapping for tar/rsync streams
    requirements: [FR-003, FR-006]

  - id: COMP-007
    name: "Policy Tools"
    layer: business-logic
    purity: mixed
    criticality: LOW
    dependencies: [openshell-core]
    interfaces_provided: [IF-015]
    interfaces_consumed: [IF-010]
    crate: openshell-cli
    files:
      - src/policy_tools.rs  # Validate, test, net-test commands
    requirements: [FR-030, FR-031, FR-032]

  - id: COMP-008
    name: "Lifecycle Manager"
    layer: business-logic
    purity: effectful-shell
    criticality: LOW
    dependencies: [openshell-core]
    interfaces_provided: [IF-016]
    interfaces_consumed: [IF-010, IF-011]
    crate: openshell-cli
    files:
      - src/lifecycle.rs     # Snapshot, restore, health, image save
    requirements: [FR-024, FR-025, FR-026, FR-027, FR-028, FR-029]
```

## 4. Interfaces

| Interface ID | From | To | Protocol | SLA |
|-------------|------|-----|----------|-----|
| IF-001 | CLI (COMP-001) | User/DarkClaw | CLI (stdin/stdout/stderr + exit code) | Immediate response for all commands |
| IF-002 | CLI exec (COMP-001) | Sandbox | SSH (`ssh -T` via ProxyCommand) | < 100ms overhead |
| IF-003 | CLI upload (COMP-001) | Sandbox | tar-over-SSH or rsync-over-SSH | Progress reported in real-time |
| IF-004 | CLI download (COMP-001) | Sandbox | tar-over-SSH with optional filtering | Progress reported in real-time |
| IF-005 | CLI mcp (COMP-001) | MCP Bridge (COMP-003) | IPC (start/stop daemon, query status) | < 1s for lifecycle operations |
| IF-006 | Rsync Module (COMP-002) | Sandbox | rsync over SSH ProxyCommand | Same transport as upstream SSH |
| IF-007 | MCP Bridge (COMP-003) | MCP Servers | stdio (JSON-RPC) | Auto-restart within 5s on crash |
| IF-008 | MCP Bridge (COMP-003) | Sandbox Agent | HTTP (port-forwarded into sandbox) | < 10ms added latency |
| IF-009 | Blueprint Engine (COMP-004) | Gateway + MCP Bridge | gRPC (gateway) + IPC (bridge) | < 60s total creation time |
| IF-010 | Various | Gateway (COMP-UPSTREAM-001) | gRPC (proto/openshell.proto) | Gateway must be running |
| IF-011 | Various | Provider System (COMP-UPSTREAM-001) | gRPC (provider CRUD + credential retrieval) | Credentials available at sandbox start |
| IF-012 | Observability (COMP-005) | External platforms | OTLP, Splunk HEC, Datadog API | Best-effort delivery, local buffering |
| IF-013 | Observability (COMP-005) | User/DarkClaw | JSON lines stream (watch command) | < 1s event latency |
| IF-014 | Progress (COMP-006) | User terminal | indicatif ProgressBar (stderr) | Real-time update at >=1Hz |
| IF-015 | Policy Tools (COMP-007) | User | CLI output (JSON or human-readable) | Immediate for validate; exec-dependent for test |
| IF-016 | Lifecycle (COMP-008) | Gateway + Sandbox | gRPC + SSH | Snapshot time proportional to writable FS size |

## 5. Data Models

| Entity | Storage | Primary Key | Access Patterns |
|--------|---------|-------------|-----------------|
| Blueprint | YAML file on host filesystem | `name` field in YAML | Read at sandbox creation time; version-controlled in git |
| MCP Server Registration | In-memory registry in bridge daemon + PID files on host | `(sandbox_name, server_name)` | CRUD via CLI; auto-cleanup on sandbox delete |
| MCP Bridge State | PID file: `~/.config/darkshell/mcp/<sandbox>-<server>.pid` | `(sandbox, server)` | Bridge daemon reads on startup; CLI reads for status |
| Observability Events | Transient stream (not persisted by DarkShell) | timestamp + event_type + sandbox_id | Streamed to watch command or OTel exporter |
| Snapshot | Tar archive on host: `~/.config/darkshell/snapshots/<sandbox>/<name>.tar` | `(sandbox, snapshot_name)` | Write on snapshot; read on restore; list on query |
| Behavioral Baseline | Rolling statistics in memory (COMP-005) | `sandbox_id` | Updated on every event; queried for anomaly detection |

### Blueprint Schema

```yaml
# darkshell-blueprint.yaml
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: string                    # Required. Blueprint identifier.
  description: string             # Optional. Human-readable description.
spec:
  image: string                   # Required. Container image reference.
  policy: string                  # Optional. Path to policy YAML file.
  providers:                      # Optional. List of provider names to attach.
    - string
  mcp_servers:                    # Optional. MCP servers to connect.
    - name: string                # Required. Server identifier.
      transport: bridge | in-sandbox | streamable-http
      command: string             # Required for bridge/in-sandbox. Server launch command.
      env:                        # Optional. Environment variable names for credentials.
        - string
      url: string                 # Required for streamable-http. Server endpoint URL.
  forwards:                       # Optional. Port forwards.
    - "[bind:]port"
  resources:                      # Optional. Resource limits.
    cpu: string                   # e.g., "2"
    memory: string                # e.g., "4Gi"
  upload:                         # Optional. Files to upload on creation.
    - "local:remote"
```

### MCP Bridge Registration

```yaml
# ~/.config/darkshell/mcp/<sandbox>-<server>.yaml
sandbox: string
server_name: string
transport: bridge | in-sandbox | streamable-http
command: string
env_keys: [string]
bridge_pid: int
forwarded_port: int
policy_entry_added: bool
status: running | stopped | error
```

## 6. Integration Contracts

| System | Protocol | Authentication | Error Handling |
|--------|----------|---------------|----------------|
| OpenShell Gateway | gRPC (proto/openshell.proto) | mTLS or bearer token (unchanged) | Gateway unavailable → retry with exponential backoff, surface error with `darkshell doctor` remediation |
| SSH Transport | SSH over ProxyCommand tunnel | Gateway-mediated (no direct SSH keys) | Connection failure → check gateway status, report which hop failed (DNS? gateway? sandbox?) |
| rsync (P1) | rsync over SSH ProxyCommand | Same SSH auth as upstream | rsync binary absent → warn, fall back to tar with clear message |
| MCP Servers (stdio) | stdin/stdout JSON-RPC | Credentials injected by bridge from providers | Server crash → auto-restart (5s backoff, max 3 retries), log each restart |
| MCP Servers (Streamable HTTP) | HTTPS through sandbox proxy | OAuth/API key via provider → OPA policy evaluation | Connection denied → report policy rule that blocked, suggest `policy set` fix |
| Container Registry | OCI/Docker protocol | Registry credentials | Pull failure → report registry, image, tag, auth status, suggest `docker login` |
| OpenTelemetry (P26) | OTLP gRPC or HTTP | API key (platform-specific) | Export failure → buffer locally (bounded queue), retry, alert on persistent failure |
| Git (P17 GitOps) | HTTPS or SSH | GITHUB_TOKEN | Invalid policy YAML → reject, keep last-known-good, alert operator |

## 7. Non-Functional Architecture

| NFR | Target | Architecture Decision | Validation |
|-----|--------|----------------------|-----------|
| NFR-001: Delta upload < 2s | rsync for delta, tar for full | rsync-over-SSH uses same ProxyCommand. Fall back to tar if rsync absent. | Benchmark suite across 100MB-5GB projects |
| NFR-002: Exec < 100ms (steady-state) | SSH ControlMaster multiplexing | First exec ~200ms (full handshake); subsequent < 20ms via reused connection. ControlPersist=600s. See ADR-009. | 100-run benchmark: measure first vs. subsequent exec latency |
| NFR-003: MCP bridge < 10ms | In-process HTTP proxy | Bridge runs as tokio async task; JSON-RPC parsed in-memory; no serialization to disk. | Latency comparison: direct MCP vs. through bridge |
| NFR-006: Zero security weakening | All code outside sandbox boundary except one read-only hook | DarkShell code lives in CLI crate and host-side daemons. Sandbox runtime security code (landlock.rs, seccomp.rs, netns.rs, opa.rs) is NEVER modified. proxy.rs has one narrow observability hook (ADR-011) behind a feature flag — read-only, no behavioral change. | Audit: `git diff` for sandbox crate shows ONLY the inference hook. Hook is behind feature flag and compiles to no-op when disabled. |
| NFR-007: Credential isolation | Bridge injects, agent can't read | Bridge subprocess gets env vars from provider API. Port-forwarded HTTP endpoint carries no credentials — it's just a proxy. Agent sees HTTP responses, not raw keys. | Test: exec into sandbox, attempt to read bridge env vars |
| NFR-009: 100% backward compat | No modified upstream semantics | All enhancements are additive: new files, new functions, new clap subcommands. Existing command handlers untouched except to add optional flags. | Run upstream `cargo test` against darkshell binary |
| NFR-010: < 1hr merge time | Minimal diff surface with upstream | Keep internal crate names matching upstream. New code in separate files. Avoid modifying existing functions. | Track merge time per upstream release |
| NFR-011: Bridge auto-recovery | Supervised subprocess | Bridge daemon monitors MCP server subprocess. On SIGCHLD/pipe-close, restart with backoff (1s, 2s, 4s, max 3 retries). | Kill MCP server process, verify restart within 5s |
| NFR-014: Actionable errors | Domain-specific error types | Use `thiserror` for DarkShell-specific error enum. Every variant includes what, why, and fix suggestion. | Review every error path for context + remediation |

## 8. Architecture Decision Records

### ADR-001: Enhancements Live in CLI Crate and New Crates, Not Sandbox Runtime

- **Status:** Accepted (with one exception — see ADR-011)
- **Context:** DarkShell must preserve OpenShell's security model and maintain upstream
  merge compatibility. The sandbox runtime (`openshell-sandbox`) contains the
  kernel-enforced security code (Landlock, seccomp, netns, proxy, OPA).
- **Decision:** All DarkShell enhancements are implemented either in the CLI crate
  (`openshell-cli`) or in new crates (`darkshell-mcp`, `darkshell-observe`,
  `darkshell-blueprint`). The `openshell-sandbox` and `openshell-server` crates are
  not modified, **except** for a single, narrow observability hook in `proxy.rs`
  for inference request/response logging (see ADR-011).
- **Consequences:**
  - Upstream merges for sandbox/server crates are trivial (minimal conflict surface)
  - Security audit scope is reduced (only need to verify new code doesn't bypass boundaries)
  - Some features (file access audit) require host-side eBPF instead of sandbox-side instrumentation
  - MCP bridge runs on host, not in sandbox, which is actually more secure (credentials stay out)
  - The proxy.rs hook is the only upstream merge friction point in the sandbox crate

### ADR-002: MCP Bridge Runs on Host, Not in Sandbox

- **Status:** Accepted
- **Context:** stdio MCP servers need credentials (API keys) and often need network
  access to external APIs. Running them inside the sandbox would require either
  weakening Landlock (to write to system dirs) or weakening network policy (to allow
  arbitrary endpoints).
- **Decision:** MCP bridge daemon runs on the host. It spawns MCP server subprocesses
  with host credentials, exposes them as HTTP endpoints, and port-forwards those
  endpoints into the sandbox. The agent in the sandbox connects to `localhost:<port>`.
- **Consequences:**
  - Credentials never enter the sandbox — strongest isolation
  - Network policy only needs to allow the forwarded localhost port
  - MCP server crashes don't affect sandbox stability
  - Adds host-side process management complexity
  - Filesystem-only MCP servers (e.g., Tally) can optionally run in-sandbox (P22)

### ADR-003: Rsync with Tar Fallback for Delta Uploads

- **Status:** Accepted
- **Context:** OpenShell uses tar-over-SSH for all uploads. This is simple but
  transfers the entire workspace every time. rsync would transfer only changed files.
- **Decision:** Add `--rsync` flag to upload. Detect rsync availability in sandbox.
  If unavailable, fall back to tar with a warning. Same SSH ProxyCommand transport.
- **Consequences:**
  - 15x+ speedup for typical 1-file changes on large workspaces
  - Requires rsync in sandbox base image (or installed at image build time)
  - Fallback ensures upload always works, even on minimal images
  - No new network paths — same SSH tunnel as tar

### ADR-004: Blueprint as Single Source of Truth for Sandbox Configuration

- **Status:** Accepted
- **Context:** Setting up a sandbox requires 5+ commands: create, upload, provider
  attach, policy set, forward start, MCP bridge start. This is error-prone and
  not version-controllable.
- **Decision:** Introduce blueprint YAML that declares the complete sandbox
  configuration. `darkshell sandbox create --from blueprint.yaml` orchestrates
  all setup in a single command.
- **Consequences:**
  - Sandbox configuration is declarative, version-controlled, auditable
  - Blueprints can be shared across teams and stored in git
  - Validation happens before creation (fail fast with actionable errors)
  - More complex CLI implementation (must orchestrate multiple subsystems)
  - Blueprint schema must be forward-compatible for future enhancements

### ADR-005: Observability via Host-Side eBPF, Not Sandbox Instrumentation

- **Status:** Accepted
- **Context:** Full observability requires seeing file access, process spawning, and
  syscall patterns inside the sandbox. Two approaches: instrument the sandbox runtime
  or observe from the host via eBPF.
- **Decision:** Use host-side eBPF probes scoped to the sandbox's PID/network
  namespace. The sandbox runtime code is never modified.
- **Consequences:**
  - No changes to upstream sandbox code
  - eBPF requires CAP_BPF on the host (usually available to root/Docker)
  - Observation is read-only — cannot affect sandbox behavior
  - Performance overhead is minimal (eBPF is kernel-optimized)
  - Requires Linux kernel 5.8+ for full eBPF features (matches OpenShell's Linux requirement)

### ADR-006: Three New Crates, Not One Mega-Crate

- **Status:** Accepted
- **Context:** DarkShell adds significant new functionality. Should it be one crate
  or multiple?
- **Decision:** Three new crates:
  - `darkshell-mcp` — MCP bridge daemon and server management
  - `darkshell-observe` — Observability collector, eBPF, OTel export
  - `darkshell-blueprint` — Blueprint schema parsing and orchestration
- **Consequences:**
  - Clear separation of concerns
  - Each crate can be compiled and tested independently
  - `darkshell-observe` can be optional (feature-flagged) for minimal builds
  - Dependency graph remains acyclic
  - More crates to manage during upstream merges (but they don't touch upstream crates)

### ADR-007: Sandbox Image Save Requires Mandatory Credential Stripping

- **Status:** Accepted
- **Context:** Saving a running sandbox as a new image (P33) could capture credentials
  in environment variables, temp files, or agent-modified files.
- **Decision:** `darkshell sandbox image save` is gated by:
  1. Mandatory `--confirm` flag (no accidental saves)
  2. Automated stripping of all environment variables
  3. Removal of known credential paths (`/tmp`, provider injection points)
  4. Warning listing all removed items
- **Consequences:**
  - Prevents accidental credential leakage in saved images
  - Some legitimate env vars are also stripped (operator must re-inject)
  - Stripping is best-effort — unknown credential locations may be missed
  - Operator approval creates friction (intentional)

### ADR-008: No Modification to Existing Upstream Command Semantics

- **Status:** Accepted
- **Context:** DarkClaw needs to detect whether `darkshell` or `openshell` is
  installed and use enhanced features when available. Existing commands must work
  identically to prevent breaking upstream-compatible workflows.
- **Decision:** All enhancements are new subcommands (`sandbox exec`, `mcp add`,
  `sandbox watch`) or new optional flags (`--rsync`, `--dry-run`, `--include`).
  Existing command handlers are not modified. Default behavior is unchanged.
- **Consequences:**
  - `darkshell sandbox upload <name> <local>` behaves identically to `openshell sandbox upload`
  - `darkshell sandbox upload <name> <local> --rsync` activates delta transfer
  - DarkClaw can feature-detect by checking `darkshell --version` or trying enhanced commands
  - Some enhancements (progress bar) are added to existing commands as non-breaking visual additions

### ADR-009: SSH ControlMaster for Exec Performance

- **Status:** Accepted
- **Context:** NFR-002 targets < 100ms exec overhead. Each `ssh -T` invocation
  performs a full SSH handshake (~200-500ms). Without connection reuse, the target
  is physically impossible.
- **Decision:** Use SSH ControlMaster/ControlPersist to maintain a persistent SSH
  connection per sandbox. First exec to a sandbox pays full handshake cost (~200ms).
  Subsequent exec commands reuse the multiplexed connection (< 20ms overhead).
  ControlSocket stored at `~/.config/darkshell/ssh/ctrl-%r@%h:%p`.
  ControlPersist set to 600s (10 minutes idle timeout).
- **Consequences:**
  - First exec is ~200ms; subsequent are < 20ms (meets NFR-002 for steady-state)
  - Persistent SSH connections consume a file descriptor per sandbox
  - ControlSocket must be cleaned up when sandbox is deleted (added to FR-038)
  - DarkClaw benefits most (hundreds of exec calls reuse one connection)

### ADR-011: Narrow Observability Hook in proxy.rs for Inference Logging

- **Status:** Accepted
- **Context:** Full inference observability requires seeing prompt content, model
  responses, and token counts. The privacy router in `proxy.rs` terminates TLS and
  inspects HTTP at L7 — it's the only place where inference content is visible in
  cleartext. eBPF on the host sees encrypted bytes on the wire, not prompts.
  Gateway-level logging only captures routing metadata, not content. Without this
  hook, we cannot detect prompt injection, data exfiltration through inference, or
  audit agent reasoning chains.
- **Decision:** Add a single, narrowly scoped observability hook in
  `openshell-sandbox/src/proxy.rs` at the inference routing point. The hook:
  1. Is a single function call: `inference_observer.on_request(&req, &resp)` (or
     equivalent channel send)
  2. Is behind a compile-time feature flag (`darkshell-inference-log`)
  3. Does NOT modify any request/response content or routing behavior
  4. Does NOT affect policy evaluation, TLS termination, or SSRF protection
  5. Emits a structured event (prompt, response, model, provider, latency, token count)
     to a channel that `darkshell-observe` consumes
  6. Is clearly demarcated with `// BEGIN DARKSHELL HOOK` / `// END DARKSHELL HOOK`
     markers for upstream merge management
  7. When the feature flag is disabled, compiles to a no-op (zero runtime cost)
- **Consequences:**
  - This is the ONLY modification to `openshell-sandbox` — all other sandbox code
    remains upstream-identical
  - Upstream merges for `proxy.rs` require manual attention at the hook point (~2 lines)
  - Feature flag ensures upstream builds are unaffected
  - Full inference content visibility enables prompt injection detection and
    data exfiltration auditing
  - Configurable redaction in `darkshell-observe/inference_log.rs` prevents
    sensitive prompt data from appearing in logs (strip PII, hash fields, truncate)
  - If upstream adds their own inference logging hook, we can migrate to it and
    remove ours

### ADR-010: MCP Bridge Traffic Is Outside Sandbox Proxy Scope

- **Status:** Accepted
- **Context:** Port-forwarded MCP bridge traffic enters the sandbox via localhost,
  bypassing the HTTP CONNECT proxy and OPA policy evaluation. This is inherent to
  how SSH -L port forwarding works within network namespaces.
- **Decision:** Accept that MCP bridge traffic is not evaluated by the sandbox proxy.
  Compensating controls:
  1. Bridge-layer tool policy (FR-011) — deny-by-default at bridge, not proxy
  2. MCP tool call logging (FR-020) — full audit trail at bridge layer
  3. Credential isolation (FR-013) — agent never sees raw credentials
  4. Bridge daemon is DarkShell-managed, not agent-managed — agent cannot modify bridge
- **Consequences:**
  - MCP tool calls are audited and policy-evaluated, but at bridge layer, not kernel layer
  - A compromised agent could send arbitrary HTTP to the forwarded port, but only
    reach the specific MCP server behind that port (not arbitrary endpoints)
  - FR-011 must be implemented as Should priority (promoted from Nice)
  - Document this explicitly in security documentation

## 9. Deployment Topology

### Local Development

```
Developer Workstation
├── darkshell CLI binary
├── MCP bridge daemon (auto-started by CLI)
├── Observability collector (optional, started by `sandbox watch`)
└── Docker
    └── OpenShell Gateway (k3s)
        └── Sandbox Pod(s)
            ├── openshell-sandbox supervisor (unchanged)
            └── Agent process (Claude Code, Codex, etc.)
```

### DarkClaw Factory

```
Factory Host
├── DarkClaw orchestration engine
├── darkshell CLI (invoked by DarkClaw)
├── MCP bridge daemon (managed by DarkClaw via CLI)
├── Observability collector (streams to DarkClaw dashboard)
└── Docker
    └── OpenShell Gateway (k3s)
        └── Sandbox Pod(s)
            ├── openshell-sandbox supervisor (unchanged)
            └── Factory agent (runs VSDD pipeline phases)
```

### Crate Layout

```
DarkShell/
├── crates/
│   ├── openshell-cli/              # UPSTREAM + DarkShell enhancements
│   │   └── src/
│   │       ├── main.rs             # Upstream + new clap subcommands
│   │       ├── run.rs              # Upstream + new command handlers
│   │       ├── ssh.rs              # Upstream + rsync, exec functions
│   │       ├── mcp.rs              # NEW — MCP CLI commands
│   │       ├── blueprint.rs        # NEW — Blueprint create orchestration
│   │       ├── progress.rs         # NEW — Progress bar wrapping
│   │       ├── policy_tools.rs     # NEW — Policy validate/test commands
│   │       └── lifecycle.rs        # NEW — Snapshot, health, image save
│   │
│   ├── openshell-core/             # UPSTREAM — unchanged
│   ├── openshell-sandbox/          # UPSTREAM — unchanged (NEVER MODIFY)
│   ├── openshell-server/           # UPSTREAM — unchanged
│   ├── openshell-router/           # UPSTREAM — unchanged
│   │
│   ├── darkshell-mcp/              # NEW — MCP bridge daemon
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── bridge.rs           # stdio-to-HTTP proxy
│   │       ├── registry.rs         # Server registration + lifecycle
│   │       ├── credential.rs       # Credential injection from providers
│   │       └── policy.rs           # Auto-generate network policy entries
│   │
│   ├── darkshell-observe/          # NEW — Observability collector
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── watch.rs            # Live event stream
│   │       ├── file_audit.rs       # eBPF file access logging
│   │       ├── process_trace.rs    # eBPF process tree tracing
│   │       ├── otel.rs             # OpenTelemetry export
│   │       ├── baseline.rs         # Behavioral baseline + alerting
│   │       └── inference_log.rs    # Receives events from proxy.rs hook via channel
│   │
│   └── darkshell-blueprint/        # NEW — Blueprint engine
│       └── src/
│           ├── lib.rs
│           ├── schema.rs           # Blueprint YAML schema + validation
│           └── orchestrator.rs     # Sandbox creation orchestration
│
├── proto/                          # UPSTREAM — unchanged
├── docs/
│   ├── product-brief.md
│   ├── prd.md
│   └── architecture.md
├── KICKSTART.md
├── CLAUDE.md
└── SOUL.md
```

### Build Configuration

```toml
# Root Cargo.toml — workspace members
[workspace]
members = [
    "crates/openshell-cli",
    "crates/openshell-core",
    "crates/openshell-sandbox",
    "crates/openshell-server",
    "crates/openshell-router",
    "crates/darkshell-mcp",
    "crates/darkshell-observe",
    "crates/darkshell-blueprint",
]
```

```toml
# crates/openshell-cli/Cargo.toml — feature flags for optional DarkShell components
[features]
default = ["full"]
mcp = ["dep:darkshell-mcp"]
observe = ["dep:darkshell-observe"]
blueprint = ["dep:darkshell-blueprint"]
full = ["mcp", "observe", "blueprint"]
```

### Upstream Merge Strategy

1. `git fetch upstream` — get latest NVIDIA/OpenShell changes
2. `git merge upstream/main` into `develop`
3. Conflicts only possible in `openshell-cli/src/main.rs` (new clap commands)
   and `openshell-cli/src/ssh.rs` (new transfer functions)
4. Upstream crates (`openshell-sandbox`, `openshell-server`, `openshell-core`) merge
   cleanly because we never modify them
5. New crates (`darkshell-*`) have no upstream counterpart — no conflicts
