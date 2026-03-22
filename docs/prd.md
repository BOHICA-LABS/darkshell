---
document_type: prd
version: "1.0"
status: draft
created: 2026-03-22
last_validated: 2026-03-22
consistency_score: 0.0
---

# Product Requirements Document: DarkShell

> **Context Engineering Principle — Extended ToC Pattern:**
> Each section provides a concise summary with references to full detail in
> KICKSTART.md. Frontloaded: security invariant, upstream compatibility constraint,
> and the 7 Must-priority capabilities. Full enhancement detail in KICKSTART.md
> sections P1–P34.

## 1. Problem Definition

### Problem Statement

AI agent factory workflows (DarkClaw/Dark Factory) require hundreds of file transfers,
command executions, and MCP tool connections per factory run inside OpenShell sandboxes.
OpenShell's current developer experience — full tar re-uploads for every change,
SSH session overhead for every command, no MCP management, and no visibility into
agent behavior — makes factory-scale automation impractically slow and operationally
blind. A 2GB workspace with 1 file changed takes 30+ seconds to re-upload; a single
`git status` requires 200-500ms SSH session setup; MCP servers require manual proxy
and policy configuration; and operators cannot see what agents are doing without SSH
into the sandbox.

### Affected Personas

| Persona | Description | Volume | Pain Level |
|---------|-------------|--------|------------|
| DarkClaw orchestration engine | Automated system that pushes code, runs builds, and connects tools inside sandboxes | 100s of operations/run | Critical — every operation bottlenecked |
| Factory operators | Engineers monitoring and troubleshooting factory runs | 1-5 per team | High — blind to agent behavior, manual log collection |
| AI agent developers | Engineers building and testing agents that run inside sandboxes | 10-50 per organization | Medium — sandbox setup is 5+ manual commands |

### Impact Metrics

| Metric | Current | Target | Measurement Method |
|--------|---------|--------|-------------------|
| Upload time (1-file change, 2GB project) | 30+ seconds (full tar) | < 2 seconds (rsync delta) | Wall clock time, `darkshell sandbox upload --rsync` |
| Command execution overhead | 200-500ms (SSH session setup) | < 100ms (exec) | Wall clock time, `darkshell sandbox exec` |
| MCP server setup time | 10+ minutes (manual proxy + policy + forward) | < 30 seconds (single CLI command) | Wall clock time, `darkshell mcp add` |
| Sandbox creation from blueprint | 5+ commands, 3+ minutes | 1 command, < 60 seconds | Wall clock time, `darkshell sandbox create --from blueprint.yaml` |
| Agent behavior visibility | 0% without SSH | 100% (network, file, process, MCP, inference) | Coverage of observable action types |
| Security mechanisms weakened | N/A | 0 | Audit of Landlock/seccomp/netns/OPA/SSRF |

### Constraints

- **Technical:** Rust 1.85+, Edition 2024. Internal crate names must match upstream
  (`openshell-cli`, `openshell-core`, `openshell-sandbox`, `openshell-server`) for
  merge compatibility. Binary renamed to `darkshell`.
- **Security (INVARIANT):** No enhancement may weaken or bypass any kernel-enforced
  security mechanism. Landlock `restrict_self()` is irreversible. seccomp
  `PR_SET_NO_NEW_PRIVS` is irreversible. Network namespace isolation is immutable
  after creation. SSRF protection always blocks loopback/link-local/RFC1918.
- **Upstream:** All existing OpenShell commands must work identically. Enhancements
  are new commands or new flags only. Periodic upstream merges must succeed.
- **License:** Apache 2.0 (same as upstream). Fork attribution in README and NOTICE.

### Out of Scope

- Modifying OpenShell's security model (Landlock, seccomp, netns, OPA, SSRF)
- Runtime tool installation into Landlock-protected directories (rejected: P32, P35)
- Multi-tenancy and RBAC (enterprise feature, upstream's responsibility)
- General-purpose application runtime (DarkShell is for AI agent sandboxes)
- GPU scheduling across sandboxes (k3s/k8s territory)
- Community MCP server vetting/scanning (upstream ecosystem concern)
- Compliance certifications (NVIDIA's responsibility)

## 2. Solution Vision

### High-Level Approach

DarkShell wraps OpenShell's existing security runtime with an enhanced developer
experience layer. All enhancements operate in one of three zones:

1. **Client-side** (CLI on host) — progress bars, dry-run, rsync invocation
2. **Host-side** (bridge daemons, adapters) — MCP bridge, observability exporters
3. **Read-only observation** (eBPF, log tailing) — file audit, process tracing

No enhancement modifies the sandbox security boundary. The gateway, proxy, Landlock,
seccomp, and network namespace code remain untouched upstream code.

Full detail: KICKSTART.md "Security Analysis of Enhancements"

### Core Capabilities

| ID | Capability | Priority | User Value | Success Metric |
|----|-----------|----------|------------|----------------|
| CAP-001 | Fast file transfer (delta upload, multi-upload, progress, filtering) | Must | 15x faster uploads, visible progress, selective downloads | < 2s delta upload, progress bar on all transfers |
| CAP-002 | Direct command execution | Must | Eliminate SSH session overhead | < 100ms per command |
| CAP-003 | MCP server management (bridge, CLI, credential isolation) | Must | One-command MCP setup, credentials stay on host | < 30s MCP server connected to sandbox |
| CAP-004 | Declarative sandbox blueprints | Must | Single-file sandbox definition, one-command creation | < 60s from blueprint to ready sandbox |
| CAP-005 | Sandbox observability (live watch, audit logs, tracing) | Should | Real-time visibility into agent behavior | 100% action coverage without SSH |
| CAP-006 | Sandbox lifecycle (snapshots, health, resource limits) | Nice | Checkpoint before risky operations, prevent resource exhaustion | Snapshot/restore cycle < 30s for 1GB workspace |
| CAP-007 | Operational tooling (policy validation, GitOps, log export) | Nice | Catch misconfigurations before they matter | Zero silent policy failures |

## 3. Functional Requirements

### File Transfer

| ID | Actor | Action | Outcome | Constraints | Priority |
|----|-------|--------|---------|-------------|----------|
| FR-001 | Operator | `darkshell sandbox upload <name> <local> [dest] --rsync` | Only changed files transferred via rsync-over-SSH | Same ProxyCommand transport; fall back to tar if rsync unavailable in sandbox | Must |
| FR-002 | Operator | `darkshell sandbox create --upload <spec1> --upload <spec2>` | Multiple directories uploaded during sandbox creation | Backward compatible — single `--upload` still works | Must |
| FR-003 | Operator | `darkshell sandbox upload <name> <local>` (default) | Progress bar shows bytes transferred, rate, ETA | Use `indicatif` crate; calculate total from local file sizes before transfer | Must |
| FR-004 | Operator | `darkshell sandbox download <name> <remote> --include <pattern>` | Only matching files downloaded | Server-side tar filtering; client-side same unpack | Should |
| FR-005 | Operator | `darkshell sandbox upload <name> <local> --dry-run` | Display added/modified/deleted files without transferring | Compare local hashes against sandbox hashes via exec | Should |
| FR-006 | Operator | `darkshell sandbox download <name> <remote>` (default) | Progress bar shows bytes received, rate, ETA | Wrap tar stream in counting reader | Should |

### Execution

| ID | Actor | Action | Outcome | Constraints | Priority |
|----|-------|--------|---------|-------------|----------|
| FR-007 | Operator/DarkClaw | `darkshell sandbox exec <name> [--timeout <secs>] -- <command>` | stdout, stderr, and exit code returned without interactive SSH session | Non-interactive `ssh -T`; same ProxyCommand transport. Default timeout: 300s for programmatic use. `--timeout 0` disables for interactive use. Timeout configurable per-blueprint. | Must |

### MCP Integration

| ID | Actor | Action | Outcome | Constraints | Priority |
|----|-------|--------|---------|-------------|----------|
| FR-008 | Operator | `darkshell mcp add <sandbox> --name <server> --command <cmd> --env <KEY>` | MCP bridge daemon started on host, port forwarded into sandbox, network policy auto-configured | Credentials stay on host; agent sees HTTP endpoint. **Note:** port-forwarded traffic bypasses sandbox proxy (localhost not routed through OPA). Bridge-layer policy evaluation (FR-011) and MCP tool call logging (FR-020) are compensating controls. | Must |
| FR-009 | Operator | `darkshell mcp list <sandbox>` | Display connected MCP servers, transport type, connection status | Show bridge PID, forwarded port, health | Must |
| FR-010 | Operator | `darkshell mcp remove <sandbox> --name <server>` | Bridge stopped, port forward removed, network policy entry removed | Clean teardown of all resources | Must |
| FR-011 | Operator | Configure `allowed_tools` / `denied_tools` in policy YAML for MCP endpoints | Only specified MCP tools accessible to agent | Enforce at bridge layer via request inspection. **Required** because port-forwarded MCP traffic bypasses sandbox OPA proxy — bridge-layer policy is the only enforcement point for MCP tool calls. | Should |
| FR-012 | Operator | Configure MCP server with `transport: in-sandbox` in blueprint | MCP server runs inside sandbox as subprocess, inherits all sandbox restrictions | Only for filesystem-only MCP servers (no external network/credentials needed) | Should |
| FR-013 | System | MCP bridge injects credentials from provider system into MCP server subprocess | MCP server has API keys; agent process does not | Credentials flow through gateway provider API, never visible to agent | Should |
| FR-014 | Agent | Connect to remote MCP server via Streamable HTTP transport | Standard HTTP connection through existing proxy, OPA evaluates like any endpoint | Network policy allowlists the MCP server endpoint | Should |

### Sandbox Blueprints

| ID | Actor | Action | Outcome | Constraints | Priority |
|----|-------|--------|---------|-------------|----------|
| FR-015 | Operator | `darkshell sandbox create --from blueprint.yaml` | Sandbox created with image, policy, providers, MCP servers, port forwards, resource limits from single YAML | All referenced resources must exist (image pullable, providers created, policy valid) | Must |
| FR-016 | Operator | Define blueprint YAML with `mcp_servers`, `providers`, `forwards`, `resources` sections | Declarative, version-controlled sandbox definition | Schema-validated before creation; error messages reference specific YAML line | Must |

### Observability

| ID | Actor | Action | Outcome | Constraints | Priority |
|----|-------|--------|---------|-------------|----------|
| FR-017 | Operator | `darkshell sandbox watch <name>` | Real-time JSON lines stream of commands, files, network requests, policy decisions | Long-poll or SSE; filterable by event type | Should |
| FR-018 | System | Export OTel metrics and traces from gateway and proxy | Policy decisions/sec, action types, latency histograms available in Prometheus/Grafana/Jaeger | Instrument with `opentelemetry` crate; export via OTLP | Nice |
| FR-019 | System | Log every successful file read/write/delete inside sandbox | Structured log: path, operation, process, timestamp | eBPF/fanotify; minimal performance impact | Nice |
| FR-020 | System | Log every MCP tool invocation through bridge | Structured log: server, tool name, arguments, response summary, duration | Captured at bridge layer (host-side) | Should |
| FR-021 | System | Track every process spawned inside sandbox | Log: parent->child, command line, exit code, duration | eBPF process events scoped to sandbox PID namespace | Nice |
| FR-022 | System | Log inference requests/responses at privacy router inside sandbox via narrow observability hook in proxy.rs | Structured log: prompt content, model provider, response content, token counts, latency. Configurable redaction (strip PII, hash sensitive fields, truncate to N tokens). | **Exception to ADR-001:** requires a minimal, clearly demarcated hook in openshell-sandbox/proxy.rs. See ADR-011. Hook is a single function call at the inference routing point — not a behavioral change. Must be isolated for upstream merge management. | Nice |
| FR-023 | System | Establish behavioral baselines and alert on deviations | Rolling baseline of network/file/command patterns; alert when current exceeds threshold | Requires P17-P22 data collection | Nice |

### Sandbox Lifecycle

| ID | Actor | Action | Outcome | Constraints | Priority |
|----|-------|--------|---------|-------------|----------|
| FR-024 | Operator | `darkshell sandbox snapshot <name>` | Writable filesystem tarred and stored on host | Does not capture Landlock/seccomp state (kernel, not filesystem) | Nice |
| FR-025 | Operator | `darkshell sandbox restore <name> <snapshot>` | Writable filesystem restored from snapshot | Sandbox must be stopped or recreated | Nice |
| FR-026 | Operator | `darkshell sandbox health <name>` | Structured JSON: CPU, memory, disk, process count, network, gateway status | Via exec; no new sandbox capabilities | Nice |
| FR-027 | Operator | `darkshell sandbox create --cpu-limit 2 --memory-limit 4Gi` | Resource limits applied to k3s pod spec | Maps to k8s requests/limits | Nice |
| FR-028 | System | Rotate provider credentials on running sandbox | New credentials injected without sandbox deletion | Extend provider system with refresh API | Nice |
| FR-029 | Operator | `darkshell sandbox image save <name> <tag> --confirm` | Running sandbox committed as new container image | **Mandatory:** strip env vars, clear provider creds, scrub temp files. Requires `--confirm` | Nice |

### Operational Tooling

| ID | Actor | Action | Outcome | Constraints | Priority |
|----|-------|--------|---------|-------------|----------|
| FR-030 | Operator | `darkshell policy validate <file>` | Policy YAML validated without applying; errors with line numbers | Load into regorus engine, report issues | Nice |
| FR-031 | Operator | `darkshell policy test <name> --host <h> --port <p> --binary <b>` | Report allow/deny + which policy rule matched | Evaluate against current sandbox policy | Nice |
| FR-032 | Operator | `darkshell sandbox net-test <name> --host <h> --port <p>` | Diagnostic: DNS, proxy eval, TLS handshake, HTTP response | Via exec inside sandbox | Nice |
| FR-033 | Operator | `darkshell sandbox logs <name> --export <path>` | Gateway + proxy + agent logs aggregated to local file | Structured JSON output | Nice |
| FR-034 | System | Watch git repo for policy YAML changes, auto-apply to sandboxes | GitOps reconciliation for network policies | Only hot-reloadable fields (network, inference) | Nice |
| FR-035 | System | Export audit logs to SIEM platforms via pluggable adapters | Splunk, Datadog, Grafana, OpenSearch adapters | Standard log driver integration | Nice |
| FR-036 | Operator | `darkshell sandbox watch <name>` streams events; optional `--webhook <url>` | Events POST'd to webhook URL for CI/CD integration | JSON payload with event type, sandbox, timestamp | Nice |
| FR-037 | DarkClaw | Coordinate policies and lifecycle across multiple sandboxes | Fleet-level operations (apply policy to all, status of all) | Each sandbox retains own isolation | Nice |
| FR-038 | System | When sandbox is deleted, clean up all associated MCP bridge daemons, PID files, port forwards, and network policy entries | No orphaned resources after sandbox deletion | Partial cleanup failure logged but does not block sandbox deletion | Must |

## 4. Non-Functional Requirements

| ID | Category | Requirement | Target | Validation Method |
|----|----------|-------------|--------|-------------------|
| NFR-001 | Performance | Delta upload latency for single-file change in 2GB workspace | < 2 seconds | Benchmark: rsync 1-file change over ProxyCommand SSH |
| NFR-002 | Performance | Exec command overhead (excluding command runtime) | < 100ms | Benchmark: `darkshell sandbox exec <name> -- echo ok` |
| NFR-003 | Performance | MCP bridge request latency overhead | < 10ms added to MCP tool call | Benchmark: bridge round-trip vs. direct MCP call |
| NFR-004 | Performance | Blueprint sandbox creation (image already cached) | < 60 seconds to Ready phase | Benchmark: `darkshell sandbox create --from blueprint.yaml` |
| NFR-005 | Performance | Observability overhead on sandbox throughput | < 5% impact on agent operations | Benchmark: agent workload with/without observability enabled |
| NFR-006 | Security | No kernel-enforced security mechanism weakened | 0 mechanisms weakened | Audit: verify Landlock, seccomp, netns, OPA, SSRF unchanged |
| NFR-007 | Security | MCP credentials never visible to agent process | 0 credentials leaked to agent | Test: agent cannot read bridge daemon env vars or provider secrets |
| NFR-008 | Security | Sandbox image save strips all sensitive data | 0 credentials in saved image | Test: inspect saved image for env vars, provider data, temp files |
| NFR-009 | Compatibility | All upstream OpenShell commands work identically | 100% backward compatibility | Run upstream test suite against darkshell binary |
| NFR-010 | Compatibility | Upstream merge succeeds without manual conflict resolution | < 1 hour merge time per release | Track merge time for each upstream release |
| NFR-011 | Reliability | MCP bridge daemon auto-recovers from MCP server crashes | Restart within 5 seconds | Test: kill MCP server process, verify bridge restarts it |
| NFR-012 | Reliability | Upload falls back to tar when rsync unavailable | Graceful degradation with warning | Test: sandbox without rsync binary, verify tar fallback |
| NFR-013 | Observability | Live watch event latency | < 1 second from action to event in stream | Benchmark: exec command, measure time to watch output |
| NFR-014 | Usability | All CLI errors include what failed, why, and how to fix | 100% actionable error messages | Review: every error path has context + remediation |
| NFR-015 | Usability | All commands producing structured output support `--json` flag | Machine-readable JSON for: exec, mcp list, health, watch, policy test, net-test | Test: parse output with `jq` for every `--json` command |
| NFR-016 | Platform | Observability collector requires CAP_BPF (or root) on Linux | eBPF features unavailable on macOS/WSL; graceful degradation to log-only | Test: run `sandbox watch` on macOS, verify degraded mode with clear message |
| NFR-017 | Usability | Progress bars only shown when stderr is a TTY | No progress bar output when piped (programmatic use by DarkClaw) | Test: pipe upload output, verify no ANSI/progress bytes in stderr |
| NFR-018 | Performance | SSH connection multiplexing (ControlMaster) for exec commands | First exec ~200ms, subsequent < 20ms via reused connection | Benchmark: 10 sequential exec commands, measure total time |

## 5. Edge Case Catalog

| ID | Requirement | Edge Case | Expected Behavior |
|----|-------------|-----------|-------------------|
| EC-001 | FR-001 (rsync upload) | rsync binary not present in sandbox image | Detect absence, warn user, fall back to tar upload |
| EC-002 | FR-001 (rsync upload) | rsync transfer interrupted mid-stream | Partial transfer cleaned up; next rsync resumes correctly |
| EC-003 | FR-002 (multi-upload) | Two `--upload` specs target the same sandbox directory | Second upload overwrites first (last-writer-wins); warn user |
| EC-004 | FR-003 (progress) | Upload of 0-byte directory (empty or all-gitignored) | Progress bar shows "0 bytes" and completes immediately |
| EC-005 | FR-007 (exec) | Command produces unbounded stdout (e.g., `cat /dev/urandom`) | Stream output without buffering; respect SSH channel limits |
| EC-006 | FR-007 (exec) | Command hangs indefinitely | Default 300s timeout kills SSH process, returns exit code 124 (timeout). `--timeout 0` disables. Timeout logged as warning. |
| EC-007 | FR-008 (MCP bridge) | MCP server subprocess crashes during agent operation | Bridge detects pipe closure, restarts server within 5s, logs restart event |
| EC-008 | FR-008 (MCP bridge) | MCP server requires interactive authentication (OAuth browser flow) | Bridge handles OAuth flow on host-side; sandbox never involved in auth |
| EC-009 | FR-015 (blueprint) | Blueprint references image that can't be pulled | Fail fast with actionable error: "Image ghcr.io/x/y:z not found. Check registry access." |
| EC-010 | FR-015 (blueprint) | Blueprint references provider that doesn't exist | Fail fast: "Provider 'github' not found. Create with: darkshell provider create --name github --type github" |
| EC-011 | FR-024 (snapshot) | Snapshot of sandbox with 50GB writable filesystem | Stream tar directly to host without buffering; show progress bar |
| EC-012 | FR-029 (image save) | Saved image contains env vars with credentials | Mandatory stripping removes all env vars from saved image; warning lists removed vars |
| EC-013 | FR-001 (rsync upload) | Symlinks in upload source | rsync follows symlinks by default (`-L`); document behavior, provide `--no-follow-symlinks` flag |
| EC-014 | FR-004 (download filter) | `--include` pattern matches no files | Download completes with 0 bytes; warn "No files matched pattern '<pattern>'" |
| EC-015 | FR-017 (live watch) | Watch connection drops (network interruption) | Client auto-reconnects; events not lost (gateway buffers) |
| EC-016 | FR-034 (GitOps) | Policy YAML in git is invalid | Reject invalid policy; keep last-known-good; alert operator |
| EC-017 | FR-038 (cleanup) | Bridge daemon running when sandbox is force-deleted | Bridge receives SIGTERM, cleans up within 5s, PID file removed. If bridge doesn't exit, SIGKILL after 10s. |
| EC-018 | FR-017 (observe) | eBPF not available (macOS, older kernel, no CAP_BPF) | Graceful degradation to log-tailing-only mode. Message: "eBPF unavailable. Falling back to log-based monitoring." |
| EC-019 | FR-008 (MCP bridge) | Port conflict when auto-allocating MCP bridge port | Bridge selects ports starting from 9100, increments until available via `check_port_available()`. Selected port recorded in registration file. |

## 6. Integration Points

| System | Protocol | Authentication | Error Handling |
|--------|----------|---------------|----------------|
| OpenShell gateway | gRPC (proto/openshell.proto) | mTLS or bearer token | Gateway unavailable: retry with backoff, surface error with remediation |
| SSH transport (ProxyCommand) | SSH over gateway tunnel | Gateway-mediated auth (no direct SSH keys in sandbox) | Connection failure: check gateway status, report which hop failed |
| MCP servers (stdio) | stdin/stdout JSON-RPC via bridge daemon | Credentials injected from provider system | Server crash: auto-restart with backoff; log event |
| MCP servers (Streamable HTTP) | HTTPS through sandbox proxy | OAuth or API key via provider system | Connection denied: report which policy rule blocked, suggest fix |
| k3s (sandbox orchestration) | Kubernetes API via gateway | Service account | Pod creation failure: report k3s error with context |
| Container registry (images) | OCI/Docker registry protocol | Registry credentials (if private) | Pull failure: report registry, image, tag, and auth status |
| SIEM/observability platforms (P16) | OTLP, Splunk HEC, Datadog API | Platform-specific API keys | Export failure: buffer locally, retry, alert on persistent failure |
| Git repositories (P17 GitOps) | Git over HTTPS/SSH | GITHUB_TOKEN via provider | Invalid policy in git: reject, keep last-known-good, alert |

## 7. Success Metrics

| Metric | Target | Measurement | Timeframe |
|--------|--------|-------------|-----------|
| Delta upload speedup | 15x faster than full tar for typical 1-file change | Benchmark suite: 100MB, 1GB, 5GB projects with 1-file changes | v1.0 release |
| Exec command latency | < 100ms overhead | Benchmark: `exec -- echo ok` across 100 runs | v1.0 release |
| MCP setup time | < 30 seconds for any MCP server | Time from `mcp add` to first successful tool call | v1.0 release |
| Blueprint creation time | < 60 seconds to Ready phase | Time from `create --from blueprint.yaml` to sandbox Ready | v1.0 release |
| Upstream test suite pass rate | 100% | Run `cargo test` from upstream against darkshell binary | Every upstream merge |
| Security mechanisms preserved | 0 weakened | Security audit of all changed code paths | Every release |
| Agent action visibility | 100% of action types observable | Audit: network, file, process, MCP, inference all covered | v1.1 release |
| Operator satisfaction | < 5 minutes to diagnose sandbox failure | Timed troubleshooting exercise with/without DarkShell observability | v1.1 release |
