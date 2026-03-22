# DarkShell — Kickstart Document

**What:** A fork of [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) (Apache 2.0)
with quality-of-life enhancements for the DarkClaw factory ecosystem.

**Repo:** `BOHICA-LABS/darkshell` (private)
**Upstream:** `NVIDIA/OpenShell` v0.0.13 (tagged March 21, 2026)
**Language:** Rust (same as upstream)

---

## Phase 0: Fork + Rename + Verify

Before any enhancements, establish the fork:

```bash
cd /Users/jmagady/Dev/DarkShell
git remote add upstream https://github.com/NVIDIA/OpenShell.git
git fetch upstream
git merge upstream/main --allow-unrelated-histories

# Rename binary: openshell → darkshell
# Update Cargo.toml: package name, description, repository URL
# Update CLI help text and binary name references

# Verify everything builds and passes
cargo build
cargo test
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

**The first story (DC-S001) should be this fork + rename + green build.**
No enhancements until upstream builds and tests pass under the new name.

---

## Why Fork

OpenShell provides excellent kernel-level sandbox isolation (Landlock + seccomp + netns)
and a clean proxy architecture. We don't want to change its security model. We want to
improve the developer experience for file transfer, workspace management, and command
execution — the "getting code in and results out" workflow that DarkClaw automates.

**Everything we add is additive.** No security downgrades, no isolation weakening.
We periodically merge upstream changes.

---

## Upstream Architecture (from source analysis, March 22, 2026)

### Codebase Structure

```
OpenShell/
├── crates/
│   ├── openshell-cli/          # CLI binary (~3K LOC)
│   │   └── src/
│   │       ├── main.rs         # Clap command definitions
│   │       ├── run.rs          # Command handlers (~4K LOC)
│   │       └── ssh.rs          # SSH tunnel, upload, download (~1K LOC)
│   │
│   ├── openshell-core/         # Shared types + utilities
│   │   └── src/
│   │       ├── forward.rs      # Port forwarding (SSH -L, PID tracking)
│   │       └── ...
│   │
│   ├── openshell-sandbox/      # Sandbox runtime (runs inside k3s pod)
│   │   └── src/
│   │       ├── proxy.rs        # HTTP proxy (2598 lines — the critical file)
│   │       ├── opa.rs          # OPA policy engine (regorus)
│   │       ├── policy.rs       # Policy types (filesystem, network, process)
│   │       └── l7/
│   │           └── tls.rs      # TLS termination + MITM
│   │
│   ├── openshell-server/       # Gateway server (gRPC)
│   │   └── src/
│   │       └── sandbox/mod.rs  # Sandbox lifecycle (create, delete, etc.)
│   │
│   └── openshell-router/       # Inference router
│
├── proto/                      # gRPC proto definitions
├── docs/                       # Documentation + tutorials
└── data/
    └── sandbox-policy.rego     # OPA Rego rules for policy evaluation
```

### Key File Transfer Internals

**Upload (`ssh.rs:454-592`):**
- `sandbox_sync_up()` — arbitrary files via tar-over-SSH
- `sandbox_sync_up_files()` — git-tracked files only
- Server-side: `mkdir -p <dest> && cat | tar xf - -C <dest>`
- Uses `tar` crate to build archives in blocking tokio task
- Git filtering: `git ls-files -co --exclude-standard -z`
- No size limit, no progress reporting, no delta

**Download (`ssh.rs:596-672`):**
- `sandbox_sync_down()` — reverse tar-over-SSH
- Server-side: `if [ -d <path> ]; then tar cf - -C <path> .; else tar cf - -C <parent> <name>; fi`
- Client-side: `tar::Archive::unpack()`
- No filtering on download, no delta

**SSH (`ssh.rs:64-147`):**
- ProxyCommand-based tunnel through gateway
- No direct SSH key in sandbox — auth via gateway mTLS/bearer token
- Config installed at `~/.config/openshell/ssh/config`
- `Include` added to `~/.ssh/config`

### Proxy Architecture (`proxy.rs` — 2598 lines)

**Entry:** `handle_tcp_connection()` at line 260
1. Parse HTTP request → check method
2. Non-CONNECT → forward proxy path (line 1561) — plain HTTP to private IPs
3. CONNECT → parse host:port → check `inference.local` (hardcoded bypass, line 320) → OPA policy eval → SSRF check → 200 Established → L7 config → TLS/relay

**SSRF Protection (line 424):**
- Two-mode gate:
  - No `allowed_ips` → resolve DNS, reject if ANY IP is RFC 1918/loopback/link-local
  - With `allowed_ips` → resolve DNS, validate each IP against CIDR allowlist
- Hard guardrail: `is_always_blocked_ip()` (line 1209) — loopback + link-local ALWAYS blocked
- Applies to both CONNECT and forward proxy

**TLS Modes:**
- `terminate`: MITM with ephemeral certs (sandbox CA, 256-entry LRU cache), enables L7 inspection
- `passthrough`: raw TCP relay, no inspection
- Omitting `tls` + `protocol` = no L7, raw relay
- `tls: false` is NOT valid

**Forward Proxy (line 1561-1572):**
- Handles non-CONNECT requests (plain HTTP to private IPs)
- Requires `allowed_ips`, rejects L7-configured endpoints (line 1681)
- Rewrites absolute-form URI to origin-form
- **Merged and released in v0.0.13** (PR #158, March 6)

**Policy Evaluation:**
- OPA via regorus engine (Rust-native Rego interpreter)
- Identity: `/proc/net/tcp` → resolve socket owner → binary path → TOFU SHA256 verify → ancestor chain
- Endpoint matching: exact host:port, glob host:port, hostless (any host on port with `allowed_ips`)
- Binary matching: exact path, ancestor exact path, glob pattern
- `cmdline_paths` intentionally excluded (spoofable)

**Policy Hot-Reload:**
- `reload()` → create new engine → full validation → atomic swap (Mutex)
- On failure: previous engine untouched (last-known-good)
- No restart needed

### Port Forwarding (`forward.rs`)

- SSH-based: `-L <bind_addr>:<port>:127.0.0.1:<port>`
- `ForwardSpec` supports `[bind_address:]port` syntax
- **`0.0.0.0:port` IS supported** (test at line 700 confirms)
- PID tracking: `~/.config/openshell/forwards/<sandbox>-<port>.pid`
- Format: `<pid>\t<sandbox_id>\t<bind_addr>`
- Multi-port: each gets own PID file
- `find_ssh_forward_pid()` uses pgrep to validate
- `check_port_available()` checks for conflicts with actionable hints

### CLI Command Structure

```
openshell
├── gateway
│   ├── start --name <name>
│   └── destroy -g <name>
├── sandbox
│   ├── create --name <name> --from <image:tag> [--upload <local>:<remote>] [--no-git-ignore] [--policy <file>] [--forward <port>] [--editor vscode|cursor] [--provider <name>]
│   ├── get <name>              # status: Phase (Ready/Provisioning/Failed)
│   ├── delete <name>
│   ├── upload <name> <local> [dest]     # default dest: /sandbox
│   ├── download <name> <remote> [dest]  # default dest: .
│   ├── connect <name> [--editor vscode|cursor]
│   ├── ssh-config <name>       # print SSH config block
│   └── list
├── policy
│   ├── get <name> --full
│   └── set <name> --policy <file> --wait
├── forward
│   ├── start [bind:]<port> <sandbox>
│   ├── stop <port> [sandbox]
│   └── list
├── provider
│   ├── create --name <name> --type <github|gitlab|generic> [--from-existing] [--credential KEY=VALUE]
│   ├── list
│   └── delete <name>
├── inference
│   ├── set --provider <name> --model <model>
│   └── get
├── doctor
│   ├── exec -- <command>       # run command in gateway VM
│   └── logs --lines <N>
├── status                      # gateway health
└── term                        # TUI for monitoring
```

### Key Limitations (What We Want to Fix)

| # | Limitation | Impact | Enhancement |
|---|---|---|---|
| 1 | **No incremental upload** — always full tar | Re-uploading a 2GB project takes minutes even if 1 file changed | Add rsync-over-SSH mode alongside tar mode |
| 2 | **Single `--upload` per create** — `Option<String>` not `Vec` | Multi-dir setup requires N post-create upload calls | Change to `Vec<String>` for multiple upload specs |
| 3 | **No `exec` command** — everything requires SSH session | Running a single command (e.g., `git status`) has SSH setup overhead | Add `darkshell sandbox exec <name> -- <command>` |
| 4 | **No sandbox snapshots** — deletion destroys everything | Can't checkpoint workspace before rebuild | Add `darkshell sandbox snapshot <name>` and `darkshell sandbox restore <name> <snapshot>` |
| 5 | **No upload progress** — tar streams silently | Users don't know if a large upload is working or stuck | Add progress reporting (bytes transferred / estimated total) |
| 6 | **No download filtering** — gets everything | Downloading just `.factory/` requires downloading the entire workspace first | Add `--include`/`--exclude` patterns to download |
| 7 | **No upload diffing** — can't detect what changed | User can't preview what will be overwritten before uploading | Add `--dry-run` to upload showing what would transfer |

### P8: Sandbox Health Monitoring

**What:** `darkshell sandbox health <name>` returns structured health status:
CPU/memory usage, disk usage, process count, network connectivity, gateway status.

**Why:** When agents are running, operators need to know if the sandbox is healthy
or resource-constrained. Currently requires SSH + manual inspection.

**How:** Run health check commands via exec, parse + return structured JSON.

**Scope:** ~200 LOC

### P9: Sandbox Resource Limits

**What:** `--cpu-limit` and `--memory-limit` flags on sandbox create.

**Why:** AI agents can consume unbounded resources (large context windows, parallel
builds). Without limits, one sandbox starves others.

**How:** Map to k3s pod resource limits (requests/limits in pod spec).

**Scope:** ~150 LOC (pod spec generation + CLI flags)

### P10: Upload/Download Streaming Progress with ETA

**What:** Real-time progress bar showing: bytes transferred, transfer rate, ETA.
Both upload and download.

**Why:** Users killing "stuck" transfers that were actually working.

**How:** Wrap tar stream in counting reader/writer, use `indicatif` ProgressBar.

**Scope:** ~200 LOC (included with P4 but covers download too)

### P11: Sandbox Events / Webhook Notifications

**What:** `darkshell sandbox watch <name>` streams sandbox events (state changes,
policy reloads, process exits, resource alerts). Optional webhook for CI/CD integration.

**Why:** DarkClaw's orchestration needs to react to sandbox state changes without
polling. CI/CD pipelines need callbacks when sandboxes are ready or fail.

**How:** Subscribe to k3s pod events via the gateway, stream as JSON lines.
Webhook: POST events to a configured URL.

**Scope:** ~400 LOC

### P12: Sandbox Log Export

**What:** `darkshell sandbox logs <name> --export <path>` exports all sandbox logs
(gateway, proxy, agent) to a local file or directory.

**Why:** Debugging factory failures requires correlating multiple log streams.
Currently requires SSH + manual log collection.

**How:** Aggregate logs from gateway + proxy + entrypoint into structured output.

**Scope:** ~150 LOC

### P13: Policy Validation (Dry-Run)

**What:** `darkshell policy validate <file>` validates a policy YAML without applying it.
`darkshell policy test <name> --host <host> --port <port> --binary <path>` tests
whether a specific request would be allowed by the current policy.

**Why:** Silent policy failures are the #1 debugging nightmare. Being able to test
"would this request be allowed?" before running actual commands saves hours.

**How:** Load policy into regorus engine, evaluate test query, report allow/deny + reason.

**Scope:** ~300 LOC

### P14: Sandbox Networking Diagnostics

**What:** `darkshell sandbox net-test <name> --host <host> --port <port>` tests
outbound connectivity from inside the sandbox, reporting: DNS resolution, proxy
evaluation result (allow/deny + which policy matched), TLS handshake, HTTP response.

**Why:** When agents can't reach a model provider, the operator needs to know WHERE
in the chain it fails: DNS? proxy policy? TLS? upstream?

**How:** Run diagnostic commands inside sandbox via exec, parse results.

**Scope:** ~250 LOC

### Sandbox Mutability Model (from source analysis)

**Kernel-locked (irreversible after creation):**
- Landlock filesystem policy — `ruleset.restrict_self()` is a one-way kernel operation
- seccomp syscall filters — `PR_SET_NO_NEW_PRIVS` + BPF filter is irreversible
- Network namespace — veth pair and routing locked at creation
- Process identity — `setuid`/`setgid` applied before sandbox::apply

**Hot-reloadable (atomic swap, no restart):**
- Network policies — OPA engine `reload_from_proto()` builds new engine, validates, swaps
- Inference configuration — model provider routing

**Implication:** Tools/packages cannot be installed at runtime into system directories.
The only supported path is pre-baking everything into the container image before sandbox
creation. See P34 (Blueprints) for our solution.

### MCP Support (current state)

OpenShell has no first-class MCP server management. MCP integration uses a
host-to-sandbox bridge pattern:
- MCP servers run on the **host**, not inside the sandbox
- A stdio-to-HTTP proxy bridges them in via `openshell forward`
- Credentials stay on the host — agents never see raw API keys
- All traffic passes through the network policy proxy

**Gaps:** No MCP CLI commands, no tool-level policy, no in-sandbox stdio support,
no managed bridge daemon, no MCP server discovery/catalog.

### Observability (current state)

OpenShell provides policy decision logging (allow/deny for every action) stored in
customer infrastructure. Exportable via Docker log drivers to SIEM platforms.

**Gaps:** No real-time agent activity view, no file access audit trail (only Landlock
denials, not successful reads/writes), no syscall tracing, no MCP tool call logging,
no OpenTelemetry/Prometheus integration, no behavioral anomaly detection, no process
tree tracing, no inference content logging.

Enterprise partners (Cisco AI Defense, CrowdStrike Falcon, Trend Micro TrendAI) fill
some gaps but require external integration.

### What We Do NOT Change

- **Landlock filesystem isolation** — kernel-enforced, stays as-is
- **seccomp system call filtering** — stays as-is
- **Network namespace isolation** — stays as-is
- **OPA policy evaluation** — stays as-is
- **SSRF protection** — stays as-is
- **TLS termination/passthrough** — stays as-is
- **Binary path matching** — stays as-is
- **Policy YAML formatting sensitivity** — stays as-is (we document the workaround)
- **Proxy architecture** — stays as-is
- **Gateway/sandbox lifecycle** — stays as-is

---

## Proposed Enhancements (Priority Order)

### P1: Delta Upload (rsync mode)

**What:** Add `--rsync` flag to `sandbox upload` that uses rsync-over-SSH instead of tar.

**Why:** The single biggest pain point. A 2GB project with 1 file change takes 30+ seconds
via tar. Rsync transfers only the diff in < 1 second.

**How:**
- `ssh.rs`: add `sandbox_sync_up_rsync()` alongside existing `sandbox_sync_up()`
- Detect if rsync is available in sandbox (it may need to be in the base image or installed)
- Fall back to tar if rsync unavailable
- Same SSH ProxyCommand transport — no new network path

**Scope:** ~200 LOC in `ssh.rs` + CLI flag

### P2: Multiple `--upload` on Create

**What:** Change `upload: Option<String>` to `upload: Vec<String>` in the create command.

**Why:** Multi-directory setup (engine + workspace + env) requires 3 separate upload calls.

**How:**
- `main.rs`: change Clap arg type
- `run.rs`: iterate over upload specs in create handler
- Backward compatible — single `--upload` still works

**Scope:** ~20 LOC

### P3: Exec Command

**What:** `darkshell sandbox exec <name> -- <command>` runs a command inside the sandbox
and returns stdout/stderr/exit code without starting an interactive SSH session.

**Why:** DarkClaw needs to run many quick commands (`git status`, `which node`, `openclaw agents list`)
inside the sandbox. SSH session setup adds 200-500ms overhead per command.

**How:**
- `ssh.rs`: add `sandbox_exec()` that uses `ssh -T <sandbox-host> '<command>'`
- Non-interactive, captures output, returns exit code
- Same ProxyCommand transport

**Scope:** ~100 LOC in `ssh.rs` + command handler

### P4: Upload Progress Reporting

**What:** Show bytes transferred and estimated time remaining during upload.

**Why:** Large uploads (>100MB) appear hung. Users kill and retry, wasting time.

**How:**
- Wrap tar stream in a progress-reporting reader
- Use `indicatif` for terminal progress bar
- Calculate total from local file sizes before starting transfer

**Scope:** ~150 LOC

### P5: Download Filtering

**What:** `--include` / `--exclude` patterns for selective download.

**Why:** Downloading just `.factory/` (10MB) from a 2GB workspace is wasteful.

**How:**
- Server-side: modify tar command to use `--include` patterns
- Or: use `find` + `tar` with file list
- Client-side: same unpack

**Scope:** ~100 LOC

### P6: Sandbox Snapshots

**What:** `darkshell sandbox snapshot <name>` saves sandbox state.
`darkshell sandbox restore <name> <snapshot>` restores from snapshot.

**Why:** `darkclaw rebuild` currently destroys all sandbox-side work. Snapshots let
users checkpoint before risky operations.

**How:** This is the most complex enhancement. Options:
- Tar the entire writable filesystem and store on host
- Use containerd checkpoint/restore (if k3s supports it)
- Export container state via `ctr`

**Scope:** ~500 LOC, needs research into k3s/containerd checkpoint support

### P7: Upload Dry-Run and Diff

**What:** `--dry-run` flag shows what would be uploaded/overwritten.

**How:**
- Compare local file list + hashes against sandbox file list + hashes (via exec)
- Display added/modified/deleted files
- Confirm before proceeding

**Scope:** ~200 LOC

---

## Enhancements: Orchestration & Lifecycle (P15–P18)

### P15: Multi-Sandbox Orchestration

**What:** Coordinate policies, shared state, and lifecycle across multiple sandboxes
from a single DarkClaw orchestration layer.

**Why:** DarkClaw runs multiple agents across sandboxes. No built-in way to manage
them as a fleet — each sandbox is an island.

**How:** Gateway-level coordination API. Each sandbox retains its own isolation.

**Scope:** ~600 LOC

### P16: Observability Export Adapters

**What:** Structured adapters to pipe OpenShell audit logs to SIEM/observability
platforms (Splunk, Datadog, Grafana, OpenSearch).

**Why:** OpenShell generates logs but provides zero tooling to forward them.

**How:** Pluggable exporter interface with built-in adapters for common platforms.

**Scope:** ~400 LOC

### P17: Policy-as-Code GitOps Integration

**What:** `git push` a policy change and have it automatically apply to running
sandboxes via reconciliation loop.

**Why:** Docs recommend storing policies in git but provide no reconciliation tooling.

**How:** Watch a git repo/branch for policy YAML changes, auto-apply via `policy set`.

**Scope:** ~300 LOC

### P18: Credential Rotation for Running Sandboxes

**What:** Rotate provider credentials on running sandboxes without delete + recreate.

**Why:** Long-running agents (hours/days) need credential rotation. Current model
requires destroying the sandbox.

**How:** Extend provider system to support credential refresh via gateway API.

**Scope:** ~200 LOC

---

## Enhancements: MCP Integration (P19–P24)

### P19: MCP Bridge Daemon

**What:** `darkshell mcp bridge` — a managed stdio-to-HTTP proxy that DarkShell
starts/stops automatically when sandboxes use MCP servers.

**Why:** Current MCP integration requires manual setup of stdio-to-HTTP proxies
and port forwards. This is the biggest friction for factory workflows.

**How:**
- Host-side daemon spawns MCP server subprocesses with host credentials
- Exposes them as HTTP endpoints
- Auto-configures port forwards into sandbox
- Credentials stay on host — agent never sees raw API keys

**Scope:** ~500 LOC

**Security:** Host-side only. Sandbox sees an HTTP endpoint through existing
port forward mechanism. No security model changes.

### P20: MCP CLI Management

**What:** `darkshell mcp add/list/remove <sandbox>` — first-class CLI for
registering MCP servers with sandboxes.

**Why:** Currently requires manual network policy edits + port forward setup
for every MCP server.

**How:**
- `mcp add` registers server, auto-configures network policy + port forward
- `mcp list` shows connected MCP servers and their status
- `mcp remove` tears down bridge + port forward + policy entry

**Scope:** ~300 LOC

**Security:** Automates existing mechanisms (policy set + forward start). No new
capabilities granted.

### P21: MCP Tool-Level Policy

**What:** Extend policy YAML to allow/deny specific MCP tools by name.

**Why:** If an agent can reach an MCP server, it currently gets ALL tools.
Can't restrict to read-only tools vs. destructive ones.

**How:** Add `allowed_tools` / `denied_tools` fields to network policy blocks.
Enforce at the MCP bridge layer via request inspection.

**Scope:** ~200 LOC

**Security:** Adds MORE restriction. Strictly tightens the security model.

### P22: In-Sandbox stdio MCP Support

**What:** Run MCP servers inside the sandbox for filesystem-only tools (e.g., Tally)
that don't need external network or credentials.

**Why:** Not all MCP servers need the host bridge. Filesystem-only servers like
Tally can run inside the sandbox safely.

**How:** Agent spawns MCP server as subprocess inside sandbox. Server inherits
all sandbox restrictions (Landlock, seccomp, netns).

**Scope:** ~100 LOC (mostly documentation and example policies)

**Security:** MCP server inherits ALL sandbox restrictions. More constrained than
host-side. No security model changes.

### P23: MCP Credential Isolation

**What:** MCP servers get credentials via the provider system without exposing
them to the agent process.

**Why:** MCP servers often need API keys (Perplexity, Tavily). These should flow
through the provider system, not be visible to the agent.

**How:** Bridge daemon receives credentials from gateway provider API. Injects
into MCP server subprocess environment. Agent process never sees them.

**Scope:** ~150 LOC

**Security:** Strengthens credential isolation. Extends existing provider model.

### P24: Streamable HTTP MCP Transport

**What:** Native support for the modern MCP transport (Streamable HTTP, spec
2025-03-26) which consolidates bidirectional communication through a single
`/mcp` endpoint.

**Why:** Eliminates the stdio subprocess problem entirely. Agents connect to
MCP servers via standard HTTP — goes through existing proxy and OPA evaluation.

**How:** MCP servers expose Streamable HTTP endpoints. Network policy allowlists
them like any other endpoint. No bridge needed for remote servers.

**Scope:** ~200 LOC (client-side support in agent configuration)

**Security:** Standard HTTP through existing proxy. OPA evaluates it like any
other connection. No security model changes.

---

## Enhancements: Observability (P25–P31)

### P25: Live Sandbox Watch

**What:** `darkshell sandbox watch <name>` — real-time event stream showing
commands executed, files changed, network requests, and policy decisions as
they happen. JSON lines output for piping to dashboards.

**Why:** Currently no way to see what an agent is doing in real-time. Only
after-the-fact log retrieval.

**How:** Aggregate gateway logs, proxy decisions, and sandbox events into a
unified stream. Subscribe via long-poll or SSE.

**Scope:** ~400 LOC

**Security:** Read-only observation. Does not modify sandbox state.

### P26: OpenTelemetry Exporter

**What:** Native OTel metrics (policy decisions/sec, actions by type, latency
histograms) and traces (action→policy eval→decision chain).

**Why:** No integration with modern observability stacks (Prometheus, Grafana,
Jaeger). Operators must build custom exporters.

**How:** Instrument gateway and proxy with `opentelemetry` crate. Export via
OTLP to any OTel-compatible backend.

**Scope:** ~400 LOC

**Security:** Exports metrics from gateway/proxy. Observes, doesn't modify.

### P27: File Access Audit Log

**What:** Log every successful file read/write/delete inside the sandbox, not
just Landlock denials.

**Why:** Landlock blocks violations but doesn't surface which files were
successfully accessed. Critical for compliance and forensics.

**How:** Use eBPF (fanotify) to observe file operations without performance
impact. Structured log: path, operation, process, timestamp.

**Scope:** ~500 LOC

**Security:** Read-only monitoring via eBPF. Does not modify sandbox state
or weaken Landlock enforcement.

### P28: MCP Tool Call Logging

**What:** Structured log of every MCP tool invocation: server name, tool name,
arguments, response summary, duration.

**Why:** No visibility into which MCP tools are being invoked or what data
flows through them.

**How:** Captured at the MCP bridge layer (P19). Bridge logs all requests
passing through it.

**Scope:** ~150 LOC (part of P19 bridge implementation)

**Security:** Logging at bridge layer (host-side). Read-only.

### P29: Process Tree Tracing

**What:** Track every process spawned inside the sandbox: parent→child,
command line, exit code, duration.

**Why:** Can't see the full process tree — what commands the agent spawned,
what subprocesses ran, what failed.

**How:** eBPF process events (exec, exit) scoped to sandbox PID namespace.

**Scope:** ~300 LOC

**Security:** Read-only eBPF observation. Does not modify sandbox.

### P30: Inference Request/Response Logging

**What:** Log prompts sent to model providers and responses received, with
configurable redaction for sensitive data.

**Why:** Privacy router routes requests but doesn't log content. Can't detect
prompt injection or data exfiltration through inference.

**How:** Tap the privacy router's request/response pipeline. Configurable
redaction rules (strip PII, limit response size, hash sensitive fields).

**Scope:** ~300 LOC

**Security:** Read-only logging at privacy router. Redaction prevents
sensitive data from appearing in logs.

### P31: Behavioral Baseline and Alerting

**What:** Establish per-sandbox behavioral baselines (normal network patterns,
file access patterns, command frequency). Alert on deviations.

**Why:** No anomaly detection. Can't detect "agent suddenly making 1000x more
network requests than usual."

**How:** Collect metrics from P25-P30, compute rolling baselines, alert when
current behavior exceeds threshold.

**Scope:** ~400 LOC

**Security:** Analysis of existing logs. Read-only. Strengthens security by
detecting anomalous agent behavior.

---

## Enhancements: Workspace & Tooling (P33–P34)

### P33: Sandbox Image Save (with sanitization)

**What:** `darkshell sandbox image save <name> <tag>` saves current sandbox
state as a new base image for future sandboxes.

**Why:** Avoids the "rebuild Dockerfile from scratch" cycle when an agent has
set up a useful environment.

**How:**
- Commit container state to new image
- **Mandatory sanitization:** strip environment variables, clear provider
  credentials, remove temp files, scrub known sensitive paths
- Requires explicit operator approval (`--confirm`)

**Scope:** ~300 LOC

**Security:** Credential stripping prevents sensitive data leakage. Operator
approval required. Does not modify running sandbox isolation.

### P34: Sandbox Blueprints

**What:** Versioned, declarative sandbox definitions as a single YAML file:
image + policy + providers + MCP servers + port forwards + resource limits.

**Why:** The right answer for "agents need tools at runtime" is making sandbox
creation trivial, not weakening sandbox immutability. Blueprints make it
one command to create a fully-configured sandbox.

**How:**
```yaml
# darkshell-blueprint.yaml
name: dark-factory-agent
image: ghcr.io/bohica-labs/darkshell-factory:latest
policy: policies/factory-agent.yaml
providers: [github, anthropic]
mcp_servers:
  - name: perplexity
    transport: bridge
    command: npx -y @anthropic/perplexity-mcp
    env: [PERPLEXITY_API_KEY]
  - name: tally
    transport: in-sandbox
    command: /opt/mcp-servers/tally
forwards: [8080, 3000]
resources:
  cpu: "2"
  memory: "4Gi"
```

One command: `darkshell sandbox create --from blueprint.yaml`

**Scope:** ~400 LOC

**Security:** Declarative config that creates sandboxes using existing mechanisms.
No new capabilities. Version-controlled and auditable.

---

## Security Analysis of Enhancements

All 32 enhancements were evaluated against OpenShell's five security promises:

1. **Landlock** — kernel-enforced filesystem isolation (irreversible)
2. **seccomp** — kernel-enforced syscall filtering (irreversible)
3. **Network namespace** — all traffic through OPA-evaluated proxy
4. **SSRF protection** — loopback/link-local/RFC1918 always blocked
5. **Credential isolation** — providers inject secrets, agents never see raw keys

### Verdict

| Category | Count | Security Impact |
|---|---|---|
| No impact (client-side, host-side, read-only) | 25 | None — operates outside security boundary |
| Strengthens security | 5 | P9 (resource limits), P13 (policy validation), P21 (tool-level policy), P23 (credential isolation), P31 (anomaly detection) |
| Requires care | 1 | P33 (image save) — mandatory credential stripping + operator approval |
| Rejected | 2 | ~~P32 (sandbox extend)~~, ~~P35 (writable overlay)~~ — violate Landlock immutability |

**No enhancement weakens or bypasses any kernel-enforced security mechanism.**

### Enhancements Explicitly Rejected

- **~~P32: `sandbox extend --install`~~** — Would require writing to Landlock-protected
  system directories. `restrict_self()` is irreversible. Rejected.
- **~~P35: Writable tool overlay~~** — Mounting a writable overlay at `/usr/local/`
  circumvents what Landlock is designed to prevent. A compromised agent could install
  persistent backdoors. Rejected.

The correct solution is P34 (Blueprints): make sandbox creation trivial so that
recreating with new tools is fast and painless.

---

## Enhancement Summary

| # | Enhancement | Category | Priority |
|---|---|---|---|
| P1 | Delta upload (rsync mode) | File Transfer | Must |
| P2 | Multiple `--upload` on create | File Transfer | Must |
| P3 | Exec command | Execution | Must |
| P4 | Upload progress reporting | Observability | Must |
| P5 | Download filtering | File Transfer | Should |
| P6 | Sandbox snapshots | Lifecycle | Nice |
| P7 | Upload dry-run and diff | File Transfer | Should |
| P8 | Sandbox health monitoring | Observability | Nice |
| P9 | Sandbox resource limits | Lifecycle | Nice |
| P10 | Streaming progress with ETA | Observability | Should |
| P11 | Sandbox events / webhooks | Orchestration | Nice |
| P12 | Sandbox log export | Operational | Nice |
| P13 | Policy validation (dry-run) | Policy | Nice |
| P14 | Sandbox networking diagnostics | Policy | Nice |
| P15 | Multi-sandbox orchestration | Orchestration | Nice |
| P16 | Observability export adapters | Operational | Nice |
| P17 | Policy-as-code GitOps | Policy | Nice |
| P18 | Credential rotation | Lifecycle | Nice |
| P19 | MCP bridge daemon | MCP | Must |
| P20 | MCP CLI management | MCP | Must |
| P21 | MCP tool-level policy | MCP | Nice |
| P22 | In-sandbox stdio MCP | MCP | Should |
| P23 | MCP credential isolation | MCP | Should |
| P24 | Streamable HTTP MCP transport | MCP | Should |
| P25 | Live sandbox watch | Observability | Should |
| P26 | OpenTelemetry exporter | Observability | Nice |
| P27 | File access audit log | Observability | Nice |
| P28 | MCP tool call logging | Observability | Should |
| P29 | Process tree tracing | Observability | Nice |
| P30 | Inference request/response logging | Observability | Nice |
| P31 | Behavioral baseline + alerting | Observability | Nice |
| P33 | Sandbox image save (sanitized) | Workspace | Nice |
| P34 | Sandbox blueprints | Workspace | Must |

**Must (7):** P1, P2, P3, P4, P19, P20, P34
**Should (8):** P5, P7, P10, P22, P23, P24, P25, P28
**Nice (17):** P6, P8, P9, P11–P18, P21, P26, P27, P29–P31, P33

---

## Fork Strategy

1. **Fork** `NVIDIA/OpenShell` to `BOHICA-LABS/darkshell`
2. **Rename** CLI binary: `openshell` → `darkshell` (but keep internal crate names to ease upstream merges)
3. **Add enhancements** as separate commits on a `darkshell/enhancements` branch
4. **Maintain upstream branch** tracking `NVIDIA/OpenShell:main` for periodic merges
5. **DarkClaw detects** which binary is available (`darkshell` or `openshell`) at runtime and uses enhanced features when `darkshell` is present

---

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

DarkClaw v1 ships with upstream OpenShell support. DarkShell enhancements are
additive — DarkClaw gains speed and UX when DarkShell is installed but never
requires it.

### Dark Factory Integration

The dark factory runs VSDD pipeline phases inside DarkShell sandboxes:
- **Spec phases:** Read/write `.factory/` artifacts, git operations
- **Implementation phases:** `cargo build`, `cargo test`, `cargo clippy` via exec
- **Review phases:** MCP servers (Perplexity for research, Tally for findings)
- **All phases:** Observability for monitoring agent progress and behavior

DarkShell blueprints (P34) define the complete factory sandbox environment:
image + policy + providers + MCP servers + port forwards in one YAML file.

---

## Build & Test

Same as upstream OpenShell:
```bash
cargo build                  # Build all crates
cargo test                   # Run all tests
cargo clippy -- -D warnings  # Lint
```

CI mirrors upstream's workflow with added tests for new features.

---

## License

Apache 2.0 (same as upstream). Fork attribution in README and NOTICE file.
