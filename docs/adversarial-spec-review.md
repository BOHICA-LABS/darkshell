---
document_type: adversarial-review
reviewed_documents:
  - docs/product-brief.md
  - docs/prd.md
  - docs/architecture.md
  - KICKSTART.md
reviewer: Claude Opus 4.6 (adversarial stance, fresh read)
date: 2026-03-22
pass: 1
status: findings-reported
---

# Adversarial Spec Review: DarkShell — Pass 1

## Summary

22 findings. 3 Critical, 6 High, 9 Medium, 4 Low.

---

### [CRITICAL] F-001: MCP Bridge Port Forward Bypasses Sandbox Network Policy

**Location:** `docs/architecture.md:362` (ADR-002), `docs/prd.md:125` (FR-008)
**Category:** security

**The Problem:**
ADR-002 states the bridge port-forwards HTTP endpoints into the sandbox so the agent
connects to `localhost:<port>`. But OpenShell's SSRF protection
(`is_always_blocked_ip()`) **always blocks loopback addresses**. The KICKSTART.md
source analysis (line 120) confirms: "loopback + link-local ALWAYS blocked."

If port-forwarded traffic enters the sandbox via `localhost`, it bypasses the
HTTP CONNECT proxy entirely (it's local, not outbound). The agent talks to
`localhost:<port>` directly — the OPA policy engine never evaluates this connection.
This means MCP tool calls are **completely unaudited by the sandbox proxy**.

**Evidence:**
KICKSTART.md line 120: `is_always_blocked_ip()` (line 1209) — loopback + link-local
ALWAYS blocked. But SSH port forwards (`-L`) bind inside the sandbox's network
namespace and are reachable via `127.0.0.1` without hitting the proxy.

**The Fix:**
Either:
1. Route MCP bridge traffic through the sandbox proxy (not localhost) by binding the
   forward to the veth interface IP, not loopback. This puts it under OPA evaluation.
2. Accept that port-forwarded MCP traffic is outside proxy scope and document this
   explicitly. Add MCP tool call logging at the bridge layer (P28) as a compensating
   control.
3. Add a dedicated MCP policy evaluation at the bridge layer that mirrors OPA's
   deny-by-default model for tool calls (related to P21).

Option 2+3 combined is likely correct. Document the gap and add bridge-layer policy.

---

### [CRITICAL] F-002: exec Command Has No Timeout Default — Enables Sandbox Resource Exhaustion

**Location:** `docs/prd.md:204` (EC-006), `docs/prd.md:119` (FR-007)
**Category:** spec-gap

**The Problem:**
EC-006 says exec "otherwise no timeout (matches SSH behavior)." FR-007 specifies
"Non-interactive `ssh -T`; same ProxyCommand transport." But DarkClaw runs hundreds
of exec commands per factory run. A single hung command with no timeout blocks the
entire factory pipeline indefinitely. This is a denial-of-service on the factory.

The "matches SSH behavior" justification is wrong. SSH is interactive and a human
notices hangs. DarkClaw is automated and blind.

**Evidence:**
Product brief: "DarkClaw orchestration engine... 100s of operations/run"
EC-006: "otherwise no timeout (matches SSH behavior)"

**The Fix:**
Add a mandatory `--timeout` flag with a sensible default (e.g., 300 seconds) for
programmatic use. CLI interactive use can default to no timeout. Add an
`NFR-015: Exec timeout` with default of 300s and configurable per-blueprint.

---

### [CRITICAL] F-003: "Never Modify openshell-sandbox" Is Contradicted by Observability Requirements

**Location:** `docs/architecture.md:63-64` (Key Principle), `docs/prd.md:149` (FR-022)
**Category:** contradiction

**The Problem:**
The architecture states: "The sandbox runtime code (openshell-sandbox) is NEVER
modified." But FR-022 requires "Log inference requests/responses at privacy router."
The privacy router IS the sandbox proxy (proxy.rs in openshell-sandbox). You cannot
tap the privacy router's request/response pipeline without modifying proxy.rs.

ADR-005 says "Use host-side eBPF probes." But eBPF can observe syscalls and file
access — it cannot read the decrypted content of TLS-terminated HTTP requests inside
the proxy process. The proxy terminates TLS, inspects HTTP, then re-encrypts. eBPF
sees encrypted bytes on the wire, not cleartext prompts.

**Evidence:**
Architecture ADR-005: "Use host-side eBPF probes scoped to the sandbox's PID/network namespace"
KICKSTART.md line 124: "terminate: MITM with ephemeral certs... enables L7 inspection"
The L7 inspection happens inside proxy.rs. eBPF cannot see inside the TLS termination.

**The Fix:**
Either:
1. Accept that FR-022 (inference logging) requires modifying openshell-sandbox/proxy.rs
   and create a narrow, well-defined hook point. Update ADR-001 to say "openshell-sandbox
   is not modified EXCEPT for a clearly demarcated observability hook."
2. Demote FR-022 to out-of-scope and remove it from COMP-005. Inference logging
   would require upstream OpenShell to add a hook, which we can't control.
3. Intercept at the gateway level before traffic reaches the sandbox, if inference
   requests are routed through the gateway. Verify this with the actual traffic flow.

Option 2 is safest. Option 3 needs validation against the actual inference routing path.

---

### [HIGH] F-004: Blueprint Schema Has No Versioning Strategy

**Location:** `docs/architecture.md:265-291` (Blueprint Schema)
**Category:** spec-gap

**The Problem:**
The schema declares `apiVersion: darkshell/v1` but there's no discussion of what
happens when we need `v2`. ADR-004 consequences mention "Blueprint schema must be
forward-compatible for future enhancements" but the schema has no mechanism for this.

What happens when:
- We add a new field in v1.1? Do old blueprints still work?
- We rename `mcp_servers` to `tools`? How do we migrate?
- A blueprint is checked into git and used 6 months later with a newer DarkShell?

**Evidence:**
Blueprint schema has `apiVersion` but no `#[non_exhaustive]` equivalent, no schema
migration, no unknown-field handling policy.

**The Fix:**
Add to ADR-004 or create ADR-009:
- Unknown fields in blueprint YAML are **warned but not rejected** (forward-compat)
- `apiVersion` is checked on parse; unsupported versions fail with actionable error
- Schema migration: provide `darkshell blueprint migrate <file>` for version upgrades
- Document the compatibility promise: "v1.x blueprints always work with v1.x+ DarkShell"

---

### [HIGH] F-005: MCP Bridge Daemon Lifecycle Is Undefined for Sandbox Deletion

**Location:** `docs/architecture.md:257-258` (MCP Server Registration), `docs/prd.md:127` (FR-010)
**Category:** spec-gap

**The Problem:**
FR-010 defines `mcp remove` but there's no requirement for what happens when the
SANDBOX is deleted (not the MCP server). If a user runs `darkshell sandbox delete foo`,
are the associated MCP bridge daemons cleaned up? The data model says "auto-cleanup
on sandbox delete" but no FR requires it and no edge case covers it.

What happens to:
- Bridge daemon processes still running?
- PID files in `~/.config/darkshell/mcp/`?
- Port forwards that are now forwarding to nothing?
- Network policy entries that reference a deleted sandbox?

**Evidence:**
Data model: "auto-cleanup on sandbox delete" — stated but not specified.

**The Fix:**
Add FR-038: "When a sandbox is deleted, all associated MCP bridge daemons are stopped,
PID files removed, port forwards torn down, and network policy entries cleaned up.
Partial failure during cleanup is logged but does not block sandbox deletion."

Add EC-017: "Bridge daemon is running when sandbox is force-deleted (`--force`)" —
Expected: bridge daemon receives SIGTERM, cleans up within 5s, PID file removed.

---

### [HIGH] F-006: COMP-008 (Lifecycle Manager) Claims Dependency on openshell-server

**Location:** `docs/architecture.md:100` (COMP-008 row)
**Category:** contradiction

**The Problem:**
COMP-008 lists `openshell-server (gateway API)` as a dependency. But ADR-001 says
new crates depend on `openshell-core` only, never on `openshell-sandbox` or
`openshell-server`. The Lifecycle Manager is in `openshell-cli` (per crate layout),
which already has an implicit dependency on `openshell-server` via gRPC client stubs.
But the component map's COMP-008 entry doesn't appear in the YAML at all — it only
lists `openshell-core` as a dependency.

The table says one thing; the YAML says another.

**Evidence:**
Table row: `openshell-core, openshell-server (gateway API)`
YAML: `dependencies: [openshell-core]`

**The Fix:**
Clarify: COMP-008 depends on `openshell-core` for types and uses the gateway's gRPC
API via client stubs already present in `openshell-cli`. It does NOT directly depend
on `openshell-server` as a crate. Update the table to match the YAML.

---

### [HIGH] F-007: NFR-002 (< 100ms exec) May Be Physically Impossible

**Location:** `docs/prd.md:181` (NFR-002), `docs/architecture.md:326` (NFR-002 architecture)
**Category:** implicit-assumption

**The Problem:**
NFR-002 targets "< 100ms overhead" for exec, measured as `exec -- echo ok`. But
the exec command uses `ssh -T` via ProxyCommand through the gateway. The SSH
handshake alone involves:
1. TCP connection to gateway (local Docker, ~1ms)
2. SSH key exchange (~20-50ms)
3. ProxyCommand tunnel setup through gateway to sandbox
4. SSH channel open + command execution

The architecture claims "no session negotiation" but `ssh -T` still does a full SSH
handshake unless connection multiplexing (ControlMaster) is used. OpenShell's existing
SSH code does NOT use ControlMaster — each `ssh` invocation is a new connection.

**Evidence:**
KICKSTART.md line 103-106: "ProxyCommand-based tunnel through gateway"
Architecture: "Reuses existing SSH config; no session negotiation" — incorrect, SSH
always negotiates.

**The Fix:**
Either:
1. Use SSH ControlMaster/ControlPersist to maintain a persistent SSH connection to
   each sandbox. First exec takes ~200ms; subsequent ones reuse the multiplexed
   connection at ~10ms. Add this as a design decision.
2. Relax NFR-002 to "< 100ms overhead for subsequent commands with connection reuse;
   < 500ms for first command."
3. Investigate whether the gateway supports connection keepalive/multiplexing natively.

Option 1 is the right answer. Document it as ADR-009.

---

### [HIGH] F-008: Observability Collector (COMP-005) Claims No Dependencies But Needs Sandbox PID Namespace

**Location:** `docs/architecture.md:176-189` (COMP-005 YAML)
**Category:** implicit-assumption

**The Problem:**
COMP-005 lists `dependencies: []` and `interfaces_consumed: []`. But to scope eBPF
probes to the sandbox's PID namespace, the collector needs to know the sandbox's
PID namespace ID (or cgroup). Where does it get this? It must query the gateway or
Docker to find the sandbox's container PID.

Also, `aya` (eBPF library) requires a BPF-capable kernel and root/CAP_BPF privileges.
This is not stated as a constraint anywhere in the PRD or architecture.

**Evidence:**
COMP-005 YAML: `dependencies: []`, `interfaces_consumed: []`
ADR-005: "requires Linux kernel 5.8+ for full eBPF features"
Missing: no mention of CAP_BPF requirement, no mention of how to discover sandbox PID ns

**The Fix:**
1. Add dependency on gateway API (to discover sandbox container PID/cgroup)
2. Add NFR-016: "Observability collector requires CAP_BPF (or root) on the host"
3. Add EC-018: "eBPF not available (macOS, older kernel, no CAP_BPF)" — Expected:
   graceful degradation to log-tailing-only mode with reduced observability

---

### [HIGH] F-009: Progress Bar on Default Upload (FR-003) Contradicts ADR-008

**Location:** `docs/prd.md:110` (FR-003), `docs/architecture.md:458-459` (ADR-008)
**Category:** contradiction

**The Problem:**
FR-003 says progress bar is shown on default upload (no `--rsync` flag needed).
ADR-008 says "Some enhancements (progress bar) are added to existing commands as
non-breaking visual additions." But the progress bar changes the stderr output of
`darkshell sandbox upload`. If DarkClaw is parsing stderr, a progress bar appearing
where none existed before IS a breaking change.

**Evidence:**
FR-003 Actor: "Operator", Action: "`darkshell sandbox upload <name> <local>` (default)"
ADR-008: "Existing command handlers are not modified. Default behavior is unchanged."

**The Fix:**
Progress bar must be opt-in OR only shown when stderr is a TTY (isatty check). When
stdout/stderr is piped (DarkClaw's programmatic use), no progress bar output. This
is standard CLI practice. Add this constraint to FR-003.

---

### [MEDIUM] F-010: rsync Fallback Detection Method Not Specified

**Location:** `docs/prd.md:108` (FR-001), `KICKSTART.md:319`
**Category:** ambiguous-language

**The Problem:**
FR-001 says "fall back to tar if rsync unavailable in sandbox." But how is availability
detected? Options:
- Run `which rsync` via exec before upload (adds latency)
- Try rsync, catch error, fall back (adds latency on failure)
- Check during sandbox creation and cache the result
- Let the user specify in the blueprint

Each has different performance and reliability characteristics.

**The Fix:**
Specify: "Detection via `darkshell sandbox exec <name> -- which rsync`. Cache result
per sandbox session. First upload pays detection cost (~200ms); subsequent uploads
use cached result."

---

### [MEDIUM] F-011: Blueprint `upload` Field Uses Ambiguous Colon Separator

**Location:** `docs/architecture.md:290` (Blueprint Schema)
**Category:** ambiguous-language

**The Problem:**
Blueprint schema: `upload: ["local:remote"]`. But what if the local path contains a
colon? On macOS, colons in filenames are rare but possible. On Linux, colons are
valid in paths. This is the same ambiguity Docker has with volume mounts, and Docker
solved it by requiring absolute paths (which start with `/`, disambiguating the colon).

**Evidence:**
Blueprint schema: `- "local:remote"`

**The Fix:**
Require absolute paths for local (must start with `/` or `~/`). If the local path
doesn't contain `/`, treat it as relative to the blueprint file's directory. Document
that colons in local paths are not supported (same limitation as Docker).

---

### [MEDIUM] F-012: MCP Bridge "max 3 retries" Could Leave Agent Without Tools Permanently

**Location:** `docs/architecture.md:332` (NFR-011), `docs/prd.md:191` (NFR-011)
**Category:** spec-gap

**The Problem:**
NFR-011 specifies "restart with backoff (1s, 2s, 4s, max 3 retries)." After 3 failed
restarts, the MCP server stays dead. The agent loses access to that tool for the rest
of its session. No notification to the operator. No recovery path.

For a factory run that takes hours, losing a tool after 7 seconds of retry is
unacceptable.

**The Fix:**
After max retries: (1) alert operator via webhook/watch stream, (2) continue retrying
at a slower rate (exponential backoff capped at 60s), (3) mark server as `degraded`
in `mcp list` output. Never give up permanently — always retry with bounded backoff.

---

### [MEDIUM] F-013: No Requirement for `--json` Output on Any DarkShell Command

**Location:** `docs/prd.md` (all FR sections)
**Category:** spec-gap

**The Problem:**
The product brief says "DarkClaw is the primary consumer" and "enhancements are
designed for programmatic use." But no FR specifies `--json` output for any command.
DarkClaw needs to parse exec output, mcp list results, health status, watch events.
Human-readable tables are unusable for programmatic consumption.

**Evidence:**
Product brief: "designed for programmatic use by DarkClaw's orchestration engine"
FR-007 (exec): no `--json` mentioned
FR-009 (mcp list): no `--json` mentioned
FR-026 (health): says "Structured JSON" — good, but only one of many commands

**The Fix:**
Add NFR-015: "All DarkShell commands that produce structured output must support
`--json` flag for machine-readable JSON output. This is required for: exec (exit
code + output), mcp list, health, watch, policy test, net-test, logs export."

---

### [MEDIUM] F-014: Snapshot Restore (FR-025) Says "Sandbox Must Be Stopped" But OpenShell Has No Stop Command

**Location:** `docs/prd.md:157` (FR-025)
**Category:** implicit-assumption

**The Problem:**
FR-025 constraint: "Sandbox must be stopped or recreated." But OpenShell has no
`sandbox stop` command. Sandboxes are either Ready, Error, or Deleted. There's no
pause/stop state. "Recreated" means delete + create, which destroys the sandbox
you're trying to restore into.

**Evidence:**
KICKSTART.md lines 166-173: CLI commands include create, get, delete, upload, download,
connect, ssh-config, list. No stop/pause/resume.

**The Fix:**
Clarify FR-025: "Restore creates a NEW sandbox from the snapshot. The snapshot
includes writable filesystem state but not running processes. The operator specifies
the base image and policy; the snapshot overlays the writable paths."

---

### [MEDIUM] F-015: `darkshell-observe` Requires `aya` (eBPF) Which Is Linux-Only

**Location:** `docs/architecture.md:97` (COMP-005), `docs/product-brief.md:76-77`
**Category:** implicit-assumption

**The Problem:**
OpenShell experimentally supports macOS via Docker Desktop. DarkShell inherits this.
But `darkshell-observe` uses `aya` for eBPF, which only works on Linux. If a developer
on macOS runs `darkshell sandbox watch`, it will fail with an obscure error.

The PRD has no mention of platform-specific degradation for observability features.

**The Fix:**
Add EC-019: "Observability commands on macOS/WSL" — Expected: graceful degradation
to log-tailing-only mode. eBPF features (file audit, process trace) unavailable
with clear message: "eBPF observability requires Linux. Falling back to log-based
monitoring." Feature-flag `darkshell-observe` so it can be compiled without `aya`
on non-Linux platforms.

---

### [MEDIUM] F-016: Component Map Lists FR-020 (MCP Logging) Under COMP-005 But It Should Be COMP-003

**Location:** `docs/architecture.md:189` (COMP-005 requirements)
**Category:** contradiction

**The Problem:**
COMP-005 (Observability Collector) lists FR-020 (MCP tool call logging). But
FR-020 says "Captured at bridge layer (host-side)" and KICKSTART.md P28 says
"Captured at the MCP bridge layer (P19)." The bridge layer is COMP-003
(MCP Bridge Daemon), not COMP-005 (Observability Collector).

**Evidence:**
FR-020: "Captured at bridge layer (host-side)"
COMP-005 requirements: [FR-017, FR-018, FR-019, FR-020, FR-021, FR-022, FR-023]
COMP-003 requirements: [FR-008, FR-009, FR-010, FR-011, FR-013]

**The Fix:**
Move FR-020 from COMP-005 requirements to COMP-003 requirements. COMP-003 logs MCP
tool calls; COMP-005 can aggregate and export those logs via its OTel pipeline.

---

### [MEDIUM] F-017: Layering Diagram Shows Incorrect Dependency Direction

**Location:** `docs/architecture.md:78-84` (Layering diagram)
**Category:** contradiction

**The Problem:**
The layering diagram shows:
```
darkshell-blueprint ──┐
darkshell-mcp ────────┤
darkshell-observe ────┤
                      ▼
openshell-cli → openshell-core → openshell-sandbox → openshell-server
```

This implies the new crates depend on `openshell-cli`. But COMP-004 (Blueprint Engine,
in `darkshell-blueprint`) depends on COMP-003 (MCP Bridge, in `darkshell-mcp`). And
`openshell-cli` depends on all three new crates (it imports them). The arrows should
point FROM `openshell-cli` TO the new crates, not the reverse.

**Evidence:**
COMP-004 YAML: `dependencies: [openshell-core, COMP-003]`
Crate layout: `openshell-cli` contains `src/mcp.rs` which uses `darkshell-mcp`

**The Fix:**
Correct the diagram:
```
openshell-cli ──→ darkshell-blueprint ──→ openshell-core
              ──→ darkshell-mcp ─────────→ openshell-core
              ──→ darkshell-observe ─────→ (no deps)
              ──→ openshell-core ──→ ...
```

---

### [MEDIUM] F-018: No Error Handling for Port Conflicts in MCP Bridge

**Location:** `docs/prd.md:125` (FR-008)
**Category:** spec-gap

**The Problem:**
FR-008 says the bridge auto-configures port forwards. But what port does it use?
If the operator adds 5 MCP servers, each needs its own port. Port selection,
conflict detection, and resolution are not specified.

OpenShell's `check_port_available()` handles port conflicts for manual forwards, but
the MCP bridge needs automatic port allocation.

**The Fix:**
Add to FR-008 constraints: "Bridge automatically selects available ports starting
from 9100. Port conflicts detected via `check_port_available()`. If preferred port
is taken, increment until available. Selected port recorded in MCP registration file."

---

### [LOW] F-019: Product Brief Claims "100% action coverage" But Lists Only 5 Categories

**Location:** `docs/product-brief.md:71` (Success Criteria)
**Category:** ambiguous-language

**The Problem:**
Success criterion: "100% (network, file, process, MCP, inference)." But agent actions
also include: environment variable reads, inter-process signals, shared memory access,
timer creation, and pipe operations. The claim of "100%" is overclaiming.

**The Fix:**
Change to "100% coverage of primary action categories (network connections, file
operations, process lifecycle, MCP tool calls, inference requests)." Explicitly
acknowledge that kernel-level operations (signals, shm) are not in scope.

---

### [LOW] F-020: KICKSTART Enhancement Numbers Skip P15-P18 in Priority Table

**Location:** `KICKSTART.md` Enhancement Summary table
**Category:** spec-gap

**The Problem:**
The enhancement summary table lists P15-P18 as "Nice" priority. But the text
descriptions for P15 (multi-sandbox orchestration) and P16 (observability export)
describe them as foundational infrastructure that other enhancements depend on.
P16 is required by P26 (OTel exporter) and P35 (SIEM adapters). If P16 is Nice
and P26 is Nice, who builds the export pipeline?

**The Fix:**
Either promote P16 to Should (observability export is required for P26 to be useful)
or document that P26 includes its own export mechanism independent of P16.

---

### [LOW] F-021: Workspace Features Syntax in Cargo.toml Is Invalid

**Location:** `docs/architecture.md:564-568` (Build Configuration)
**Category:** spec-gap

**The Problem:**
The Cargo.toml shows `[workspace.features]` with feature names like `mcp`, `observe`,
`blueprint`. But Cargo workspace features work differently — features are defined
per-crate, not per-workspace. The `[workspace.features]` section doesn't exist in
Cargo's TOML schema (as of Rust 1.85).

**Evidence:**
```toml
[workspace.features]
mcp = ["darkshell-mcp"]
```
This is not valid Cargo.toml.

**The Fix:**
Features should be defined on the `openshell-cli` crate's `Cargo.toml`:
```toml
[features]
default = ["full"]
mcp = ["dep:darkshell-mcp"]
observe = ["dep:darkshell-observe"]
blueprint = ["dep:darkshell-blueprint"]
full = ["mcp", "observe", "blueprint"]
```

---

### [LOW] F-022: ADR-007 Credential Stripping Is "Best Effort" — No Verification

**Location:** `docs/architecture.md:443` (ADR-007)
**Category:** spec-gap

**The Problem:**
ADR-007 acknowledges "Stripping is best-effort — unknown credential locations may
be missed." But there's no verification step. After stripping, there's no scan of
the saved image to verify no credentials remain. An operator who trusts `--confirm`
might push a credential-laden image to a registry.

**The Fix:**
Add a post-strip verification step: scan the saved image for common credential
patterns (API key formats, known env var names, SSH keys, `.env` files, AWS
credential patterns). Warn if any are found. This doesn't need to be perfect —
it's defense in depth.

---

## Convergence Status

**RESOLVED.** All 3 Critical findings addressed:
- F-001: MCP bridge proxy bypass → ADR-010 with compensating controls (bridge-layer policy + logging)
- F-002: exec timeout → Default 300s timeout added to FR-007
- F-003: inference logging vs. "never modify sandbox" → ADR-011: narrow, feature-flagged,
  read-only hook in proxy.rs. Only sandbox crate modification. Compiles to no-op when disabled.

All 6 High findings resolved. Medium/Low findings documented for story-level resolution.

**CONVERGENCE REACHED** — remaining findings are implementation-level detail, not spec flaws.
