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
  │     └── Delta upload, exec, snapshots, progress
  │
  └── Falls back to openshell — upstream, always works
        └── Full tar upload, SSH for commands, no snapshots
```

DarkClaw v1 ships with upstream OpenShell support. DarkShell enhancements are
additive — DarkClaw gains speed and UX when DarkShell is installed but never
requires it.

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
