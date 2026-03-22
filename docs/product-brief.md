---
document_type: product-brief
product_name: "DarkShell"
author: "DarkClaw Team"
date: 2026-03-22
status: draft
---

# Product Brief: DarkShell

## What Is This?

DarkShell is a fork of NVIDIA OpenShell that enhances the developer experience for
AI agent sandboxes without changing the upstream security model. It adds fast file
transfer (rsync delta uploads), direct command execution, first-class MCP server
management, full sandbox observability, and declarative blueprint-based sandbox
creation — the "getting code in, running commands, connecting tools, and seeing
what's happening" layer that OpenShell lacks.

## Who Is It For?

| Persona | Pain Point | Current Workaround |
|---------|-----------|-------------------|
| **DarkClaw orchestration engine** | Needs to push code, run builds, and connect MCP servers inside sandboxes hundreds of times per factory run | Multiple manual SSH sessions, full tar re-uploads for every change, no MCP integration, blind to agent behavior |
| **Factory operators** | Can't see what agents are doing inside sandboxes, can't diagnose failures without SSH + manual log collection | SSH into sandbox, grep logs manually, reconstruct timeline from fragments |
| **AI agent developers** | Setting up a sandbox with the right image, policy, credentials, MCP servers, and port forwards requires 5+ manual commands | Run each command separately, maintain shell scripts, hope nothing drifts |

## Scope

### In Scope

- **Fast file transfer:** Delta uploads via rsync-over-SSH, multiple upload paths,
  download filtering, progress reporting with ETA, dry-run preview
- **Direct execution:** Non-interactive command execution inside sandboxes without
  SSH session overhead
- **MCP server integration:** Managed bridge daemon for stdio MCP servers, CLI for
  adding/removing MCP servers, credential isolation, tool-level policy, in-sandbox
  and Streamable HTTP transport support
- **Sandbox observability:** Real-time event streaming, OpenTelemetry metrics/traces,
  file access audit logs, MCP tool call logging, process tree tracing, inference
  request logging, behavioral baseline alerting
- **Declarative sandbox configuration:** Blueprint YAML combining image + policy +
  providers + MCP servers + port forwards + resource limits in one file
- **Sandbox lifecycle:** Snapshots/restore, health monitoring, resource limits,
  credential rotation, sanitized image save
- **Operational tooling:** Policy validation dry-run, networking diagnostics, log
  export, observability export adapters, policy-as-code GitOps, multi-sandbox
  orchestration, event/webhook notifications

### Out of Scope

- **Modifying OpenShell's security model:** Landlock, seccomp, network namespaces,
  OPA policy evaluation, SSRF protection, TLS termination — all inherited unchanged
- **Runtime tool installation into protected directories:** Rejected (P32, P35)
  because it violates Landlock's irreversible kernel enforcement
- **Multi-tenancy and RBAC:** Enterprise feature, upstream's responsibility
- **General-purpose application runtime:** DarkShell is for AI agent sandboxes, not
  web apps or microservices
- **Community MCP server vetting/scanning:** Upstream ecosystem concern
- **GPU scheduling across sandboxes:** k3s/k8s territory
- **Compliance certifications:** NVIDIA's responsibility

## Success Criteria

| Outcome | Metric | Target |
|---------|--------|--------|
| File transfer speed improvement | Time to upload 2GB project with 1 file changed | < 2 seconds (vs 30+ seconds with full tar) |
| Command execution overhead | Time for single command (e.g., `git status`) | < 100ms (vs 200-500ms SSH session setup) |
| Sandbox setup time | Time from blueprint YAML to ready sandbox with MCP servers | < 60 seconds, single command |
| Observability coverage | Percentage of agent actions visible without SSH | 100% (network, file, process, MCP, inference) |
| Security model preservation | Number of kernel-enforced security mechanisms weakened | Zero |
| Upstream merge compatibility | Successful merge of upstream OpenShell updates | Every upstream release within 1 week |

## Constraints & Integration Points

- **Rust 1.85+, Edition 2024** — same as upstream OpenShell
- **Internal crate names must match upstream** (`openshell-cli`, `openshell-core`,
  `openshell-sandbox`, `openshell-server`) to ease periodic upstream merges
- **Binary renamed** `openshell` -> `darkshell` — DarkClaw detects which is available
  at runtime and uses enhanced features when `darkshell` is present
- **All enhancements are additive** — new commands or new flags only. Never modify
  semantics of existing OpenShell commands
- **Apache 2.0 license** — same as upstream, with fork attribution
- **Git Flow branching** — branch from `develop`, PRs target `develop`, never
  commit directly to `main`
- **Security invariant:** No enhancement may weaken or bypass any kernel-enforced
  security mechanism (Landlock, seccomp, netns, SSRF protection)
- **DarkClaw is the primary consumer** — enhancements are designed for programmatic
  use by DarkClaw's orchestration engine, with CLI UX as a secondary benefit
- **OpenShell upstream tracks `main` branch** — we periodically merge upstream into
  `develop`

## Overflow Context (Optional -- Reference Only)

### Why Fork Instead of Contribute Upstream

OpenShell is NVIDIA's product with its own roadmap. Our enhancements are specific to
the DarkClaw factory workflow — delta uploads, MCP bridge daemons, and blueprint-based
creation aren't general-purpose enough for upstream. Forking lets us move fast while
maintaining upstream compatibility through periodic merges.

### OpenShell's Purpose (Deep Research, March 2026)

NVIDIA OpenShell is a secure runtime environment for autonomous AI agents. It provides
kernel-level sandbox isolation (Landlock + seccomp + network namespaces) with a
gateway/sandbox architecture where the gateway is the control plane and sandboxes are
isolated execution environments. Key capabilities: deny-by-default security across
filesystem, network, and process layers; OPA-based policy evaluation with binary-level
network scoping; provider-based credential management; privacy router for inference
routing; hot-reloadable network policies.

Released under Apache 2.0 with enterprise partners including Cisco AI Defense,
CrowdStrike Falcon, and Trend Micro TrendAI for extended security integration.

### Enhancement Prioritization Rationale

**Must (7):** P1 (delta upload), P2 (multi-upload), P3 (exec), P4 (progress),
P19 (MCP bridge), P20 (MCP CLI), P34 (blueprints) — These are the minimum viable
enhancements that make DarkShell useful for DarkClaw factory workflows. Without
delta upload and exec, every factory phase is painfully slow. Without MCP bridge,
factory agents can't use their tools. Without blueprints, sandbox setup is manual.

**Should (8):** P5, P7, P10, P22–P24, P25, P28 — Important for production quality
but factory can function without them using workarounds.

**Nice (17):** P6, P8, P9, P11–P18, P21, P26, P27, P29–P31, P33 — Valuable for
mature operations but not blocking factory v1.

### Security Decisions

Two proposed enhancements were explicitly rejected during security analysis:
- P32 (sandbox extend --install) — violates Landlock immutability
- P35 (writable tool overlay) — circumvents kernel-enforced filesystem isolation

One enhancement requires mandatory safeguards:
- P33 (sandbox image save) — requires credential stripping + operator approval

All other enhancements operate outside the security boundary (client-side, host-side,
or read-only observation) or strictly strengthen security (P9, P13, P21, P23, P31).

### Key Source Code References

| File | Purpose |
|---|---|
| `crates/openshell-sandbox/src/sandbox/linux/landlock.rs` | `restrict_self()` — irreversible kernel lockdown |
| `crates/openshell-sandbox/src/sandbox/linux/seccomp.rs` | `PR_SET_NO_NEW_PRIVS` + BPF syscall filter |
| `crates/openshell-sandbox/src/sandbox/linux/netns.rs` | Network namespace + veth pair creation |
| `crates/openshell-sandbox/src/opa.rs` | `reload_from_proto()` — hot-reload network policy |
| `crates/openshell-sandbox/src/process.rs` | `pre_exec` — drop privileges then apply sandbox |
| `crates/openshell-sandbox/src/proxy.rs` | 2598-line HTTP proxy, SSRF protection, OPA eval |
| `crates/openshell-cli/src/ssh.rs` | Upload/download (tar-over-SSH), exec, SSH tunnel |
| `crates/openshell-cli/src/main.rs` | CLI command definitions (Clap) |
| `proto/openshell.proto` | gRPC definitions, static vs dynamic policy fields |
