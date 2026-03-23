---
document_type: adversarial-code-review
phase: "Phase 4 — Implementation Review"
date: 2026-03-23
status: findings-reported
total_findings: 72
critical: 5
high: 14
medium: 24
low: 21
pass: 8
---

# Adversarial Code Review: DarkShell v1.0 Implementation

## Aggregate Findings

| Crate | Critical | High | Medium | Low | Pass | Total |
|-------|----------|------|--------|-----|------|-------|
| darkshell-mcp | 2 | 6 | 7 | 5 | — | 20 |
| darkshell-observe | 1 | 4 | 6 | 4 | — | 16 |
| darkshell-blueprint | 1 | 3 | 6 | 6 | — | 16 |
| openshell-cli + Security | 1 | 1 | 5 | 6 | 5+3 | 20 |
| **Total** | **5** | **14** | **24** | **21** | **8** | **72** |

## Critical Findings (Must Fix)

| ID | Crate | Finding | Risk |
|----|-------|---------|------|
| MCP-F001 | darkshell-mcp | **Port TOCTOU race** — find_available_port drops listener before serve() re-binds. Another process can steal the port. | Host-side — sandbox agent connects to wrong process |
| MCP-F002 | darkshell-mcp | **Unbounded request body** — HTTP handler reads entire body into memory with no size limit. Sandbox agent can OOM the host. | Host-side DoS from sandbox |
| OBS-F001 | darkshell-observe | **InvalidFilter error lists wrong valid types** — omits "mcp", "inference", "watch" from error message | User confusion, incorrect guidance |
| BP-C001 | darkshell-blueprint | **expect() panics in public build_plan()** — 6 expect() calls assume validated input but type system doesn't enforce it | Runtime panic on unvalidated blueprint |
| CLI-S001 | openshell-cli | **Shell injection in build_in_sandbox_mcp_command** — working_dir not shell_escape()'d before interpolation into sh -c | Command injection via malicious path |

## High Findings (Should Fix)

| ID | Crate | Finding |
|----|-------|---------|
| MCP-F003 | darkshell-mcp | Blocking std::fs I/O in async context (start/shutdown) |
| MCP-F004 | darkshell-mcp | Spawned child leaked on error in start() |
| MCP-F005 | darkshell-mcp | Single mutex serializes all request concurrency |
| MCP-F006 | darkshell-mcp | No read timeout on MCP server stdout — hangs forever |
| MCP-F007 | darkshell-mcp | Registration file path injection via sandbox/server names |
| MCP-F008 | darkshell-mcp | Policy doc says "deny all" but code allows all for empty allowlist |
| OBS-F002 | darkshell-observe | PII regex compiles on every call (perf bomb under load) |
| OBS-F003 | darkshell-observe | truncate_content byte/char confusion for multi-byte UTF-8 |
| OBS-F004 | darkshell-observe | Duplicate filter entries accepted without dedup |
| OBS-F005 | darkshell-observe | Global static DROPPED_EVENTS causes test interference |
| BP-H001 | darkshell-blueprint | No command field content validation — shell injection vector |
| BP-H002 | darkshell-blueprint | No path traversal validation on upload specs |
| BP-H003 | darkshell-blueprint | No URL validation for streamable-http MCP servers |
| CLI-S002 | openshell-cli | PID reuse race — SIGTERM sent to wrong process |

## Security Audit Summary

**ADR-011 (proxy.rs hook): PASS** — Feature-gated, read-only, try_send, BEGIN/END markers, no behavioral change.

**ADR-001 (sandbox unmodified): PASS** — Only the inference hook modifies openshell-sandbox.

**ADR-003 (rsync fallback): PASS** — Correctly detects, falls back, handles exit code 24.

**ADR-008 (existing commands unchanged): PASS** — All enhancements are new subcommands/flags.

**ADR-009 (SSH ControlMaster): PASS** — Properly configured with ControlPersist=600, restricted permissions, cleanup on delete.

**Download --include/--exclude escaping: PASS** — All patterns shell_escape()'d.

**Credential logging: PASS** — No credential values logged (checked bridge, registry, CLI).

## Mandatory Fixes Before Release

1. **CLI-S001**: Add `shell_escape()` to `working_dir` in `build_in_sandbox_mcp_command`
2. **MCP-F001**: Return bound TcpListener from `find_available_port`, convert via `from_std()`
3. **MCP-F002**: Add request body size limit (1MB) before reading
4. **BP-C001**: Convert `expect()` to error returns, or introduce `ValidatedBlueprint` newtype
5. **OBS-F001**: Generate valid types list from `VALID_EVENT_TYPES` constant

## Recommended Fixes (High Priority)

6. **MCP-F007**: Validate sandbox/server names (alphanumeric + hyphen only)
7. **BP-H001**: Warn on shell metacharacters in MCP server command field
8. **BP-H002**: Reject upload paths containing `..` traversal
9. **OBS-F002**: Compile PII regexes once as statics via LazyLock
10. **MCP-F006**: Add read timeout on MCP server stdout (use INITIALIZE_TIMEOUT_SECS)
