# SOUL.md — The Spirit of DarkShell

*Adapted from the Axiathon SOUL.md, tailored for a kernel-level sandbox runtime.*

These principles guide how Claude should work in this project. Language-specific rules live in `.claude/rules/`.

---

## 1. Pragmatism Over Purity

Every rule in this document has a cost. Apply rules where their benefit exceeds their cost at the project's current maturity. When someone proposes a hardening measure, ask: "What's the threat model, and does the ROI justify the investment right now?"

This principle governs all others. When two principles conflict, the one with better ROI wins.

---

## 2. Make the Wrong Thing Impossible

Don't rely on discipline. Rely on design. If a path must be absolute, make the type enforce it. If a policy field only accepts two values, make it an enum — not a string.

**Push policy into the type system.** Humans forget. Toolchains don't.

- Validated constructors at trust boundaries; unchecked constructors only for tests and trusted internals
- Make invalid states unrepresentable through types, not documentation

---

## 3. The Spec Is More Important Than the Code

The code is disposable. The spec is the product. If you deleted every line of code and regenerated from the spec, the result should be correct — because the spec absorbed every lesson.

- Read the spec before writing code. It is the single source of truth.
- If the spec is wrong, fix the spec first, then implement. Never silently deviate.
- Update story artifacts in the same PR as the code.

**When fixing a bug, ask: "What spec gap allowed this?"** Then fix the right file:

| Gap type | Fix it in |
|----------|-----------|
| Universal principle | SOUL.md |
| Project-specific instruction | CLAUDE.md or `.claude/rules/` |
| Structural decision | Architecture doc |
| Under-specified requirement | Story AC or PRD |

---

## 4. Silent Failures Are the Enemy

The single most dangerous failure mode in sandbox tooling: **something fails silently and the user doesn't know.** A policy that loads but doesn't match. A tar upload that completes but is corrupt. An SSH tunnel that dies without notification.

- Every operation must report success or failure explicitly
- Never swallow stderr — capture it and surface it
- If a subprocess exits non-zero, capture its output and include it in the error
- A vacuously successful operation is worse than a visible failure

---

## 5. Errors Are Domain Knowledge, Not Strings

Errors should be structured, semantic, and domain-specific. Not string bags.

- Error messages must include: what failed, why, and how to fix it
- When a subprocess fails, parse known error patterns and translate to actionable guidance
- "Error: exit code 1" is useless. "Error: sandbox 'dev' not found. Available: dark-code, dark-publisher" is useful.

---

## 6. Upstream Compatibility Is Sacred

DarkShell is a fork of OpenShell. Every change must be additive — no security downgrades, no isolation weakening, no behavior changes for existing commands.

- All upstream OpenShell commands must continue to work identically
- New features are new commands or new flags — never modified semantics of existing ones
- Keep internal crate names matching upstream to ease periodic merges
- When upstream and our enhancement conflict, upstream wins — we adapt

---

## 7. Explain Why, Not Just What

PR descriptions lead with motivation. Comments explain design constraints and security implications, not just behavior.

Good: `Delta upload falls back to full tar when rsync is unavailable in the sandbox image, preserving compatibility with upstream base images.`
Bad: `Added rsync support.`

---

## 8. Test Boundaries, Name Tests Like Documentation

Test names are executable documentation: `upload_respects_gitignore_by_default()` tells you the contract. Not `test_upload()`.

Test boundaries explicitly: empty directories, large files, symlinks, permission-denied paths, interrupted transfers, stale PIDs. Boundaries are where bugs live.

---

## 9. Observability Is Infrastructure

Every operation should be traceable. Structured logging from the start.

- Upload/download operations log: source, destination, size, duration, method (tar/rsync)
- Port forwards log: port, sandbox, PID, bind address
- Policy operations log: preset name, endpoints added/removed, apply result
- Use `tracing` crate with structured fields, not println

---

## 10. Standards Over Invention

When a standard exists and fits, adopt it. rsync is a standard. tar is a standard. SSH is a standard. Don't invent custom protocols when established ones work.

- Use rsync for delta transfers (not a custom diff protocol)
- Use tar for bulk transfers (upstream's pattern)
- Use SSH for remote execution (upstream's pattern)
- Use JSON for structured output (upstream's `--json` flags)

---

## 11. Security Model Is Inherited, Not Invented

DarkShell's security model IS OpenShell's security model. We don't design our own isolation — we enhance the developer experience around an existing, audited isolation boundary.

- Landlock filesystem restrictions: inherited, not modified
- seccomp system call filters: inherited, not modified
- Network namespace isolation: inherited, not modified
- OPA policy evaluation: inherited, not modified
- SSRF protection: inherited, not modified

If an enhancement would require weakening any of these, we don't do it.

---

## 12. Layered Architecture, Strictly Acyclic

The dependency graph flows one direction. No circular dependencies. The crate structure mirrors upstream:

```
openshell-cli → openshell-core → openshell-sandbox → openshell-server
```

Our enhancements live within these existing boundaries. If a new feature doesn't fit the layer it belongs in, the design is wrong.

---

## 13. Behavior Is Configuration; Policy Is Types

Transfer method (tar vs rsync), progress reporting verbosity, default bind address — these are configuration.

Security policies (Landlock rules, seccomp filters, network policies, SSRF protection) — these are types and kernel enforcement. Never configurable in a way that could weaken isolation.

---

## Current State (March 2026)

Fork not yet created from upstream. Kickstart document captures 14 proposed enhancements.
Next: run VSDD pipeline (product brief → PRD → architecture → stories → implementation).
