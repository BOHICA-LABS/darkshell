# CLAUDE.md — DarkShell

@SOUL.md

## What This Is

DarkShell is a fork of [NVIDIA OpenShell](https://github.com/NVIDIA/OpenShell) (Apache 2.0)
with quality-of-life enhancements for the DarkClaw factory ecosystem. It adds delta uploads,
exec commands, multiple uploads, progress reporting, and sandbox snapshots without changing
OpenShell's security model (Landlock, seccomp, netns).

**Read `KICKSTART.md` first** — it contains the complete upstream architecture analysis,
all proposed enhancements with scope estimates, and the fork strategy.

## Build & Test

```bash
cargo build                        # Build all crates
cargo test                         # Run all tests
cargo clippy --workspace --all-targets --all-features -- -D warnings  # Lint
cargo +nightly fmt --all           # Format (requires nightly)
```

Rust 1.88+, Edition 2024.

## Git Workflow

**Git Flow** — branch from `develop`, PRs target `develop`, never commit directly to `main`.
- Branch naming: `feature/desc`, `fix/desc`
- Conventional commits enforced

## Upstream Relationship

- Upstream: `NVIDIA/OpenShell` (track `main` branch)
- Our enhancements live on `develop`
- Periodically merge upstream into `develop`
- Keep internal crate names matching upstream to ease merges

## Development Process — VSDD (Dark Factory Pattern)

This project follows Verified Spec-Driven Development. The process is documented at:
- `../dark-factory/VSDD.md` — VSDD methodology
- `../dark-factory/SOUL.md` — Factory values/principles
- `../dark-factory/FACTORY.md` — Factory constitution

**Phase flow:** Product Brief → PRD → Architecture → Adversarial Review → Stories → TDD Implementation

The product brief is captured in `KICKSTART.md`. The next step is to run the VSDD pipeline:
1. Write a formal product brief from KICKSTART.md (use `../dark-factory/templates/product-brief-template.md`)
2. Write the PRD (use `../dark-factory/templates/prd-template.md`)
3. Write the Architecture doc (use `../dark-factory/templates/architecture-template.md`)
4. Run adversarial review
5. Decompose into stories
6. Implement via TDD

## Key References

| Document | Location | Purpose |
|----------|----------|---------|
| Kickstart | `KICKSTART.md` | Complete upstream analysis, all enhancements, fork strategy |
| VSDD Methodology | `../dark-factory/VSDD.md` | How we develop software |
| Factory Values | `../dark-factory/SOUL.md` | Principles governing agent behavior |
| PRD Template | `../dark-factory/templates/prd-template.md` | PRD format to follow |
| Architecture Template | `../dark-factory/templates/architecture-template.md` | Architecture format |
| Product Brief Template | `../dark-factory/templates/product-brief-template.md` | Brief format |
| Story Template | `../dark-factory/templates/story-template.md` | Story format |
| OpenShell Source | `/tmp/OpenShell/` (cloned) or `https://github.com/NVIDIA/OpenShell` | Upstream codebase |
| DarkClaw Specs | `../DarkClaw/docs/` | Consumer of DarkShell enhancements |
| DarkClaw Workspace Strategy | `../DarkClaw/docs/workspace-strategy.md` | Why DarkShell exists |

## Claude Memory

Session context for DarkShell is in:
- `/Users/jmagady/.claude/projects/-Users-jmagady-Dev-axiathon/memory/openshell-proxy-internals.md`
- `/Users/jmagady/.claude/projects/-Users-jmagady-Dev-axiathon/memory/dark-factory-session-state.md`
- `/Users/jmagady/.claude/projects/-Users-jmagady-Dev-axiathon/memory/darkclaw-ecosystem.md`

## AI Attribution

Do NOT include in commit messages:
- The "Generated with Claude Code" line
- The "Co-Authored-By: Claude" line
