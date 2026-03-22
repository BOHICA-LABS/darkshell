---
document_type: story-index
product: DarkShell
prd_version: "1.0"
architecture_version: "1.0"
total_stories: 33
total_points: 191
v1_stories: 16
v1_points: 101
---

# DarkShell Story Index

## Epics

| Epic | Title | Stories | Points | Priority |
|------|-------|--------|--------|----------|
| EPIC-001 | Fork Foundation | 1 | 5 | Must |
| EPIC-002 | Fast File Transfer | 5 | 26 | Must/Should |
| EPIC-003 | Execution | 1 | 8 | Must |
| EPIC-004 | MCP Integration | 6 | 39 | Must/Should |
| EPIC-005 | Sandbox Blueprints | 2 | 13 | Must |
| EPIC-006 | Observability | 6 | 42 | Should/Nice |
| EPIC-007 | Lifecycle & Operations | 12 | 58 | Nice |

## All Stories

| Story | Epic | Title | Pts | FRs | Depends On | Wave | v1.0? |
|-------|------|-------|-----|-----|------------|------|-------|
| DS-001 | 001 | Fork OpenShell, rename binary, verify build | 5 | — | — | 1 | Y |
| DS-002 | 002 | Add rsync delta upload with tar fallback | 8 | FR-001 | DS-001 | 2 | Y |
| DS-003 | 002 | Support multiple --upload on sandbox create | 3 | FR-002 | DS-001 | 2 | Y |
| DS-004 | 002 | Add progress bar to upload and download | 5 | FR-003, FR-006 | DS-001 | 2 | Y |
| DS-005 | 002 | Add download --include/--exclude filtering | 5 | FR-004 | DS-001 | 2 | Y |
| DS-006 | 002 | Add upload --dry-run preview | 5 | FR-005 | DS-002 | 3 | Y |
| DS-007 | 003 | Add sandbox exec with SSH ControlMaster | 8 | FR-007 | DS-001 | 2 | Y |
| DS-008 | 004 | Implement MCP bridge daemon (stdio-to-HTTP) | 13 | FR-008, FR-013 | DS-001, DS-007 | 3 | Y |
| DS-009 | 004 | Add MCP CLI management (add/list/remove) | 8 | FR-009, FR-010, FR-038 | DS-008 | 4 | Y |
| DS-010 | 004 | Add MCP tool-level policy at bridge layer | 5 | FR-011 | DS-008 | 4 | Y |
| DS-011 | 004 | Support in-sandbox stdio MCP servers | 3 | FR-012 | DS-007 | 3 | Y |
| DS-012 | 004 | Support Streamable HTTP MCP transport | 5 | FR-014 | DS-009 | 5 | |
| DS-013 | 004 | Add MCP tool call logging at bridge layer | 5 | FR-020 | DS-008 | 4 | Y |
| DS-014 | 005 | Define blueprint schema and validation | 5 | FR-016 | DS-001 | 2 | Y |
| DS-015 | 005 | Implement blueprint-based sandbox creation | 8 | FR-015 | DS-014, DS-009, DS-003 | 5 | Y |
| DS-016 | 006 | Add sandbox watch (live event stream) | 8 | FR-017 | DS-007 | 3 | Y |
| DS-017 | 006 | Add eBPF file access audit logging | 8 | FR-019 | DS-016 | 4 | |
| DS-018 | 006 | Add eBPF process tree tracing | 5 | FR-021 | DS-016 | 4 | |
| DS-019 | 006 | Add OpenTelemetry metrics/trace export | 8 | FR-018 | DS-016 | 4 | |
| DS-020 | 006 | Add inference request/response logging hook | 8 | FR-022 | DS-016 | 4 | Y |
| DS-021 | 006 | Add behavioral baseline and alerting | 5 | FR-023 | DS-017, DS-018, DS-019 | 5 | |
| DS-022 | 007 | Add sandbox snapshot and restore | 8 | FR-024, FR-025 | DS-007 | 3 | |
| DS-023 | 007 | Add sandbox health monitoring | 3 | FR-026 | DS-007 | 3 | |
| DS-024 | 007 | Add resource limits on sandbox create | 3 | FR-027 | DS-001 | 2 | |
| DS-025 | 007 | Add policy validate and policy test | 5 | FR-030, FR-031 | DS-001 | 2 | |
| DS-026 | 007 | Add sandbox net-test diagnostics | 3 | FR-032 | DS-007 | 3 | |
| DS-027 | 007 | Add sandbox logs export | 3 | FR-033 | DS-001 | 2 | |
| DS-028 | 007 | Add sandbox image save with sanitization | 5 | FR-029 | DS-007 | 3 | |
| DS-029 | 007 | Add credential rotation for running sandboxes | 5 | FR-028 | DS-001 | 2 | |
| DS-030 | 007 | Add policy-as-code GitOps reconciliation | 8 | FR-034 | DS-025 | 3 | |
| DS-031 | 007 | Add observability export adapters (SIEM) | 5 | FR-035 | DS-019 | 5 | |
| DS-032 | 007 | Add sandbox watch --webhook for events | 3 | FR-036 | DS-016 | 4 | |
| DS-033 | 007 | Add multi-sandbox fleet orchestration | 8 | FR-037 | DS-009 | 5 | |

## Dependency DAG

```
Wave 1:  DS-001
              │
Wave 2:  ┌────┼────┬────┬────┬────┬────┬────┬────┬────┐
         002  003  004  005  007  014  024  025  027  029
              │              │         │         │
Wave 3:  006──┘  008─────011 016  022  023  026  028  030
                  │               │
Wave 4:      009  010  013   017  018  019  020  032
              │               │    │    │
Wave 5:  012  015────────021──┘    031       033
```

## v1.0 Critical Path

```
DS-001 → DS-007 → DS-008 → DS-009 → DS-015
  (5)      (8)      (13)     (8)      (8)
                                    = 42 points on critical path
```

The critical path runs through the MCP integration epic. DS-008 (MCP bridge daemon)
is the largest single story at 13 points — consider splitting if implementation
reveals independent sub-features.

## FR Traceability

| FR | Story | Status |
|----|-------|--------|
| FR-001 | DS-002 | v1.0 |
| FR-002 | DS-003 | v1.0 |
| FR-003 | DS-004 | v1.0 |
| FR-004 | DS-005 | v1.0 |
| FR-005 | DS-006 | v1.0 |
| FR-006 | DS-004 | v1.0 |
| FR-007 | DS-007 | v1.0 |
| FR-008 | DS-008 | v1.0 |
| FR-009 | DS-009 | v1.0 |
| FR-010 | DS-009 | v1.0 |
| FR-011 | DS-010 | v1.0 |
| FR-012 | DS-011 | v1.0 |
| FR-013 | DS-008 | v1.0 |
| FR-014 | DS-012 | v1.1 |
| FR-015 | DS-015 | v1.0 |
| FR-016 | DS-014 | v1.0 |
| FR-017 | DS-016 | v1.0 |
| FR-018 | DS-019 | v1.1 |
| FR-019 | DS-017 | v1.1 |
| FR-020 | DS-013 | v1.0 |
| FR-021 | DS-018 | v1.1 |
| FR-022 | DS-020 | v1.0 |
| FR-023 | DS-021 | v1.1 |
| FR-024 | DS-022 | v1.1 |
| FR-025 | DS-022 | v1.1 |
| FR-026 | DS-023 | v1.1 |
| FR-027 | DS-024 | v1.1 |
| FR-028 | DS-029 | v1.1 |
| FR-029 | DS-028 | v1.1 |
| FR-030 | DS-025 | v1.1 |
| FR-031 | DS-025 | v1.1 |
| FR-032 | DS-026 | v1.1 |
| FR-033 | DS-027 | v1.1 |
| FR-034 | DS-030 | v1.1 |
| FR-035 | DS-031 | v1.1 |
| FR-036 | DS-032 | v1.1 |
| FR-037 | DS-033 | v1.1 |
| FR-038 | DS-009 | v1.0 |
