<!-- Implementation rules for SOUL.md principles. SOUL owns "why", this file owns "how". -->

# Rust Coding Rules

Project-specific Rust conventions for Axiathon.

## Safety

- Every application crate: `#![forbid(unsafe_code)]`
- No `unwrap()` in production code — use `?` or `expect()` with actionable message
- No blocking the async runtime — use `spawn_blocking` for CPU-intensive work, `tokio::time::sleep` not `std::thread::sleep`

## Type Design

- **Newtypes for IDs:** `TenantId(String)`, `EventId(Uuid)`, `AlertId(Uuid)` — prevents mixing ID types
- **Validated constructors at trust boundaries:** `new()` validates (API input, deserialization); `new_unchecked()` for tests and trusted internal sources (database reads)
- **`#[non_exhaustive]` on enums that will grow** — forces callers to handle future variants
- **UUID v7 for time-ordered IDs:** `EventId` and `AlertId` use `Uuid::now_v7()` for time-sortable ordering
- **Private fields with getters** on security-critical types (`TenantContext`, `SystemContext`)

## Error Handling

- Use `thiserror` for error enums — structured, semantic variants (not string bags)
- Define `pub type Result<T> = std::result::Result<T, AxiathonError>` per crate
- `Display` impl is for internal logging only — sanitize before sending to clients
- Mark this with a `/// **SECURITY:** ...` comment on every error type's Display

## Tenant Context

- `&TenantContext` — user operations (has user_id, roles, permissions)
- `&SystemContext` — background jobs (has system_component, no user/roles)
- `&impl TenantScoped` — works with either (needs only tenant_id + trace_id)
- Never use global/thread-local tenant state
- Include `tenant_id()` and `trace_id()` in all tracing spans

## Module Structure

```
axiathon-{crate}/
  src/
    lib.rs          # Public API re-exports only
    error.rs        # Crate-specific error types
    config.rs       # Configuration types
    {domain}/       # Feature-specific modules
```

## Dependencies

- Workspace-level dependency declarations in root `Cargo.toml`
- Edition 2024, MSRV 1.85+
- Key crates: `tokio` (async), `serde`/`serde_json` (serialization), `tracing` (observability), `arrow`/`datafusion` (columnar data), `chumsky` (parser combinators with error recovery)
- Use `cargo clippy -- -D warnings` — warnings are errors

## Testing

- Unit: `#[cfg(test)] mod tests {}` in same file
- Integration: `tests/` directory, named by feature
- Property: `tests/property_*.rs` with `proptest`
- Snapshot: `tests/snapshot_*.rs` with `insta`
- Test names as documentation: `tenant_id_new_rejects_empty()`, not `test_1()`
- Test boundaries: empty, too-long, whitespace, case, invalid formats

## Architecture

- Dependency graph is strictly acyclic: `core` → domain crates → API/TUI
- No circular dependencies between crates
- `lib.rs` is a pure re-export barrel — implementation in domain modules
- OCSF typed accessors (`event.src_endpoint().ip()?`), never raw JSON paths
