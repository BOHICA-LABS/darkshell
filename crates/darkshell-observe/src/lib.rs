//! `darkshell-observe` — Observability collector for `DarkShell`.
//!
//! This crate provides live event streaming for sandbox observation via
//! `darkshell sandbox watch`. It is the foundation for the full observability
//! stack (DS-016 through DS-020).
//!
//! # Architecture
//!
//! - **Pure-core modules:** `event`, `filter`, `parser` — no I/O, fully testable
//! - **Effectful shell:** `watch` — manages connections, channels, I/O
//!
//! # Platform support
//!
//! eBPF probes (DS-017+) require Linux 5.8+ with `CAP_BPF`. On other platforms,
//! the crate gracefully degrades to log-based monitoring.
//!
//! # Dependencies
//!
//! This crate does NOT depend on `openshell-sandbox` or `openshell-server`.
//! It only reads gateway logs and sandbox exec output.

#![forbid(unsafe_code)]

pub mod error;
pub mod event;
pub mod filter;
pub mod inference_log;
pub mod parser;
pub mod watch;

// Re-exports for convenience
pub use error::{ObserveError, Result};
pub use event::{
    CommandEvent, EventPayload, FileEvent, LifecycleEvent, McpToolCallEvent, NetworkEvent,
    PolicyEvent, WatchEvent, WatchMetaEvent,
};
pub use filter::EventFilter;
pub use inference_log::{InferenceEvent, RedactionConfig, redact_inference_event};
pub use watch::{EventStream, WatchConfig};
