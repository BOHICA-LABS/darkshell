//! Structured error types for the darkshell-observe crate.

use thiserror::Error;

/// Errors that can occur during sandbox watch operations.
///
/// **SECURITY:** Display impls are for internal logging only. Sanitize before
/// sending to external clients.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ObserveError {
    /// The requested sandbox does not exist.
    #[error("sandbox '{name}' not found. Available sandboxes: {available}")]
    SandboxNotFound {
        /// Name that was requested.
        name: String,
        /// Comma-separated list of available sandbox names.
        available: String,
    },

    /// A filter string could not be parsed into a known event type.
    #[error(
        "unknown event type filter '{filter}'. Valid types: command, file, network, policy, mcp, lifecycle, inference, watch"
    )]
    InvalidFilter {
        /// The filter string that was not recognized.
        filter: String,
    },

    /// Failed to serialize an event to JSON.
    #[error("failed to serialize event to JSON: {source}")]
    Serialization {
        /// The underlying `serde_json` error.
        #[from]
        source: serde_json::Error,
    },

    /// Connection to the event source was lost.
    #[error("connection to event source lost: {reason}. Reconnecting...")]
    ConnectionLost {
        /// Description of why the connection was lost.
        reason: String,
    },

    /// Failed to parse a log line into a structured event.
    #[error("failed to parse log line at byte offset {offset}: {reason}")]
    ParseError {
        /// Byte offset in the log stream where the error occurred.
        offset: u64,
        /// Description of the parse failure.
        reason: String,
    },

    /// An I/O error occurred during event streaming.
    #[error("I/O error during event streaming: {source}")]
    Io {
        /// The underlying I/O error.
        #[from]
        source: std::io::Error,
    },
}

/// Crate-level Result alias.
pub type Result<T> = std::result::Result<T, ObserveError>;
