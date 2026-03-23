// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structured error types for the MCP bridge daemon.
//!
//! Every variant includes what failed, why, and how to fix it.

/// **SECURITY:** Display impl is for internal logging only. Credential values
/// are never included in error messages.
#[derive(Debug, thiserror::Error, serde::Serialize)]
#[non_exhaustive]
pub enum BridgeError {
    /// MCP server command failed to start (binary not found, permission denied, etc.).
    #[error(
        "failed to start MCP server: {reason}. \
         Command attempted: `{command}`. \
         Ensure the command is installed and accessible on the host PATH"
    )]
    StartupFailed {
        command: String,
        reason: String,
    },

    /// All ports in the configured range are occupied.
    #[error(
        "no available ports in range {start}-{end} for MCP bridge. \
         Free a port with: lsof -i :<port> -sTCP:LISTEN | kill <PID>"
    )]
    NoAvailablePort {
        start: u16,
        end: u16,
    },

    /// A specific port is already in use.
    #[error("port {port} is already in use")]
    PortInUse {
        port: u16,
    },

    /// Credential retrieval failed — gateway provider API unavailable.
    #[error(
        "cannot retrieve credentials: gateway provider API unavailable. \
         Check gateway status with: darkshell status"
    )]
    ProviderUnavailable,

    /// Provider exists but the requested credential key is missing.
    #[error(
        "provider '{provider}' exists but credential '{key}' not found. \
         Set with: darkshell provider create --name {provider} --credential {key}=<value>"
    )]
    CredentialNotFound {
        provider: String,
        key: String,
    },

    /// MCP server returned invalid JSON-RPC response.
    #[error("MCP server returned invalid JSON-RPC: {detail}")]
    InvalidJsonRpc {
        detail: String,
    },

    /// MCP server did not respond to initialize within timeout.
    #[error(
        "MCP server did not respond to initialize within {timeout_secs}s. \
         Check that the command produces JSON-RPC output on stdout"
    )]
    InitializeTimeout {
        timeout_secs: u64,
    },

    /// MCP server subprocess crashed and max retries exhausted.
    #[error(
        "MCP server crashed {attempts} times and max retries exhausted. \
         Last exit: {last_exit}. Check server logs for crash cause"
    )]
    MaxRetriesExhausted {
        attempts: u32,
        last_exit: String,
    },

    /// Sandbox not found.
    #[error(
        "sandbox '{name}' not found. Available sandboxes: {available}"
    )]
    SandboxNotFound {
        name: String,
        available: String,
    },

    /// A bridge is already running for this sandbox+server combination.
    #[error(
        "bridge already running for sandbox '{sandbox}' server '{server}' (PID {pid}). \
         Stop it first with: darkshell mcp remove {sandbox} {server}"
    )]
    AlreadyRunning {
        sandbox: String,
        server: String,
        pid: u32,
    },

    /// Registration file I/O error.
    #[error("registration file error: {reason}")]
    RegistrationIo {
        reason: String,
    },

    /// HTTP server error.
    #[error("HTTP server error: {reason}")]
    HttpServer {
        reason: String,
    },

    /// Subprocess I/O error.
    #[error("subprocess I/O error: {reason}")]
    SubprocessIo {
        reason: String,
    },

    /// JSON serialization/deserialization error.
    #[error("JSON error: {reason}")]
    Json {
        reason: String,
    },

    /// Tool call denied by policy.
    #[error(
        "tool '{tool}' denied by policy for server '{server}': {reason}. \
         Update the policy with: darkshell policy set --mcp-tools"
    )]
    ToolDenied {
        tool: String,
        server: String,
        reason: String,
    },

    /// Policy configuration is invalid.
    #[error("invalid MCP tool policy: {reason}")]
    InvalidPolicy {
        reason: String,
    },

    /// Policy file I/O error.
    #[error("policy file error: {reason}")]
    PolicyIo {
        reason: String,
    },
}

/// Crate-level result type.
pub type Result<T> = std::result::Result<T, BridgeError>;
