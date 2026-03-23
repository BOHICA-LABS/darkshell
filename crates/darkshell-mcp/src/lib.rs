// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP bridge daemon — host-side stdio-to-HTTP proxy for MCP servers.
//!
//! This crate implements the MCP bridge daemon (COMP-003) that runs on the host
//! and proxies JSON-RPC messages between MCP server subprocesses (via stdio)
//! and sandbox agents (via HTTP over port-forwarded connections).
//!
//! # Architecture
//!
//! ```text
//! HOST: darkshell-mcp bridge daemon
//!   ├── Spawns MCP server subprocess (stdio)
//!   ├── Translates JSON-RPC stdio <-> HTTP
//!   ├── Injects credentials from provider system
//!   ├── Auto-selects available port (starting 9100)
//!   └── Exposes HTTP endpoint for sandbox agent
//!
//! SANDBOX: Agent connects to localhost:<port> via port forward
//! ```
//!
//! # Security Model
//!
//! - Bridge runs on HOST, never in sandbox (ADR-002)
//! - Credentials are injected into subprocess env only — never logged, never
//!   written to disk, never sent to the sandbox
//! - Port-forwarded traffic bypasses sandbox OPA proxy (ADR-010);
//!   compensating controls: bridge-layer policy (DS-010), MCP logging (DS-013)

#![forbid(unsafe_code)]

pub mod bridge;
pub mod credential;
pub mod error;
pub mod registry;

// Re-export primary types for ergonomic imports
pub use bridge::{BridgeConfig, McpBridge, PORT_RANGE_END, PORT_RANGE_START};
pub use credential::{CredentialProvider, CredentialSpec, EnvCredentialProvider};
pub use error::{BridgeError, Result};
pub use registry::{
    BridgeRegistration, BridgeStatus, Transport, cleanup_sandbox, list_registrations,
    read_registration, remove_registration, write_registration,
};
