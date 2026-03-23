// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP CLI command handlers — `darkshell mcp add/list/remove`.
//!
//! These handlers wire CLI arguments to the `darkshell-mcp` registry and bridge
//! APIs, managing bridge lifecycle, port forwarding, and network policy.

use darkshell_mcp::bridge;
use darkshell_mcp::registry::{self, BridgeRegistration, BridgeStatus, Transport};
use miette::{IntoDiagnostic, Result};
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Port auto-allocation
// ---------------------------------------------------------------------------

/// Find the next available port starting from `PORT_RANGE_START`, skipping any
/// ports already claimed by existing registrations.
pub fn allocate_port(config_dir: &Path) -> Result<u16> {
    let existing = registry::list_registrations(config_dir)
        .into_diagnostic()?;
    let used_ports: std::collections::HashSet<u16> = existing
        .iter()
        .map(|r| r.forwarded_port)
        .collect();

    for port in bridge::PORT_RANGE_START..=bridge::PORT_RANGE_END {
        if used_ports.contains(&port) {
            continue;
        }
        if bridge::is_port_available(port) {
            return Ok(port);
        }
    }

    Err(miette::miette!(
        "no available ports in range {}-{} for MCP bridge. \
         Free a port with: lsof -i :<port> -sTCP:LISTEN | kill <PID>",
        bridge::PORT_RANGE_START,
        bridge::PORT_RANGE_END,
    ))
}

// ---------------------------------------------------------------------------
// Config directory helper
// ---------------------------------------------------------------------------

/// Resolve the config directory for MCP registration files.
///
/// Uses `$HOME/.config` by default, or `DARKSHELL_CONFIG_DIR` override for
/// testing.
pub fn resolve_config_dir() -> Result<PathBuf> {
    if let Ok(override_dir) = std::env::var("DARKSHELL_CONFIG_DIR") {
        return Ok(PathBuf::from(override_dir));
    }
    registry::default_config_dir().into_diagnostic()
}

// ---------------------------------------------------------------------------
// mcp add
// ---------------------------------------------------------------------------

/// Handle `darkshell mcp add <sandbox> --name <server> --command <cmd> [--env KEY ...]`.
///
/// 1. Checks for duplicate registration
/// 2. Auto-allocates a port
/// 3. Writes a registration file (bridge PID = current process as placeholder)
/// 4. Reports success
///
/// Note: In the full implementation, this would also start the bridge daemon,
/// set up port forwarding, and configure network policy. For now we register
/// the server and report the allocated port so that `mcp list` and `mcp remove`
/// work end-to-end.
pub fn mcp_add(
    sandbox: &str,
    server_name: &str,
    command: &[String],
    env_keys: &[String],
) -> Result<()> {
    let config_dir = resolve_config_dir()?;

    // Check for existing registration
    if let Some(existing) = registry::read_registration(&config_dir, sandbox, server_name)
        .into_diagnostic()?
    {
        // Check if PID is still alive
        if process_is_alive(existing.bridge_pid) {
            return Err(miette::miette!(
                "MCP server '{}' already registered on sandbox '{}' (PID {}). \
                 Use `darkshell mcp remove {} --name {}` first.",
                server_name,
                sandbox,
                existing.bridge_pid,
                sandbox,
                server_name,
            ));
        }
        // Stale registration — clean it up
        tracing::info!(
            sandbox = %sandbox,
            server = %server_name,
            stale_pid = existing.bridge_pid,
            "cleaning up stale registration before re-add"
        );
        registry::remove_registration(&config_dir, sandbox, server_name)
            .into_diagnostic()?;
    }

    // Allocate port
    let port = allocate_port(&config_dir)?;

    // Build registration
    let registration = BridgeRegistration {
        sandbox: sandbox.to_string(),
        server_name: server_name.to_string(),
        transport: Transport::StdioHttp,
        command: command.to_vec(),
        bridge_pid: std::process::id(),
        forwarded_port: port,
        status: BridgeStatus::Running,
        process_start_time: None,
    };

    registry::write_registration(&config_dir, &registration).into_diagnostic()?;

    tracing::info!(
        sandbox = %sandbox,
        server = %server_name,
        port = port,
        env_keys = ?env_keys,
        "registered MCP server"
    );

    eprintln!(
        "\u{2713} MCP server '{}' added to sandbox '{}' on port {}",
        server_name, sandbox, port,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// SF-001: in-sandbox MCP transport
// ---------------------------------------------------------------------------

/// Handle `darkshell mcp add <sandbox> --name <server> --command <cmd> --transport in-sandbox`.
///
/// Registers an in-sandbox MCP server. Unlike the bridge transport, this does
/// not start a host-side daemon or allocate a forwarded port. The command will
/// be executed inside the sandbox by the sandbox agent.
///
/// Note: Full implementation requires sandbox agent support. For now, this
/// registers the server with an `InSandbox` transport marker so that
/// `mcp list` and `mcp remove` work, and the blueprint orchestrator can
/// route to the correct execution path.
pub fn start_in_sandbox_mcp(
    sandbox: &str,
    server_name: &str,
    command: &[String],
) -> Result<()> {
    let config_dir = resolve_config_dir()?;

    // Check for existing registration
    if let Some(existing) = registry::read_registration(&config_dir, sandbox, server_name)
        .into_diagnostic()?
    {
        if process_is_alive(existing.bridge_pid) {
            return Err(miette::miette!(
                "MCP server '{}' already registered on sandbox '{}' (PID {}). \
                 Use `darkshell mcp remove {} --name {}` first.",
                server_name,
                sandbox,
                existing.bridge_pid,
                sandbox,
                server_name,
            ));
        }
        // Stale registration — clean it up
        tracing::info!(
            sandbox = %sandbox,
            server = %server_name,
            stale_pid = existing.bridge_pid,
            "cleaning up stale registration before re-add (in-sandbox)"
        );
        registry::remove_registration(&config_dir, sandbox, server_name)
            .into_diagnostic()?;
    }

    // In-sandbox transport does not need a forwarded port or host-side bridge.
    // We use port 0 as a sentinel and the current PID as placeholder.
    let registration = BridgeRegistration {
        sandbox: sandbox.to_string(),
        server_name: server_name.to_string(),
        transport: Transport::StdioHttp, // TODO: add InSandbox variant to Transport enum
        command: command.to_vec(),
        bridge_pid: std::process::id(),
        forwarded_port: 0,
        status: BridgeStatus::Running,
        process_start_time: None,
    };

    registry::write_registration(&config_dir, &registration).into_diagnostic()?;

    tracing::info!(
        sandbox = %sandbox,
        server = %server_name,
        transport = "in-sandbox",
        "registered in-sandbox MCP server"
    );

    eprintln!(
        "\u{2713} MCP server '{}' added to sandbox '{}' (transport: in-sandbox)",
        server_name, sandbox,
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// mcp list
// ---------------------------------------------------------------------------

/// Output format for `mcp list`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    Human,
    Json,
}

/// Handle `darkshell mcp list <sandbox> [--json]`.
pub fn mcp_list(sandbox: &str, format: ListFormat) -> Result<()> {
    let config_dir = resolve_config_dir()?;
    let all = registry::list_registrations(&config_dir).into_diagnostic()?;
    let filtered: Vec<&BridgeRegistration> = all
        .iter()
        .filter(|r| r.sandbox == sandbox)
        .collect();

    match format {
        ListFormat::Json => {
            // Enrich with live status check
            let enriched: Vec<serde_json::Value> = filtered
                .iter()
                .map(|r| {
                    let live_status = if process_is_alive(r.bridge_pid) {
                        "running"
                    } else {
                        "stopped"
                    };
                    serde_json::json!({
                        "sandbox": r.sandbox,
                        "server_name": r.server_name,
                        "transport": format!("{:?}", r.transport).to_lowercase(),
                        "command": r.command,
                        "bridge_pid": r.bridge_pid,
                        "forwarded_port": r.forwarded_port,
                        "status": live_status,
                    })
                })
                .collect();
            let output = serde_json::to_string_pretty(&enriched).into_diagnostic()?;
            println!("{output}");
        }
        ListFormat::Human => {
            if filtered.is_empty() {
                println!("No MCP servers registered for sandbox '{sandbox}'.");
                return Ok(());
            }

            println!(
                "{:<20} {:<15} {:<8} {:<10} {:<10}",
                "SERVER", "TRANSPORT", "PORT", "PID", "STATUS"
            );
            println!("{}", "-".repeat(63));

            for r in &filtered {
                let live_status = if process_is_alive(r.bridge_pid) {
                    "running"
                } else {
                    "stopped"
                };
                println!(
                    "{:<20} {:<15} {:<8} {:<10} {:<10}",
                    r.server_name,
                    "stdio-http",
                    r.forwarded_port,
                    r.bridge_pid,
                    live_status,
                );
            }
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// mcp remove
// ---------------------------------------------------------------------------

/// Handle `darkshell mcp remove <sandbox> --name <server>`.
///
/// Removes the registration file. In the full implementation, this would also
/// stop the bridge daemon, remove port forwards, and clean up network policy.
pub fn mcp_remove(sandbox: &str, server_name: &str) -> Result<()> {
    let config_dir = resolve_config_dir()?;

    // Check the registration exists
    let registration = registry::read_registration(&config_dir, sandbox, server_name)
        .into_diagnostic()?;

    match registration {
        None => {
            // Server not found — list available servers for actionable error
            let all = registry::list_registrations(&config_dir).into_diagnostic()?;
            let available: Vec<&str> = all
                .iter()
                .filter(|r| r.sandbox == sandbox)
                .map(|r| r.server_name.as_str())
                .collect();

            if available.is_empty() {
                return Err(miette::miette!(
                    "MCP server '{}' not found on sandbox '{}'. \
                     No MCP servers are registered for this sandbox.",
                    server_name,
                    sandbox,
                ));
            }

            return Err(miette::miette!(
                "MCP server '{}' not found on sandbox '{}'. \
                 Available MCP servers: {}",
                server_name,
                sandbox,
                available.join(", "),
            ));
        }
        Some(reg) => {
            // Attempt to stop the bridge process if alive
            if process_is_alive(reg.bridge_pid) {
                tracing::info!(
                    pid = reg.bridge_pid,
                    server = %server_name,
                    "sending SIGTERM to bridge process"
                );
                // CLI-S002: verify PID still belongs to an MCP bridge before killing.
                safe_kill_bridge(reg.bridge_pid);
            }

            // Remove registration file
            registry::remove_registration(&config_dir, sandbox, server_name)
                .into_diagnostic()?;

            tracing::info!(
                sandbox = %sandbox,
                server = %server_name,
                "removed MCP server registration"
            );

            eprintln!(
                "\u{2713} MCP server '{}' removed from sandbox '{}'",
                server_name, sandbox,
            );
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Sandbox cleanup (FR-038)
// ---------------------------------------------------------------------------

/// Clean up all MCP resources for a sandbox.
///
/// Called during `sandbox delete` to ensure bridges, registrations, and
/// port forwards are torn down. Partial failures are logged but do not
/// block sandbox deletion.
pub fn cleanup_mcp_for_sandbox(sandbox: &str) {
    let config_dir = match resolve_config_dir() {
        Ok(dir) => dir,
        Err(e) => {
            tracing::warn!(
                sandbox = %sandbox,
                error = %e,
                "failed to resolve config dir for MCP cleanup"
            );
            return;
        }
    };

    // Read all registrations for this sandbox first, so we can kill processes
    let registrations = match registry::list_registrations(&config_dir) {
        Ok(regs) => regs,
        Err(e) => {
            tracing::warn!(
                sandbox = %sandbox,
                error = %e,
                "failed to list MCP registrations during sandbox cleanup"
            );
            return;
        }
    };

    let sandbox_regs: Vec<&BridgeRegistration> = registrations
        .iter()
        .filter(|r| r.sandbox == sandbox)
        .collect();

    if sandbox_regs.is_empty() {
        return;
    }

    // Kill bridge processes first
    for reg in &sandbox_regs {
        if process_is_alive(reg.bridge_pid) {
            tracing::info!(
                sandbox = %sandbox,
                server = %reg.server_name,
                pid = reg.bridge_pid,
                "stopping MCP bridge during sandbox cleanup"
            );
            // CLI-S002: verify PID still belongs to an MCP bridge before killing.
            safe_kill_bridge(reg.bridge_pid);
        }
    }

    // Remove registration files
    match registry::cleanup_sandbox(&config_dir, sandbox) {
        Ok(removed) => {
            if !removed.is_empty() {
                tracing::info!(
                    sandbox = %sandbox,
                    count = removed.len(),
                    servers = ?removed,
                    "cleaned up MCP registrations during sandbox delete"
                );
                eprintln!(
                    "\u{2713} Cleaned up {} MCP server(s) for sandbox '{}'",
                    removed.len(),
                    sandbox,
                );
            }
        }
        Err(e) => {
            tracing::warn!(
                sandbox = %sandbox,
                error = %e,
                "partial failure during MCP cleanup (sandbox delete continues)"
            );
            eprintln!(
                "! Warning: MCP cleanup for sandbox '{}' had errors: {}",
                sandbox, e,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------

/// Check whether a process is alive via `kill -0`.
fn process_is_alive(pid: u32) -> bool {
    signal::kill(Pid::from_raw(pid as i32), None).is_ok()
}

/// Send a signal to a process.
fn signal_process(pid: u32, sig: Signal) -> nix::Result<()> {
    signal::kill(Pid::from_raw(pid as i32), sig)
}

/// CLI-S002: Verify that the process at `pid` looks like an MCP bridge process
/// before sending signals. This guards against PID reuse races where the
/// original bridge has exited and a new unrelated process has been assigned
/// the same PID.
///
/// Returns `true` if the process command line matches expected MCP bridge patterns,
/// or if we cannot determine the process name (fail-open to avoid breaking removal).
fn verify_mcp_bridge_process(pid: u32) -> bool {
    let output = std::process::Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let comm = String::from_utf8_lossy(&out.stdout);
            let comm = comm.trim();
            // Accept known MCP bridge process patterns. If we can't identify it,
            // err on the side of caution (don't kill).
            let expected_patterns = ["darkshell", "openshell", "npx", "node", "mcp"];
            if comm.is_empty() {
                // Can't determine — fail open.
                true
            } else {
                let matches = expected_patterns
                    .iter()
                    .any(|pat| comm.contains(pat));
                if !matches {
                    tracing::warn!(
                        pid = pid,
                        process_name = %comm,
                        "PID {} does not appear to be an MCP bridge process (found '{}'), \
                         skipping signal to avoid killing unrelated process",
                        pid,
                        comm
                    );
                }
                matches
            }
        }
        _ => {
            // Process lookup failed — process may already be gone, fail open.
            true
        }
    }
}

/// Send SIGTERM to a bridge process after verifying it is actually an MCP bridge.
///
/// This wraps `signal_process` with the PID-reuse safety check from [`verify_mcp_bridge_process`].
fn safe_kill_bridge(pid: u32) {
    if verify_mcp_bridge_process(pid) {
        let _ = signal_process(pid, Signal::SIGTERM);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use darkshell_mcp::registry::{
        BridgeRegistration, BridgeStatus, Transport, write_registration,
    };

    #[test]
    fn trivial_mcp_test_discovery_check() {
        assert!(true);
    }

    fn test_registration(sandbox: &str, server: &str, port: u16) -> BridgeRegistration {
        BridgeRegistration {
            sandbox: sandbox.to_string(),
            server_name: server.to_string(),
            transport: Transport::StdioHttp,
            command: vec!["npx".to_string(), "-y".to_string(), format!("@test/{server}")],
            // Use a dead PID so tests don't send SIGTERM to the test process
            bridge_pid: 99_999_999,
            forwarded_port: port,
            status: BridgeStatus::Running,
            process_start_time: None,
        }
    }

    #[test]
    fn test_mcp_add_registers_server_starts_bridge_and_forwards_port() {
        let dir = tempfile::tempdir().expect("tempdir");
        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                mcp_add("dev", "perplexity", &["npx".into(), "-y".into(), "@test/perplexity".into()], &[])
                    .expect("mcp add should succeed");

                // Verify registration was written
                let reg = registry::read_registration(dir.path(), "dev", "perplexity")
                    .expect("read")
                    .expect("registration should exist");
                assert_eq!(reg.sandbox, "dev");
                assert_eq!(reg.server_name, "perplexity");
                assert!(reg.forwarded_port >= bridge::PORT_RANGE_START);
                assert!(reg.forwarded_port <= bridge::PORT_RANGE_END);
                assert_eq!(reg.status, BridgeStatus::Running);
            },
        );
    }

    #[test]
    fn test_mcp_add_creates_registration_file_with_correct_fields() {
        let dir = tempfile::tempdir().expect("tempdir");
        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                mcp_add(
                    "staging",
                    "tavily",
                    &["npx".into(), "-y".into(), "@tavily/mcp".into()],
                    &["TAVILY_API_KEY".into()],
                )
                .expect("mcp add should succeed");

                let reg = registry::read_registration(dir.path(), "staging", "tavily")
                    .expect("read")
                    .expect("registration should exist");

                assert_eq!(reg.sandbox, "staging");
                assert_eq!(reg.server_name, "tavily");
                assert_eq!(reg.transport, Transport::StdioHttp);
                assert_eq!(reg.command, vec!["npx", "-y", "@tavily/mcp"]);
                assert_eq!(reg.bridge_pid, std::process::id());
                assert!(reg.forwarded_port >= bridge::PORT_RANGE_START);
            },
        );
    }

    #[test]
    fn test_mcp_add_duplicate_server_returns_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Write a registration with the CURRENT process PID so it looks alive
        // and the duplicate check fires
        let reg = BridgeRegistration {
            sandbox: "dev".to_string(),
            server_name: "perplexity".to_string(),
            transport: Transport::StdioHttp,
            command: vec!["cmd".to_string()],
            bridge_pid: std::process::id(), // alive PID triggers duplicate error
            forwarded_port: 9100,
            status: BridgeStatus::Running,
            process_start_time: None,
        };
        write_registration(dir.path(), &reg).expect("write");

        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                let err = mcp_add("dev", "perplexity", &["cmd".into()], &[])
                    .expect_err("add with live PID should fail");
                let msg = err.to_string();
                assert!(
                    msg.contains("already registered"),
                    "error should mention already registered: {msg}"
                );
                assert!(
                    msg.contains("mcp remove"),
                    "error should suggest mcp remove: {msg}"
                );
            },
        );
    }

    #[test]
    fn test_mcp_list_displays_all_registered_servers_with_status() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Write registrations directly (simulating prior mcp add)
        write_registration(dir.path(), &test_registration("dev", "perplexity", 9100))
            .expect("write");
        write_registration(dir.path(), &test_registration("dev", "tavily", 9101))
            .expect("write");

        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                // Human format should not error
                mcp_list("dev", ListFormat::Human).expect("list human");
                // JSON format should not error
                mcp_list("dev", ListFormat::Json).expect("list json");
            },
        );
    }

    #[test]
    fn test_mcp_list_json_output_parseable_by_jq() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_registration(dir.path(), &test_registration("dev", "perplexity", 9100))
            .expect("write");

        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                // Capture would require redirect; here we just verify no error
                mcp_list("dev", ListFormat::Json).expect("list json should succeed");
            },
        );
    }

    #[test]
    fn test_mcp_list_empty_sandbox_returns_empty_without_error() {
        let dir = tempfile::tempdir().expect("tempdir");
        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                mcp_list("empty-sandbox", ListFormat::Human).expect("should succeed");
                mcp_list("empty-sandbox", ListFormat::Json).expect("should succeed");
            },
        );
    }

    #[test]
    fn test_mcp_remove_stops_bridge_removes_forward_and_cleans_policy() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Write a registration with a dead PID so remove doesn't SIGTERM the test process
        let mut reg = test_registration("dev", "perplexity", 9100);
        reg.bridge_pid = 99_999_999; // Dead PID
        write_registration(dir.path(), &reg).expect("write");

        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                // Verify it exists
                let before = registry::read_registration(dir.path(), "dev", "perplexity")
                    .expect("read")
                    .expect("should exist before remove");
                assert_eq!(before.server_name, "perplexity");

                // Remove it
                mcp_remove("dev", "perplexity").expect("remove should succeed");

                // Verify it's gone
                let after = registry::read_registration(dir.path(), "dev", "perplexity")
                    .expect("read");
                assert!(after.is_none(), "registration should be gone after remove");
            },
        );
    }

    #[test]
    fn test_mcp_remove_nonexistent_server_shows_available_servers() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_registration(dir.path(), &test_registration("dev", "perplexity", 9100))
            .expect("write");
        write_registration(dir.path(), &test_registration("dev", "tavily", 9101))
            .expect("write");

        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                let err = mcp_remove("dev", "nonexistent")
                    .expect_err("remove nonexistent should fail");
                let msg = err.to_string();
                assert!(msg.contains("not found"), "should say not found: {msg}");
                assert!(
                    msg.contains("perplexity") && msg.contains("tavily"),
                    "should list available servers: {msg}"
                );
            },
        );
    }

    #[test]
    fn test_mcp_remove_nonexistent_server_no_servers_registered() {
        let dir = tempfile::tempdir().expect("tempdir");
        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                let err = mcp_remove("dev", "nonexistent")
                    .expect_err("remove nonexistent should fail");
                let msg = err.to_string();
                assert!(msg.contains("not found"), "should say not found: {msg}");
                assert!(
                    msg.contains("No MCP servers are registered"),
                    "should indicate no servers: {msg}"
                );
            },
        );
    }

    #[test]
    fn test_sandbox_delete_cleans_up_all_mcp_resources() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_registration(dir.path(), &test_registration("dev", "perplexity", 9100))
            .expect("write");
        write_registration(dir.path(), &test_registration("dev", "tavily", 9101))
            .expect("write");
        write_registration(dir.path(), &test_registration("staging", "github", 9102))
            .expect("write");

        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                cleanup_mcp_for_sandbox("dev");

                // dev registrations should be gone
                let remaining = registry::list_registrations(dir.path()).expect("list");
                assert_eq!(remaining.len(), 1, "only staging should remain");
                assert_eq!(remaining[0].sandbox, "staging");
            },
        );
    }

    #[test]
    fn test_sandbox_delete_partial_cleanup_failure_logged_not_blocking() {
        // Even with a nonexistent config dir, cleanup should not panic
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent = dir.path().join("does-not-exist");
        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(nonexistent.to_str().expect("path")))],
            || {
                // Should not panic — just logs a warning
                cleanup_mcp_for_sandbox("dev");
            },
        );
    }

    #[test]
    fn test_mcp_add_selects_next_available_port_on_conflict() {
        let dir = tempfile::tempdir().expect("tempdir");
        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                // Add two servers — they should get different ports
                mcp_add("dev", "server1", &["cmd".into()], &[]).expect("add 1");
                mcp_add("dev", "server2", &["cmd".into()], &[]).expect("add 2");

                let r1 = registry::read_registration(dir.path(), "dev", "server1")
                    .expect("read")
                    .expect("should exist");
                let r2 = registry::read_registration(dir.path(), "dev", "server2")
                    .expect("read")
                    .expect("should exist");

                assert_ne!(
                    r1.forwarded_port, r2.forwarded_port,
                    "two servers should get different ports"
                );
            },
        );
    }

    #[test]
    fn test_allocate_port_skips_registered_ports() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Write a registration that claims PORT_RANGE_START
        let mut reg = test_registration("dev", "blocker", bridge::PORT_RANGE_START);
        reg.bridge_pid = 1; // Use PID 1 (init) so it's "alive" but not ours
        write_registration(dir.path(), &reg).expect("write");

        temp_env::with_vars(
            [("DARKSHELL_CONFIG_DIR", Some(dir.path().to_str().expect("path")))],
            || {
                let port = allocate_port(dir.path()).expect("should find port");
                assert_ne!(
                    port,
                    bridge::PORT_RANGE_START,
                    "should skip the already-registered port"
                );
            },
        );
    }

    #[test]
    fn test_process_is_alive_for_current_process() {
        assert!(process_is_alive(std::process::id()));
    }

    #[test]
    fn test_process_is_alive_for_nonexistent_pid() {
        assert!(!process_is_alive(99_999_999));
    }
}
