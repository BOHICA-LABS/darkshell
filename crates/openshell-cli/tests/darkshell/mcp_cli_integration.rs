// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WF-3: CLI-level MCP management integration tests.
//!
//! Tests MCP server name validation, registration lifecycle, and transport
//! handling through the public library API.

use darkshell_mcp::registry::validate_name;

// ---------------------------------------------------------------------------
// Server name validation
// ---------------------------------------------------------------------------

#[test]
fn test_validate_server_name_rejects_path_traversal() {
    let result = validate_name("../etc/passwd");
    assert!(
        result.is_err(),
        "path traversal names must be rejected: ../etc/passwd"
    );

    let result = validate_name("foo/bar");
    assert!(
        result.is_err(),
        "names containing '/' must be rejected: foo/bar"
    );
}

#[test]
fn test_validate_server_name_rejects_uppercase() {
    assert!(
        validate_name("MyServer").is_err(),
        "uppercase names must be rejected"
    );
    assert!(
        validate_name("ALLCAPS").is_err(),
        "all-uppercase names must be rejected"
    );
}

#[test]
fn test_validate_server_name_accepts_valid() {
    assert!(
        validate_name("my-server-1").is_ok(),
        "lowercase alphanumeric with hyphens should be valid"
    );
    assert!(
        validate_name("perplexity").is_ok(),
        "simple lowercase name should be valid"
    );
    assert!(
        validate_name("tavily").is_ok(),
        "simple lowercase name should be valid"
    );
}

#[test]
fn test_validate_server_name_rejects_empty() {
    assert!(
        validate_name("").is_err(),
        "empty server name must be rejected"
    );
}

#[test]
fn test_validate_server_name_rejects_spaces() {
    assert!(
        validate_name("my server").is_err(),
        "names with spaces must be rejected"
    );
}

#[test]
fn test_validate_server_name_rejects_special_characters() {
    assert!(
        validate_name("my_server").is_err(),
        "underscores should be rejected"
    );
    assert!(validate_name("foo.bar").is_err(), "dots should be rejected");
}

// ---------------------------------------------------------------------------
// MCP add/list/remove lifecycle
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_add_and_list_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    temp_env::with_vars(
        [(
            "DARKSHELL_CONFIG_DIR",
            Some(dir.path().to_str().expect("path")),
        )],
        || {
            // Add a server
            openshell_cli::mcp::mcp_add(
                "dev",
                "perplexity",
                &[
                    "npx".into(),
                    "-y".into(),
                    "@anthropic/perplexity-mcp".into(),
                ],
                &[],
            )
            .expect("mcp add should succeed");

            // List servers — should not error
            openshell_cli::mcp::mcp_list("dev", openshell_cli::mcp::ListFormat::Human)
                .expect("mcp list human should succeed");

            openshell_cli::mcp::mcp_list("dev", openshell_cli::mcp::ListFormat::Json)
                .expect("mcp list json should succeed");
        },
    );
}

#[test]
fn test_mcp_add_and_remove_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Write a registration with a dead PID so remove does not SIGTERM
    // the test process.
    let reg = darkshell_mcp::registry::BridgeRegistration {
        sandbox: "dev".to_string(),
        server_name: "tavily".to_string(),
        transport: darkshell_mcp::registry::Transport::StdioHttp,
        command: vec!["cmd".to_string()],
        bridge_pid: 99_999_999, // dead PID
        forwarded_port: 9100,
        status: darkshell_mcp::registry::BridgeStatus::Running,
        process_start_time: None,
    };
    darkshell_mcp::registry::write_registration(dir.path(), &reg).expect("write");

    temp_env::with_vars(
        [(
            "DARKSHELL_CONFIG_DIR",
            Some(dir.path().to_str().expect("path")),
        )],
        || {
            // Verify exists
            let found = darkshell_mcp::registry::read_registration(dir.path(), "dev", "tavily")
                .expect("read")
                .expect("registration should exist");
            assert_eq!(found.server_name, "tavily");

            // Remove (dead PID — no SIGTERM to test process)
            openshell_cli::mcp::mcp_remove("dev", "tavily").expect("mcp remove should succeed");

            // Verify gone
            let after = darkshell_mcp::registry::read_registration(dir.path(), "dev", "tavily")
                .expect("read");
            assert!(after.is_none(), "registration should be gone after remove");
        },
    );
}

#[test]
fn test_mcp_remove_nonexistent_gives_actionable_error() {
    let dir = tempfile::tempdir().expect("tempdir");
    temp_env::with_vars(
        [(
            "DARKSHELL_CONFIG_DIR",
            Some(dir.path().to_str().expect("path")),
        )],
        || {
            let err = openshell_cli::mcp::mcp_remove("dev", "nonexistent")
                .expect_err("remove nonexistent should fail");
            let msg = err.to_string();
            assert!(
                msg.contains("not found"),
                "error should mention 'not found': {msg}"
            );
        },
    );
}

#[test]
fn test_mcp_list_empty_sandbox() {
    let dir = tempfile::tempdir().expect("tempdir");
    temp_env::with_vars(
        [(
            "DARKSHELL_CONFIG_DIR",
            Some(dir.path().to_str().expect("path")),
        )],
        || {
            // List on empty sandbox should succeed without error
            openshell_cli::mcp::mcp_list("empty", openshell_cli::mcp::ListFormat::Human)
                .expect("list on empty sandbox should succeed");
            openshell_cli::mcp::mcp_list("empty", openshell_cli::mcp::ListFormat::Json)
                .expect("list json on empty sandbox should succeed");
        },
    );
}

// ---------------------------------------------------------------------------
// In-sandbox transport
// ---------------------------------------------------------------------------

#[test]
fn test_mcp_in_sandbox_transport_registers() {
    let dir = tempfile::tempdir().expect("tempdir");
    temp_env::with_vars(
        [(
            "DARKSHELL_CONFIG_DIR",
            Some(dir.path().to_str().expect("path")),
        )],
        || {
            openshell_cli::mcp::start_in_sandbox_mcp(
                "dev",
                "github-mcp",
                &["npx".into(), "-y".into(), "@github/mcp".into()],
            )
            .expect("in-sandbox mcp add should succeed");

            let reg = darkshell_mcp::registry::read_registration(dir.path(), "dev", "github-mcp")
                .expect("read")
                .expect("registration should exist");
            assert_eq!(reg.server_name, "github-mcp");
            // In-sandbox uses port 0 as sentinel
            assert_eq!(reg.forwarded_port, 0);
        },
    );
}

// ---------------------------------------------------------------------------
// Cleanup on sandbox delete
// ---------------------------------------------------------------------------

#[test]
fn test_cleanup_mcp_for_sandbox_removes_all_registrations() {
    let dir = tempfile::tempdir().expect("tempdir");

    // Write registrations directly
    let reg1 = darkshell_mcp::registry::BridgeRegistration {
        sandbox: "dev".to_string(),
        server_name: "server1".to_string(),
        transport: darkshell_mcp::registry::Transport::StdioHttp,
        command: vec!["cmd".to_string()],
        bridge_pid: 99_999_999,
        forwarded_port: 9100,
        status: darkshell_mcp::registry::BridgeStatus::Running,
        process_start_time: None,
    };
    let reg2 = darkshell_mcp::registry::BridgeRegistration {
        sandbox: "dev".to_string(),
        server_name: "server2".to_string(),
        transport: darkshell_mcp::registry::Transport::StdioHttp,
        command: vec!["cmd".to_string()],
        bridge_pid: 99_999_999,
        forwarded_port: 9101,
        status: darkshell_mcp::registry::BridgeStatus::Running,
        process_start_time: None,
    };
    darkshell_mcp::registry::write_registration(dir.path(), &reg1).expect("write");
    darkshell_mcp::registry::write_registration(dir.path(), &reg2).expect("write");

    temp_env::with_vars(
        [(
            "DARKSHELL_CONFIG_DIR",
            Some(dir.path().to_str().expect("path")),
        )],
        || {
            openshell_cli::mcp::cleanup_mcp_for_sandbox("dev");

            let remaining = darkshell_mcp::registry::list_registrations(dir.path()).expect("list");
            assert!(
                remaining.is_empty(),
                "all dev registrations should be removed, found: {remaining:?}"
            );
        },
    );
}
