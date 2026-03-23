// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WF-2: End-to-end exec workflow integration tests.
//!
//! Tests the pure functions that compose the exec pipeline: SSH command
//! building, ControlSocket path computation, ExecResult formatting, and
//! timeout constants.

use openshell_cli::ssh::{
    EXEC_DEFAULT_TIMEOUT_SECS, EXIT_CODE_TIMEOUT, ExecResult, build_exec_ssh_command,
    controlsocket_dir, controlsocket_path,
};
use std::time::Duration;

// ---------------------------------------------------------------------------
// build_exec_ssh_command — ControlMaster arguments
// ---------------------------------------------------------------------------

#[test]
fn test_exec_command_builds_with_control_master() {
    let cmd = build_exec_ssh_command(
        "proxy-cmd --gateway https://example.com",
        &["echo".to_string(), "hello".to_string()],
        "/tmp/ctrl-%r@%h:%p",
    );

    let args: Vec<String> = cmd
        .as_std()
        .get_args()
        .filter_map(|a| a.to_str().map(String::from))
        .collect();

    assert!(
        args.contains(&"ControlMaster=auto".to_string()),
        "must include ControlMaster=auto, got: {args:?}"
    );
}

#[test]
fn test_exec_command_includes_control_persist() {
    let cmd = build_exec_ssh_command("proxy-cmd", &["ls".to_string()], "/tmp/ctrl-%r@%h:%p");

    let args: Vec<String> = cmd
        .as_std()
        .get_args()
        .filter_map(|a| a.to_str().map(String::from))
        .collect();

    assert!(
        args.iter().any(|a| a.starts_with("ControlPersist=")),
        "must include ControlPersist, got: {args:?}"
    );

    // Verify the value is 600 seconds
    assert!(
        args.contains(&"ControlPersist=600".to_string()),
        "ControlPersist should be 600 seconds, got: {args:?}"
    );
}

#[test]
fn test_exec_command_includes_control_path() {
    let control_path = "/tmp/test-ctrl-%r@%h:%p";
    let cmd = build_exec_ssh_command("proxy-cmd", &["ls".to_string()], control_path);

    let args: Vec<String> = cmd
        .as_std()
        .get_args()
        .filter_map(|a| a.to_str().map(String::from))
        .collect();

    let expected = format!("ControlPath={control_path}");
    assert!(
        args.contains(&expected),
        "must include ControlPath={control_path}, got: {args:?}"
    );
}

#[test]
fn test_exec_command_includes_proxy_command() {
    let proxy = "proxy-cmd --gateway https://example.com --sandbox-id abc --token xyz";
    let cmd = build_exec_ssh_command(
        proxy,
        &["echo".to_string(), "test".to_string()],
        "/tmp/ctrl-%r@%h:%p",
    );

    let args: Vec<String> = cmd
        .as_std()
        .get_args()
        .filter_map(|a| a.to_str().map(String::from))
        .collect();

    let expected = format!("ProxyCommand={proxy}");
    assert!(
        args.contains(&expected),
        "must include ProxyCommand, got: {args:?}"
    );
}

// ---------------------------------------------------------------------------
// Default timeout
// ---------------------------------------------------------------------------

#[test]
fn test_exec_command_default_timeout_300() {
    assert_eq!(
        EXEC_DEFAULT_TIMEOUT_SECS, 300,
        "default exec timeout should be 300 seconds (5 minutes)"
    );
}

#[test]
fn test_exec_timeout_exit_code() {
    assert_eq!(
        EXIT_CODE_TIMEOUT, 124,
        "timeout exit code should match POSIX timeout(1) convention"
    );
}

// ---------------------------------------------------------------------------
// ExecResult JSON formatting
// ---------------------------------------------------------------------------

#[test]
fn test_exec_json_output_format() {
    let result = ExecResult {
        stdout: b"output line\n".to_vec(),
        stderr: b"warning\n".to_vec(),
        exit_code: 0,
        duration: Duration::from_millis(1234),
    };

    let json = serde_json::json!({
        "stdout": String::from_utf8_lossy(&result.stdout),
        "stderr": String::from_utf8_lossy(&result.stderr),
        "exit_code": result.exit_code,
        "duration_ms": result.duration.as_millis() as u64,
    });

    let json_str = serde_json::to_string(&json).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("parse JSON");

    assert_eq!(parsed["exit_code"], 0);
    assert_eq!(parsed["duration_ms"], 1234);
    assert_eq!(parsed["stdout"], "output line\n");
    assert_eq!(parsed["stderr"], "warning\n");
}

#[test]
fn test_exec_propagates_nonzero_exit_code() {
    let result = ExecResult {
        stdout: Vec::new(),
        stderr: b"command not found\n".to_vec(),
        exit_code: 127,
        duration: Duration::from_millis(50),
    };

    assert_eq!(
        result.exit_code, 127,
        "nonzero exit code should be preserved"
    );
    assert!(
        !result.stderr.is_empty(),
        "stderr should contain error output"
    );
}

// ---------------------------------------------------------------------------
// ControlSocket path computation
// ---------------------------------------------------------------------------

#[test]
fn test_control_socket_path_computation() {
    // controlsocket_path depends on XDG_CONFIG_HOME. We verify the pattern
    // portion is correct without setting env vars (which would require
    // synchronization).
    let path = controlsocket_path().expect("controlsocket_path should succeed");
    assert!(
        path.contains("ctrl-%r@%h:%p"),
        "ControlPath must use SSH token expansion pattern, got: {path}"
    );
    assert!(
        path.contains("darkshell/ssh/"),
        "ControlPath must be under darkshell/ssh/, got: {path}"
    );
}

#[test]
fn test_control_socket_dir_under_darkshell() {
    let dir = controlsocket_dir().expect("controlsocket_dir should succeed");
    assert!(
        dir.ends_with("darkshell/ssh"),
        "expected path ending with 'darkshell/ssh', got: {dir:?}"
    );
}

// ---------------------------------------------------------------------------
// Shell escaping in exec commands
// ---------------------------------------------------------------------------

#[test]
fn test_exec_shell_escaping() {
    // Command with spaces and special characters should be properly escaped.
    let cmd = build_exec_ssh_command(
        "proxy-cmd",
        &[
            "echo".to_string(),
            "hello world".to_string(),
            "it's".to_string(),
        ],
        "/tmp/ctrl-%r@%h:%p",
    );

    let args: Vec<String> = cmd
        .as_std()
        .get_args()
        .filter_map(|a| a.to_str().map(String::from))
        .collect();

    // The last arg should be the escaped remote command
    let last = args.last().expect("should have args");
    assert!(
        last.contains("hello"),
        "escaped command should contain the word hello: {last}"
    );
    // Verify the command with spaces is quoted or escaped
    assert!(
        last.contains('\'') || last.contains('"') || last.contains('\\'),
        "command with spaces should be escaped in some way: {last}"
    );
}

#[test]
fn test_exec_command_non_interactive_flag() {
    let cmd = build_exec_ssh_command("proxy-cmd", &["whoami".to_string()], "/tmp/ctrl-%r@%h:%p");

    let args: Vec<String> = cmd
        .as_std()
        .get_args()
        .filter_map(|a| a.to_str().map(String::from))
        .collect();

    assert!(
        args.contains(&"-T".to_string()),
        "must include -T for non-interactive mode, got: {args:?}"
    );

    assert!(
        args.contains(&"RequestTTY=no".to_string()),
        "must include RequestTTY=no, got: {args:?}"
    );
}

#[test]
fn test_exec_command_program_is_ssh() {
    let cmd = build_exec_ssh_command("proxy-cmd", &["ls".to_string()], "/tmp/ctrl-%r@%h:%p");

    let prog = cmd.as_std().get_program();
    assert_eq!(prog, "ssh", "program must be ssh");
}
