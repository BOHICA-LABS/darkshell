//! WF-6 integration tests: in-sandbox MCP command building and credential rejection.

use openshell_cli::ssh::{
    build_in_sandbox_mcp_command, check_in_sandbox_binary_not_found, reject_credential_env_vars,
};

#[test]
fn test_in_sandbox_command_builds_correctly() {
    // Without working dir: should produce ["sh", "-c", "<command>"].
    let cmd = build_in_sandbox_mcp_command("/usr/local/bin/mcp-tally", None)
        .expect("should build command");
    assert_eq!(cmd.len(), 3, "command should have 3 parts");
    assert_eq!(cmd[0], "sh");
    assert_eq!(cmd[1], "-c");
    assert_eq!(cmd[2], "/usr/local/bin/mcp-tally");

    // With working dir: should wrap in cd.
    let cmd_with_dir =
        build_in_sandbox_mcp_command("/usr/local/bin/mcp-tally", Some("/workspace"))
            .expect("should build command with working dir");
    assert_eq!(cmd_with_dir.len(), 3, "command should have 3 parts");
    assert_eq!(cmd_with_dir[0], "sh");
    assert_eq!(cmd_with_dir[1], "-c");
    assert!(
        cmd_with_dir[2].contains("cd"),
        "should contain cd for working dir, got: {}",
        cmd_with_dir[2]
    );
    assert!(
        cmd_with_dir[2].contains("/workspace"),
        "should contain the working directory path, got: {}",
        cmd_with_dir[2]
    );
    assert!(
        cmd_with_dir[2].contains("mcp-tally"),
        "should contain the original command, got: {}",
        cmd_with_dir[2]
    );
}

#[test]
fn test_in_sandbox_rejects_credential_env_vars() {
    let credential_vars = vec![
        "API_KEY".to_string(),
        "SECRET_TOKEN".to_string(),
        "AWS_ACCESS_KEY_ID".to_string(),
        "GITHUB_TOKEN".to_string(),
        "ANTHROPIC_API_KEY".to_string(),
    ];

    for var in &credential_vars {
        let vars = vec![var.clone()];
        let err = reject_credential_env_vars(&vars)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains(var),
            "error should mention the rejected var '{var}', got: {msg}"
        );
    }
}

#[test]
fn test_in_sandbox_credential_rejection_suggests_bridge() {
    let vars = vec!["GITHUB_TOKEN".to_string()];
    let err = reject_credential_env_vars(&vars).unwrap_err();
    let msg = format!("{err}");

    assert!(
        msg.contains("bridge"),
        "error message should suggest using 'transport: bridge', got: {msg}"
    );
}

#[test]
fn test_in_sandbox_detects_binary_not_found() {
    // Exit code 127 (command not found).
    let err = check_in_sandbox_binary_not_found(
        "dev",
        "mcp-tally",
        127,
        b"sh: mcp-tally: not found",
    )
    .unwrap_err();

    let msg = format!("{err}");
    assert!(
        msg.contains("not found"),
        "error should mention 'not found', got: {msg}"
    );
    assert!(
        msg.contains("mcp-tally"),
        "error should mention the command name, got: {msg}"
    );
    assert!(
        msg.contains("Dockerfile") || msg.contains("container image"),
        "error should suggest updating the Dockerfile or container image, got: {msg}"
    );

    // "No such file" in stderr with non-127 exit code should also be caught.
    let err2 = check_in_sandbox_binary_not_found(
        "dev",
        "/opt/bin/mcp-server",
        1,
        b"bash: /opt/bin/mcp-server: No such file or directory",
    )
    .unwrap_err();

    let msg2 = format!("{err2}");
    assert!(
        msg2.contains("not found") || msg2.contains("No such file"),
        "should detect 'No such file' pattern, got: {msg2}"
    );
}

#[test]
fn test_in_sandbox_accepts_filesystem_only_env() {
    // These are not credentials and should be accepted.
    let safe_vars = vec![
        "PATH".to_string(),
        "HOME".to_string(),
        "LANG".to_string(),
        "RUST_LOG".to_string(),
        "EDITOR".to_string(),
    ];

    reject_credential_env_vars(&safe_vars)
        .expect("non-credential env vars should be accepted");
}
