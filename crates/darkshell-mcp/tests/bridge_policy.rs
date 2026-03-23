// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for MCP bridge policy enforcement through the full
//! HTTP request path.
//!
//! These tests start REAL bridges with `cat` as the MCP server subprocess,
//! configure tool-level policies, and verify enforcement via HTTP requests.

use darkshell_mcp::bridge::{BridgeConfig, McpBridge};
use darkshell_mcp::credential::CredentialProvider;
use darkshell_mcp::error::Result as BridgeResult;
use darkshell_mcp::policy::{McpPolicyFile, McpToolPolicy, PolicyHolder};
use std::sync::Arc;

struct NoopCredentialProvider;

impl CredentialProvider for NoopCredentialProvider {
    fn resolve(&self, _provider: &str, _key: &str) -> BridgeResult<String> {
        Ok(String::new())
    }
}

fn cat_bridge_config(tmp_dir: &std::path::Path, sandbox: &str, server: &str) -> BridgeConfig {
    let mut config = BridgeConfig::new(sandbox, server, vec!["cat".to_string()]);
    config.config_dir = tmp_dir.to_path_buf();
    config.credentials = Vec::new();
    config
}

/// Helper: start a bridge with the given policy, serve it, and return the bridge, port, and shutdown sender.
async fn start_bridge_with_policy(
    tmp_dir: &std::path::Path,
    server_name: &str,
    policy: PolicyHolder,
) -> (Arc<McpBridge>, u16, tokio::sync::oneshot::Sender<()>) {
    let config = cat_bridge_config(tmp_dir, "policy-sb", server_name);
    let bridge = McpBridge::start(config, &NoopCredentialProvider, policy, None)
        .await
        .expect("bridge should start");
    let port = bridge.port();
    let bridge = Arc::new(bridge);

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let serve_bridge = bridge.clone();
    tokio::spawn(async move { serve_bridge.serve(shutdown_rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    (bridge, port, shutdown_tx)
}

fn tools_call_request(tool_name: &str) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": {}
        },
        "id": 1
    })
}

#[tokio::test]
async fn test_allowed_tool_passes_through() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Policy: only "search" is allowed for server "echo-allow"
    let mut policy_file = McpPolicyFile::default();
    policy_file.mcp_servers.insert(
        "echo-allow".to_string(),
        McpToolPolicy {
            allowed_tools: vec!["search".to_string()],
            denied_tools: vec![],
        },
    );
    let policy = PolicyHolder::new(policy_file);

    let (bridge, port, shutdown_tx) =
        start_bridge_with_policy(tmp.path(), "echo-allow", policy).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .json(&tools_call_request("search"))
        .send()
        .await
        .expect("request should connect");

    assert_eq!(resp.status(), 200, "allowed tool should return 200");

    // cat echoes the request back, so the response should contain the original method
    let body: serde_json::Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["method"], "tools/call");

    let _ = shutdown_tx.send(());
    bridge.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_denied_tool_returns_error() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Policy: "delete" is explicitly denied for server "echo-deny"
    let mut policy_file = McpPolicyFile::default();
    policy_file.mcp_servers.insert(
        "echo-deny".to_string(),
        McpToolPolicy {
            allowed_tools: vec![],
            denied_tools: vec!["delete".to_string()],
        },
    );
    let policy = PolicyHolder::new(policy_file);

    let (bridge, port, shutdown_tx) =
        start_bridge_with_policy(tmp.path(), "echo-deny", policy).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .json(&tools_call_request("delete"))
        .send()
        .await
        .expect("request should connect");

    assert_eq!(
        resp.status(),
        200,
        "denied tool still returns 200 (JSON-RPC error in body)"
    );

    let body: serde_json::Value = resp.json().await.expect("response should be JSON");
    assert_eq!(body["jsonrpc"], "2.0");
    assert!(
        body.get("error").is_some(),
        "response should contain JSON-RPC error"
    );
    assert_eq!(body["error"]["code"], -32001);
    assert!(
        body["error"]["data"]["tool"]
            .as_str()
            .unwrap()
            .contains("delete"),
        "error should reference the denied tool name"
    );

    let _ = shutdown_tx.send(());
    bridge.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_no_policy_allows_all() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Empty policy = allow all
    let policy = PolicyHolder::allow_all();

    let (bridge, port, shutdown_tx) =
        start_bridge_with_policy(tmp.path(), "echo-nopol", policy).await;

    let client = reqwest::Client::new();

    // Any tool name should pass through
    for tool in &["search", "delete", "write_file", "anything"] {
        let resp = client
            .post(format!("http://127.0.0.1:{port}/"))
            .json(&tools_call_request(tool))
            .send()
            .await
            .expect("request should connect");

        assert_eq!(resp.status(), 200);

        let body: serde_json::Value = resp.json().await.expect("response should be JSON");
        // cat echoes back, so no JSON-RPC error should be present
        assert!(
            body.get("error").is_none(),
            "with no policy, tool '{tool}' should not have an error in response",
        );
    }

    let _ = shutdown_tx.send(());
    bridge.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_policy_hot_reload() {
    let tmp = tempfile::tempdir().expect("tempdir");

    // Start with restrictive policy: only "read" allowed
    let mut restrictive = McpPolicyFile::default();
    restrictive.mcp_servers.insert(
        "echo-reload".to_string(),
        McpToolPolicy {
            allowed_tools: vec!["read".to_string()],
            denied_tools: vec![],
        },
    );
    let policy = PolicyHolder::new(restrictive);

    let (bridge, port, shutdown_tx) =
        start_bridge_with_policy(tmp.path(), "echo-reload", policy).await;

    let client = reqwest::Client::new();

    // "write" should be denied initially
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .json(&tools_call_request("write"))
        .send()
        .await
        .expect("request should connect");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(
        body.get("error").is_some(),
        "write should be denied before reload"
    );

    // Hot-reload: now allow both "read" and "write"
    let mut permissive = McpPolicyFile::default();
    permissive.mcp_servers.insert(
        "echo-reload".to_string(),
        McpToolPolicy {
            allowed_tools: vec!["read".to_string(), "write".to_string()],
            denied_tools: vec![],
        },
    );
    bridge.policy().reload(permissive).await;

    // "write" should now pass through
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .json(&tools_call_request("write"))
        .send()
        .await
        .expect("request should connect");
    let body: serde_json::Value = resp.json().await.expect("json");
    assert!(
        body.get("error").is_none(),
        "write should be allowed after policy reload"
    );

    let _ = shutdown_tx.send(());
    bridge.shutdown().await.expect("shutdown");
}
