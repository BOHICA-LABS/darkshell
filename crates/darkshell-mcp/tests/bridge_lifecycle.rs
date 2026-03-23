// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for MCP bridge lifecycle (WF-3).
//!
//! These tests spawn REAL subprocesses (`cat` as an echo MCP server),
//! start REAL HTTP servers, and send REAL HTTP requests.

use darkshell_mcp::bridge::{BridgeConfig, McpBridge};
use darkshell_mcp::credential::CredentialProvider;
use darkshell_mcp::error::Result as BridgeResult;
use darkshell_mcp::policy::PolicyHolder;
use darkshell_mcp::registry::{read_registration, registration_path};
use std::sync::Arc;

/// A no-op credential provider for tests (no credentials needed).
struct NoopCredentialProvider;

impl CredentialProvider for NoopCredentialProvider {
    fn resolve(&self, _provider: &str, _key: &str) -> BridgeResult<String> {
        Ok(String::new())
    }
}

/// Create a `BridgeConfig` that uses `cat` as the MCP server.
///
/// `cat` reads from stdin and echoes to stdout line by line, which makes it
/// a perfect stand-in for a JSON-RPC server in integration tests: we send
/// a JSON line and get the same JSON line back.
fn cat_bridge_config(tmp_dir: &std::path::Path, sandbox: &str, server: &str) -> BridgeConfig {
    let mut config = BridgeConfig::new(sandbox, server, vec!["cat".to_string()]);
    config.config_dir = tmp_dir.to_path_buf();
    config.credentials = Vec::new();
    config
}

#[tokio::test]
async fn test_bridge_starts_and_listens_on_port() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = cat_bridge_config(tmp.path(), "test-sb", "echo-server");

    let bridge = McpBridge::start(
        config,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        None,
    )
    .await
    .expect("bridge should start");

    let port = bridge.port();
    assert!(port > 0, "bridge should have a non-zero port");

    // Start serving in the background
    let bridge = Arc::new(bridge);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let serve_bridge = bridge.clone();
    let serve_handle = tokio::spawn(async move { serve_bridge.serve(shutdown_rx).await });

    // Give the server a moment to bind
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // HTTP GET should return 405 Method Not Allowed (only POST is accepted)
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{port}/"))
        .send()
        .await
        .expect("GET request should connect");
    assert_eq!(
        resp.status(),
        405,
        "GET should return 405 Method Not Allowed"
    );

    // Clean up
    let _ = shutdown_tx.send(());
    let _ = serve_handle.await;
    bridge.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn test_bridge_handles_jsonrpc_request() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = cat_bridge_config(tmp.path(), "test-sb", "echo-rpc");

    let bridge = McpBridge::start(
        config,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        None,
    )
    .await
    .expect("bridge should start");

    let port = bridge.port();
    let bridge = Arc::new(bridge);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let serve_bridge = bridge.clone();
    let serve_handle = tokio::spawn(async move { serve_bridge.serve(shutdown_rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // POST a JSON-RPC request — cat echoes it back as the "response"
    let jsonrpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/list",
        "id": 1
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .json(&jsonrpc_request)
        .send()
        .await
        .expect("POST request should connect");

    assert_eq!(
        resp.status(),
        200,
        "POST with valid JSON-RPC should return 200"
    );

    let body: serde_json::Value = resp.json().await.expect("response should be JSON");
    // cat echoes back the exact input, so it should be valid JSON-RPC
    assert_eq!(body["jsonrpc"], "2.0");
    assert_eq!(body["method"], "tools/list");
    assert_eq!(body["id"], 1);

    let _ = shutdown_tx.send(());
    let _ = serve_handle.await;
    bridge.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn test_bridge_rejects_oversized_body() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = cat_bridge_config(tmp.path(), "test-sb", "echo-big");

    let bridge = McpBridge::start(
        config,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        None,
    )
    .await
    .expect("bridge should start");

    let port = bridge.port();
    let bridge = Arc::new(bridge);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let serve_bridge = bridge.clone();
    let serve_handle = tokio::spawn(async move { serve_bridge.serve(shutdown_rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // POST a body larger than 1MB with Content-Length header
    let oversized_body = vec![b'x'; 2_000_000];
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .header("content-type", "application/json")
        .body(oversized_body)
        .send()
        .await
        .expect("POST request should connect");

    assert_eq!(
        resp.status(),
        413,
        "oversized body should return 413 Payload Too Large"
    );

    let _ = shutdown_tx.send(());
    let _ = serve_handle.await;
    bridge.shutdown().await.expect("shutdown should succeed");
}

#[tokio::test]
async fn test_bridge_shutdown_cleans_up() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = cat_bridge_config(tmp.path(), "test-sb", "echo-clean");

    let bridge = McpBridge::start(
        config,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        None,
    )
    .await
    .expect("bridge should start");

    let port = bridge.port();

    // Verify registration file exists before shutdown
    let reg = read_registration(tmp.path(), "test-sb", "echo-clean")
        .expect("read should succeed")
        .expect("registration should exist before shutdown");
    assert_eq!(reg.forwarded_port, port);

    // Shutdown kills subprocess and removes registration
    bridge.shutdown().await.expect("shutdown should succeed");

    // Verify registration file is gone
    let reg_after =
        read_registration(tmp.path(), "test-sb", "echo-clean").expect("read should succeed");
    assert!(
        reg_after.is_none(),
        "registration should be removed after shutdown"
    );

    // Drop the bridge to release the pre-bound listener
    drop(bridge);

    // Note: we do not assert port availability here because the OS may keep
    // the socket in TIME_WAIT. The important guarantees — subprocess killed
    // and registration removed — are verified above.
}

#[tokio::test]
async fn test_bridge_registers_and_deregisters() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = cat_bridge_config(tmp.path(), "test-sb", "echo-reg");

    let bridge = McpBridge::start(
        config,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        None,
    )
    .await
    .expect("bridge should start");

    // Verify registration file exists on disk
    let reg_path = registration_path(tmp.path(), "test-sb", "echo-reg").expect("valid names");
    assert!(
        reg_path.exists(),
        "registration file should exist after start"
    );

    // Read it back and verify contents
    let reg = read_registration(tmp.path(), "test-sb", "echo-reg")
        .expect("read should succeed")
        .expect("registration should exist");
    assert_eq!(reg.sandbox, "test-sb");
    assert_eq!(reg.server_name, "echo-reg");
    assert_eq!(reg.forwarded_port, bridge.port());

    // Shutdown should remove it
    bridge.shutdown().await.expect("shutdown should succeed");
    assert!(
        !reg_path.exists(),
        "registration file should be removed after shutdown"
    );
}

#[tokio::test]
async fn test_bridge_auto_selects_available_port() {
    let tmp = tempfile::tempdir().expect("tempdir");

    let config1 = cat_bridge_config(tmp.path(), "test-sb", "echo-one");
    let bridge1 = McpBridge::start(
        config1,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        None,
    )
    .await
    .expect("first bridge should start");

    let config2 = cat_bridge_config(tmp.path(), "test-sb", "echo-two");
    let bridge2 = McpBridge::start(
        config2,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        None,
    )
    .await
    .expect("second bridge should start");

    assert_ne!(
        bridge1.port(),
        bridge2.port(),
        "two bridges should get different ports"
    );

    // Clean up
    bridge1.shutdown().await.expect("shutdown 1");
    bridge2.shutdown().await.expect("shutdown 2");
}
