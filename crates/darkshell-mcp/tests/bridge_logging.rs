// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for MCP bridge tool call logging through the full
//! HTTP request path.
//!
//! These tests verify that sending a real HTTP request through the bridge
//! produces structured log entries with the correct fields.

use darkshell_mcp::bridge::{BridgeConfig, McpBridge};
use darkshell_mcp::credential::CredentialProvider;
use darkshell_mcp::error::Result as BridgeResult;
use darkshell_mcp::logging::ToolCallLogger;
use darkshell_mcp::policy::PolicyHolder;
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

#[tokio::test]
async fn test_tool_call_logged_after_request() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = cat_bridge_config(tmp.path(), "log-sb", "echo-log");

    let (logger, mut rx) = ToolCallLogger::with_defaults();
    let logger = Arc::new(logger);

    let bridge = McpBridge::start(
        config,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        Some(logger),
    )
    .await
    .expect("bridge should start");

    let port = bridge.port();
    let bridge = Arc::new(bridge);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let serve_bridge = bridge.clone();
    tokio::spawn(async move { serve_bridge.serve(shutdown_rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send a tools/call request
    let jsonrpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "/tmp/test.txt"}
        },
        "id": 42
    });

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{port}/"))
        .json(&jsonrpc_request)
        .send()
        .await
        .expect("request should connect");
    assert_eq!(resp.status(), 200);

    // Give the logger a moment to process
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    // Verify log entry was emitted
    let log_entry = rx.try_recv().expect("should receive a log entry");
    assert_eq!(log_entry.server_name, "echo-log");
    assert_eq!(log_entry.tool_name, "read_file");
    assert_eq!(log_entry.sandbox, "log-sb");
    assert!(!log_entry.request_id.is_empty());
    assert_eq!(log_entry.jsonrpc_id.as_deref(), Some("42"));

    let _ = shutdown_tx.send(());
    bridge.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_log_includes_duration() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = cat_bridge_config(tmp.path(), "dur-sb", "echo-dur");

    let (logger, mut rx) = ToolCallLogger::with_defaults();
    let logger = Arc::new(logger);

    let bridge = McpBridge::start(
        config,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        Some(logger),
    )
    .await
    .expect("bridge should start");

    let port = bridge.port();
    let bridge = Arc::new(bridge);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let serve_bridge = bridge.clone();
    tokio::spawn(async move { serve_bridge.serve(shutdown_rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let jsonrpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "search",
            "arguments": {"query": "test"}
        },
        "id": 2
    });

    let client = reqwest::Client::new();
    client
        .post(format!("http://127.0.0.1:{port}/"))
        .json(&jsonrpc_request)
        .send()
        .await
        .expect("request should connect");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let log_entry = rx.try_recv().expect("should receive a log entry");
    // Duration is measured in milliseconds. cat is extremely fast so the
    // round-trip may complete in under 1ms (duration_ms == 0). The important
    // thing is that the field is populated and the log entry was created.
    // We verify the field exists and is a reasonable value (not u64::MAX or
    // some sentinel).
    assert!(
        log_entry.duration_ms < 10_000,
        "duration_ms should be reasonable, got {}",
        log_entry.duration_ms
    );
    assert_eq!(log_entry.tool_name, "search");

    let _ = shutdown_tx.send(());
    bridge.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn test_log_truncates_large_arguments() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let config = cat_bridge_config(tmp.path(), "trunc-sb", "echo-trunc");

    // Use a logger with a small truncation limit (128 bytes)
    let (logger, mut rx) = ToolCallLogger::new(10_000, 128);
    let logger = Arc::new(logger);

    let bridge = McpBridge::start(
        config,
        &NoopCredentialProvider,
        PolicyHolder::allow_all(),
        Some(logger),
    )
    .await
    .expect("bridge should start");

    let port = bridge.port();
    let bridge = Arc::new(bridge);
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let serve_bridge = bridge.clone();
    tokio::spawn(async move { serve_bridge.serve(shutdown_rx).await });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Send a request with very large arguments (>1KB)
    let large_value = "x".repeat(2000);
    let jsonrpc_request = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "big_tool",
            "arguments": {"data": large_value}
        },
        "id": 3
    });

    let client = reqwest::Client::new();
    client
        .post(format!("http://127.0.0.1:{port}/"))
        .json(&jsonrpc_request)
        .send()
        .await
        .expect("request should connect");

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let log_entry = rx.try_recv().expect("should receive a log entry");
    // Arguments should be truncated to at most 128 bytes + "..."
    assert!(
        log_entry.arguments.len() <= 131,
        "arguments should be truncated, got len={}",
        log_entry.arguments.len()
    );
    assert!(
        log_entry.arguments.ends_with("..."),
        "truncated arguments should end with '...'"
    );

    let _ = shutdown_tx.send(());
    bridge.shutdown().await.expect("shutdown");
}
