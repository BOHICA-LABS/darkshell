// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Structured logging for MCP tool calls at the bridge layer.
//!
//! This module provides non-blocking, channel-based logging of every MCP tool
//! invocation that passes through the bridge daemon. Log entries are structured
//! for JSON ingestion and compatible with `darkshell-observe`'s `McpToolCall`
//! event type.
//!
//! # Design
//!
//! - **Pure core:** `McpToolCallLog` construction and `format_tool_call_log()`
//!   are pure functions with no I/O.
//! - **Effectful shell:** `ToolCallLogger` uses a bounded `tokio::sync::mpsc`
//!   channel with `try_send` to never block the bridge request path.
//! - **Truncation safety:** All truncation is UTF-8 boundary-safe.

use crate::policy::extract_tool_call_name;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::mpsc;
use uuid::Uuid;

/// Default maximum length for truncated arguments/responses (in bytes).
pub const DEFAULT_MAX_TRUNCATE_LEN: usize = 1024;

/// Default channel capacity for non-blocking log delivery.
pub const DEFAULT_CHANNEL_CAPACITY: usize = 10_000;

/// A structured log entry for an MCP tool call.
///
/// This is a pure-core type: serializable, deserializable, and constructable
/// without any I/O.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolCallLog {
    /// Unique request ID for correlating request and response logs.
    pub request_id: String,

    /// Name of the MCP server that handled the call.
    pub server_name: String,

    /// Name of the tool that was called.
    pub tool_name: String,

    /// Serialized arguments (truncated to max length).
    pub arguments: String,

    /// Summary of the response (truncated to max length).
    pub response_summary: String,

    /// Duration of the call in milliseconds.
    pub duration_ms: u64,

    /// When the call was made (UTC).
    pub timestamp: DateTime<Utc>,

    /// Whether the call succeeded.
    pub success: bool,

    /// Sandbox name this bridge serves.
    pub sandbox: String,

    /// JSON-RPC error code, if the call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i64>,

    /// JSON-RPC error message, if the call failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,

    /// Original JSON-RPC request ID for protocol-level correlation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jsonrpc_id: Option<String>,
}

/// Truncate a string to at most `max_len` bytes, respecting UTF-8 boundaries.
///
/// If the string is longer than `max_len`, it is truncated at the last valid
/// UTF-8 character boundary at or before `max_len`, and "..." is appended.
///
/// This function never panics, even with empty strings or zero `max_len`.
pub fn truncate_utf8_safe(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        return s.to_owned();
    }

    if max_len < 4 {
        // Not enough room for even one char + "...", just return "..."
        return "...".to_owned();
    }

    let target = max_len - 3; // room for "..."

    // Find the last valid UTF-8 char boundary at or before target
    let mut end = target;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }

    let mut result = s[..end].to_owned();
    result.push_str("...");
    result
}

/// Extract the JSON-RPC method from a request.
pub fn extract_method(jsonrpc: &serde_json::Value) -> Option<&str> {
    jsonrpc.get("method").and_then(|m| m.as_str())
}

/// Extract arguments from a JSON-RPC `tools/call` request as a string.
pub fn extract_arguments(jsonrpc: &serde_json::Value, max_len: usize) -> String {
    let args = jsonrpc
        .get("params")
        .and_then(|p| p.get("arguments"))
        .map(ToString::to_string)
        .unwrap_or_default();
    truncate_utf8_safe(&args, max_len)
}

/// Extract a response summary from a JSON-RPC response.
///
/// For success responses, summarizes the `result` field.
/// For error responses, includes the error code and message.
/// For binary/non-UTF-8 content, returns a size description.
pub fn extract_response_summary(
    response: &serde_json::Value,
    max_len: usize,
) -> (String, bool, Option<i64>, Option<String>) {
    response.get("error").map_or_else(
        || {
            response.get("result").map_or_else(
                || ("<empty response>".to_owned(), true, None, None),
                |result| {
                    let raw = result.to_string();
                    (truncate_utf8_safe(&raw, max_len), true, None, None)
                },
            )
        },
        |error| {
            let code = error.get("code").and_then(serde_json::Value::as_i64);
            let message = error
                .get("message")
                .and_then(|m| m.as_str())
                .map(ToOwned::to_owned);
            let summary = format!(
                "error: code={}, message={}",
                code.map_or_else(|| "unknown".to_owned(), |c| c.to_string()),
                message.as_deref().unwrap_or("unknown")
            );
            (truncate_utf8_safe(&summary, max_len), false, code, message)
        },
    )
}

/// Extract the JSON-RPC request ID as a string (for correlation).
pub fn extract_request_id(jsonrpc: &serde_json::Value) -> String {
    jsonrpc
        .get("id")
        .map(|id| match id {
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

/// Format a `McpToolCallLog` as a structured JSON string.
///
/// This is a pure function suitable for use in tests and log sinks.
///
/// # Errors
///
/// Returns `serde_json::Error` if serialization fails (should not happen for
/// well-formed log entries).
pub fn format_tool_call_log(log: &McpToolCallLog) -> Result<String, serde_json::Error> {
    serde_json::to_string(log)
}

/// Build a complete `McpToolCallLog` from request, response, and timing data.
pub fn build_tool_call_log(
    server_name: &str,
    sandbox: &str,
    request: &serde_json::Value,
    response: &serde_json::Value,
    duration_ms: u64,
    max_truncate_len: usize,
) -> McpToolCallLog {
    let tool_name = extract_tool_call_name(request)
        .unwrap_or("unknown")
        .to_owned();
    let arguments = extract_arguments(request, max_truncate_len);
    let (response_summary, success, error_code, error_message) =
        extract_response_summary(response, max_truncate_len);
    let jsonrpc_id_raw = extract_request_id(request);
    let jsonrpc_id = if jsonrpc_id_raw.is_empty() {
        None
    } else {
        Some(jsonrpc_id_raw)
    };
    let request_id = ToolCallLogger::generate_request_id();

    McpToolCallLog {
        request_id,
        server_name: server_name.to_owned(),
        tool_name,
        arguments,
        response_summary,
        duration_ms,
        timestamp: Utc::now(),
        success,
        sandbox: sandbox.to_owned(),
        error_code,
        error_message,
        jsonrpc_id,
    }
}

/// Non-blocking, channel-based logger for MCP tool call events.
///
/// Uses `try_send` on a bounded channel so it never blocks the bridge request
/// path. Dropped events are counted and periodically warned about.
pub struct ToolCallLogger {
    sender: mpsc::Sender<McpToolCallLog>,
    dropped_count: AtomicU64,
    max_truncate_len: usize,
}

impl ToolCallLogger {
    /// Create a new logger with the given channel capacity and truncation limit.
    ///
    /// Returns the logger and a receiver for consuming log entries.
    pub fn new(
        capacity: usize,
        max_truncate_len: usize,
    ) -> (Self, mpsc::Receiver<McpToolCallLog>) {
        let (sender, receiver) = mpsc::channel(capacity);
        (
            Self {
                sender,
                dropped_count: AtomicU64::new(0),
                max_truncate_len,
            },
            receiver,
        )
    }

    /// Create a new logger with default settings.
    pub fn with_defaults() -> (Self, mpsc::Receiver<McpToolCallLog>) {
        Self::new(DEFAULT_CHANNEL_CAPACITY, DEFAULT_MAX_TRUNCATE_LEN)
    }

    /// Get the configured max truncation length.
    pub fn max_truncate_len(&self) -> usize {
        self.max_truncate_len
    }

    /// Get the number of dropped events since the logger was created.
    pub fn dropped_count(&self) -> u64 {
        self.dropped_count.load(Ordering::Relaxed)
    }

    /// Log a tool call. This is non-blocking: if the channel is full, the
    /// event is dropped and counted.
    pub fn log_tool_call(
        &self,
        server_name: &str,
        sandbox: &str,
        request: &serde_json::Value,
        response: &serde_json::Value,
        duration_ms: u64,
    ) {
        let log_entry = build_tool_call_log(
            server_name,
            sandbox,
            request,
            response,
            duration_ms,
            self.max_truncate_len,
        );

        // Emit tracing event with structured fields
        if log_entry.success {
            tracing::info!(
                server = %log_entry.server_name,
                tool = %log_entry.tool_name,
                duration_ms = log_entry.duration_ms,
                success = log_entry.success,
                sandbox = %log_entry.sandbox,
                request_id = %log_entry.request_id,
                "MCP tool call completed"
            );
        } else {
            tracing::warn!(
                server = %log_entry.server_name,
                tool = %log_entry.tool_name,
                duration_ms = log_entry.duration_ms,
                success = log_entry.success,
                sandbox = %log_entry.sandbox,
                request_id = %log_entry.request_id,
                error_code = ?log_entry.error_code,
                error_message = ?log_entry.error_message,
                "MCP tool call failed"
            );
        }

        // Non-blocking send — never slow down the bridge
        if self.sender.try_send(log_entry).is_err() {
            let prev = self.dropped_count.fetch_add(1, Ordering::Relaxed);
            // Warn every 100 drops to avoid log spam
            if prev.is_multiple_of(100) {
                tracing::warn!(
                    dropped_total = prev + 1,
                    "MCP tool call log channel full — dropping events"
                );
            }
        }
    }

    /// Log a `tools/list` request at debug level only (AC-007).
    pub fn log_tools_list(
        &self,
        server_name: &str,
        sandbox: &str,
        duration_ms: u64,
    ) {
        tracing::debug!(
            server = %server_name,
            sandbox = %sandbox,
            duration_ms = duration_ms,
            method = "tools/list",
            "MCP tools/list discovery request"
        );
    }

    /// Generate a unique request ID for correlation.
    pub fn generate_request_id() -> String {
        Uuid::new_v4().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- AC-001: Every tool call is logged with structured fields ---

    #[test]
    fn test_bridge_logs_tool_call_with_server_name_and_tool_name() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "read_file",
                "arguments": {"path": "/tmp/test.txt"}
            },
            "id": 1
        });
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"content": "hello"},
            "id": 1
        });

        let log = build_tool_call_log("perplexity", "dev-sandbox", &request, &response, 42, 1024);

        assert_eq!(log.server_name, "perplexity");
        assert_eq!(log.tool_name, "read_file");
        // request_id is a unique trace ID (UUID v7), not the JSON-RPC id
        assert!(!log.request_id.is_empty());
        assert_eq!(log.jsonrpc_id.as_deref(), Some("1"));
    }

    #[test]
    fn test_bridge_log_includes_arguments_and_timestamp() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": "search",
                "arguments": {"query": "rust async"}
            },
            "id": 2
        });
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"results": []},
            "id": 2
        });

        let log = build_tool_call_log("tavily", "test-sb", &request, &response, 100, 1024);

        assert!(log.arguments.contains("rust async"));
        // Timestamp should be recent (within last second)
        let now = Utc::now();
        let diff = now.signed_duration_since(log.timestamp);
        assert!(
            diff.num_seconds().abs() < 2,
            "timestamp should be recent, got diff={diff}"
        );
    }

    // --- AC-002: Response logged with summary and duration ---

    #[test]
    fn test_bridge_logs_response_with_duration_and_summary() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "fetch", "arguments": {}},
            "id": 3
        });
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"data": "some result data"},
            "id": 3
        });

        let log = build_tool_call_log("mcp-server", "sb", &request, &response, 250, 1024);

        assert_eq!(log.duration_ms, 250);
        assert!(log.response_summary.contains("some result data"));
        assert!(log.success);
    }

    #[test]
    fn test_bridge_truncates_response_summary_at_configured_limit() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "big_tool", "arguments": {}},
            "id": 4
        });
        let large_result = "x".repeat(5000);
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": large_result,
            "id": 4
        });

        let log = build_tool_call_log("server", "sb", &request, &response, 10, 512);

        // Response summary should be truncated to ~512 bytes
        assert!(
            log.response_summary.len() <= 515, // 512 + "..."
            "response_summary should be truncated, got len={}",
            log.response_summary.len()
        );
        assert!(log.response_summary.ends_with("..."));
    }

    // --- AC-003: Log entries are valid JSON ---

    #[test]
    fn test_bridge_log_entries_are_valid_json() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "test_tool", "arguments": {"key": "value"}},
            "id": 5
        });
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"ok": true},
            "id": 5
        });

        let log = build_tool_call_log("server", "my-sandbox", &request, &response, 50, 1024);
        let json_str = format_tool_call_log(&log).expect("should serialize");

        // Verify it's valid JSON
        let parsed: serde_json::Value =
            serde_json::from_str(&json_str).expect("output should be valid JSON");
        assert_eq!(parsed["server_name"], "server");
        assert_eq!(parsed["tool_name"], "test_tool");
        assert_eq!(parsed["duration_ms"], 50);
        assert_eq!(parsed["success"], true);
    }

    #[test]
    fn test_bridge_log_entries_include_sandbox_name() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "tool", "arguments": {}},
            "id": 6
        });
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": null,
            "id": 6
        });

        let log = build_tool_call_log("server", "production-sb", &request, &response, 10, 1024);
        let json_str = format_tool_call_log(&log).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json_str).expect("valid JSON");

        assert_eq!(parsed["sandbox"], "production-sb");
    }

    // --- AC-005: Failed tool calls logged with error details ---

    #[test]
    fn test_bridge_logs_error_responses_with_code_and_message() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "fail_tool", "arguments": {}},
            "id": 7
        });
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "error": {
                "code": -32601,
                "message": "Method not found"
            },
            "id": 7
        });

        let log = build_tool_call_log("server", "sb", &request, &response, 5, 1024);

        assert!(!log.success);
        assert_eq!(log.error_code, Some(-32601));
        assert_eq!(log.error_message.as_deref(), Some("Method not found"));
        assert!(log.response_summary.contains("-32601"));
        assert!(log.response_summary.contains("Method not found"));
    }

    // --- Truncation tests ---

    #[test]
    fn truncate_utf8_safe_no_truncation_needed() {
        let s = "hello world";
        assert_eq!(truncate_utf8_safe(s, 100), "hello world");
    }

    #[test]
    fn truncate_utf8_safe_truncates_long_string() {
        let s = "a".repeat(2000);
        let result = truncate_utf8_safe(&s, 1024);
        assert!(result.len() <= 1024);
        assert!(result.ends_with("..."));
    }

    #[test]
    fn truncate_utf8_safe_handles_multibyte_chars() {
        // Each emoji is 4 bytes
        let s = "\u{1F600}\u{1F601}\u{1F602}\u{1F603}\u{1F604}"; // 20 bytes
        let result = truncate_utf8_safe(s, 10);
        // Should not panic and should be valid UTF-8
        assert!(result.len() <= 13); // 10 - 3 = 7 bytes for content + 3 for "..."
        assert!(result.ends_with("..."));
        // Verify it's valid UTF-8 by checking it can be iterated
        for _ in result.chars() {}
    }

    #[test]
    fn truncate_utf8_safe_handles_empty_string() {
        assert_eq!(truncate_utf8_safe("", 100), "");
        assert_eq!(truncate_utf8_safe("", 0), "");
    }

    #[test]
    fn truncate_utf8_safe_handles_zero_max_len() {
        assert_eq!(truncate_utf8_safe("hello", 0), "...");
    }

    #[test]
    fn truncate_utf8_safe_handles_very_small_max_len() {
        assert_eq!(truncate_utf8_safe("hello world", 1), "...");
        assert_eq!(truncate_utf8_safe("hello world", 2), "...");
        assert_eq!(truncate_utf8_safe("hello world", 3), "...");
    }

    #[test]
    fn truncate_utf8_safe_handles_exact_boundary() {
        let s = "abcdefghij"; // 10 bytes
        assert_eq!(truncate_utf8_safe(s, 10), "abcdefghij");
        let result = truncate_utf8_safe(s, 9);
        assert_eq!(result, "abcdef...");
    }

    #[test]
    fn truncate_utf8_safe_handles_mixed_multibyte() {
        // "a" (1 byte) + "\u{00E9}" (2 bytes) + "\u{1F600}" (4 bytes) = 7 bytes
        let s = "a\u{00E9}\u{1F600}";
        assert_eq!(s.len(), 7);

        // Truncate at 6 should keep "a\u{00E9}" (3 bytes) + "..."
        let result = truncate_utf8_safe(s, 6);
        assert!(result.ends_with("..."));
        // The content part should be valid UTF-8
        for _ in result.chars() {}
    }

    // --- Field extraction tests ---

    #[test]
    fn extract_tool_call_name_from_tools_call() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {}},
            "id": 1
        });
        assert_eq!(extract_tool_call_name(&req), Some("read_file"));
    }

    #[test]
    fn extract_tool_call_name_returns_none_for_tools_list() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });
        assert_eq!(extract_tool_call_name(&req), None);
    }

    #[test]
    fn extract_tool_call_name_returns_none_for_missing_params() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1
        });
        assert_eq!(extract_tool_call_name(&req), None);
    }

    #[test]
    fn extract_method_from_request() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });
        assert_eq!(extract_method(&req), Some("tools/list"));
    }

    #[test]
    fn extract_arguments_truncates_large_payload() {
        let large_args = serde_json::json!({
            "data": "x".repeat(5000)
        });
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "tool", "arguments": large_args},
            "id": 1
        });

        let args = extract_arguments(&req, 512);
        assert!(args.len() <= 515); // 512 + "..."
    }

    #[test]
    fn extract_request_id_numeric() {
        let req = serde_json::json!({"id": 42});
        assert_eq!(extract_request_id(&req), "42");
    }

    #[test]
    fn extract_request_id_string() {
        let req = serde_json::json!({"id": "req-abc"});
        assert_eq!(extract_request_id(&req), "req-abc");
    }

    #[test]
    fn extract_request_id_missing() {
        let req = serde_json::json!({"method": "test"});
        assert_eq!(extract_request_id(&req), "");
    }

    // --- Response summary extraction ---

    #[test]
    fn extract_response_summary_success() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"tools": ["a", "b"]},
            "id": 1
        });
        let (summary, success, code, msg) = extract_response_summary(&resp, 1024);
        assert!(success);
        assert!(code.is_none());
        assert!(msg.is_none());
        assert!(summary.contains("tools"));
    }

    #[test]
    fn extract_response_summary_error() {
        let resp = serde_json::json!({
            "jsonrpc": "2.0",
            "error": {"code": -32600, "message": "Invalid Request"},
            "id": 1
        });
        let (summary, success, code, msg) = extract_response_summary(&resp, 1024);
        assert!(!success);
        assert_eq!(code, Some(-32600));
        assert_eq!(msg.as_deref(), Some("Invalid Request"));
        assert!(summary.contains("-32600"));
    }

    #[test]
    fn extract_response_summary_empty() {
        let resp = serde_json::json!({"jsonrpc": "2.0", "id": 1});
        let (summary, success, _, _) = extract_response_summary(&resp, 1024);
        assert!(success);
        assert_eq!(summary, "<empty response>");
    }

    // --- Non-blocking channel tests ---

    #[tokio::test]
    async fn test_bridge_logging_overhead_non_blocking() {
        let (logger, mut rx) = ToolCallLogger::new(10, 1024);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "fast_tool", "arguments": {}},
            "id": 1
        });
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"ok": true},
            "id": 1
        });

        // Measure logging overhead
        let start = std::time::Instant::now();
        for _ in 0..100 {
            logger.log_tool_call("server", "sb", &request, &response, 10);
        }
        let elapsed = start.elapsed();

        // Average should be well under 1ms per call
        let avg_us = elapsed.as_micros() / 100;
        assert!(
            avg_us < 1000,
            "logging overhead should be under 1ms, got {avg_us}us"
        );

        // Verify entries were received (up to channel capacity)
        let mut count = 0;
        while rx.try_recv().is_ok() {
            count += 1;
        }
        assert_eq!(count, 10, "channel capacity is 10, should receive 10 entries");
    }

    #[tokio::test]
    async fn test_channel_full_drops_events_and_counts() {
        let (logger, _rx) = ToolCallLogger::new(2, 1024);

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "tool", "arguments": {}},
            "id": 1
        });
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": null,
            "id": 1
        });

        // Send more than capacity
        for _ in 0..5 {
            logger.log_tool_call("server", "sb", &request, &response, 10);
        }

        assert!(
            logger.dropped_count() >= 3,
            "should have dropped at least 3 events, got {}",
            logger.dropped_count()
        );
    }

    #[tokio::test]
    async fn test_mcp_tool_call_events_available_to_watch_stream() {
        let (logger, mut rx) = ToolCallLogger::with_defaults();

        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": "search", "arguments": {"q": "test"}},
            "id": 10
        });
        let response = serde_json::json!({
            "jsonrpc": "2.0",
            "result": {"hits": 5},
            "id": 10
        });

        logger.log_tool_call("tavily", "dev-sb", &request, &response, 200);

        let log_entry = rx.try_recv().expect("should receive log entry");

        // Verify the log entry can be converted to a WatchEvent-compatible format
        assert_eq!(log_entry.server_name, "tavily");
        assert_eq!(log_entry.tool_name, "search");
        assert_eq!(log_entry.sandbox, "dev-sb");
        assert_eq!(log_entry.duration_ms, 200);
        assert!(log_entry.success);
    }

    // --- AC-007: tools/list at debug level only ---

    #[test]
    fn test_tools_list_logged_at_debug_level_only() {
        // Verify that extract_tool_call_name returns None for tools/list,
        // meaning it won't be processed as a tool call log entry
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });
        assert!(extract_tool_call_name(&req).is_none());
        assert_eq!(extract_method(&req), Some("tools/list"));
    }

    // --- format_tool_call_log tests ---

    #[test]
    fn format_tool_call_log_produces_valid_json() {
        let log = McpToolCallLog {
            request_id: "req-123".to_owned(),
            server_name: "test-server".to_owned(),
            tool_name: "my_tool".to_owned(),
            arguments: r#"{"key":"value"}"#.to_owned(),
            response_summary: r#"{"result":"ok"}"#.to_owned(),
            duration_ms: 42,
            timestamp: Utc::now(),
            success: true,
            sandbox: "test-sb".to_owned(),
            error_code: None,
            error_message: None,
            jsonrpc_id: Some("5".to_owned()),
        };

        let json = format_tool_call_log(&log).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed["request_id"], "req-123");
        assert_eq!(parsed["server_name"], "test-server");
        assert_eq!(parsed["tool_name"], "my_tool");
        assert_eq!(parsed["duration_ms"], 42);
        assert_eq!(parsed["success"], true);
        assert_eq!(parsed["sandbox"], "test-sb");
        // error_code and error_message should be absent (skip_serializing_if)
        assert!(parsed.get("error_code").is_none());
        assert!(parsed.get("error_message").is_none());
    }

    #[test]
    fn format_tool_call_log_includes_error_fields_when_present() {
        let log = McpToolCallLog {
            request_id: "req-456".to_owned(),
            server_name: "server".to_owned(),
            tool_name: "bad_tool".to_owned(),
            arguments: "{}".to_owned(),
            response_summary: "error: code=-32601, message=Not found".to_owned(),
            duration_ms: 5,
            timestamp: Utc::now(),
            success: false,
            sandbox: "sb".to_owned(),
            error_code: Some(-32601),
            error_message: Some("Not found".to_owned()),
            jsonrpc_id: Some("7".to_owned()),
        };

        let json = format_tool_call_log(&log).expect("should serialize");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should parse");

        assert_eq!(parsed["error_code"], -32601);
        assert_eq!(parsed["error_message"], "Not found");
        assert_eq!(parsed["success"], false);
    }

    #[test]
    fn generate_request_id_is_unique() {
        let id1 = ToolCallLogger::generate_request_id();
        let id2 = ToolCallLogger::generate_request_id();
        assert_ne!(id1, id2);
        assert!(!id1.is_empty());
    }
}
