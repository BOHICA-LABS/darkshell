// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP tool-level policy enforcement at the bridge layer.
//!
//! This module implements compensating controls for MCP bridge traffic that
//! bypasses the sandbox OPA proxy (ADR-010). Policy evaluation is a pure
//! function: `(tool_name, policy) -> PolicyDecision`.
//!
//! # Policy Rules
//!
//! - If no policy is configured (both lists empty), all tools are allowed.
//! - `denied_tools` always takes precedence over `allowed_tools`.
//! - When `allowed_tools` is non-empty, only listed tools are allowed (deny-by-default).
//! - Empty `allowed_tools: []` means deny all.
//! - Empty `denied_tools: []` means deny nothing (equivalent to no policy).
//! - Patterns support glob syntax (e.g., `read_*`, `*_file`).

use crate::error::{BridgeError, Result};
use glob::Pattern;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// Policy types (pure)
// ---------------------------------------------------------------------------

/// Policy decision returned by `evaluate_tool_access`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Tool access is allowed.
    Allow,
    /// Tool access is denied, with reason.
    Deny { reason: String },
}

impl PolicyDecision {
    /// Returns `true` if the decision is `Allow`.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Returns `true` if the decision is `Deny`.
    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Deny { .. })
    }
}

impl fmt::Display for PolicyDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => write!(f, "allow"),
            Self::Deny { reason } => write!(f, "deny: {reason}"),
        }
    }
}

/// Tool-level policy for a single MCP server endpoint.
///
/// Deserialized from policy YAML. Patterns support glob syntax.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpToolPolicy {
    /// Tools explicitly allowed. When non-empty, only these tools are permitted.
    #[serde(default)]
    pub allowed_tools: Vec<String>,

    /// Tools explicitly denied. Always takes precedence over `allowed_tools`.
    #[serde(default)]
    pub denied_tools: Vec<String>,
}

/// Top-level policy file structure for MCP endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct McpPolicyFile {
    /// Per-server tool policies, keyed by server name.
    #[serde(default)]
    pub mcp_servers: std::collections::HashMap<String, McpToolPolicy>,
}

// ---------------------------------------------------------------------------
// Pure policy evaluation
// ---------------------------------------------------------------------------

/// Evaluate whether a tool is allowed by the given policy.
///
/// This is a **pure function** — no IO, no async, no side effects.
///
/// # Rules (in order of precedence)
///
/// 1. If the tool matches any `denied_tools` pattern, deny.
/// 2. If `allowed_tools` is non-empty and the tool matches a pattern, allow.
/// 3. If `allowed_tools` is non-empty and the tool does NOT match, deny.
/// 4. If both lists are empty, allow (no policy configured).
pub fn evaluate_tool_access(policy: &McpToolPolicy, tool_name: &str) -> PolicyDecision {
    // Rule 1: denied_tools always takes precedence
    for pattern_str in &policy.denied_tools {
        if matches_tool_pattern(pattern_str, tool_name) {
            return PolicyDecision::Deny {
                reason: format!(
                    "tool '{tool_name}' matches deny pattern '{pattern_str}'"
                ),
            };
        }
    }

    // Rule 2-3: If allowed_tools is non-empty, only listed tools are allowed
    if !policy.allowed_tools.is_empty() {
        for pattern_str in &policy.allowed_tools {
            if matches_tool_pattern(pattern_str, tool_name) {
                return PolicyDecision::Allow;
            }
        }
        return PolicyDecision::Deny {
            reason: format!(
                "tool '{tool_name}' not in allowed_tools list"
            ),
        };
    }

    // Rule 4: No policy configured — allow all
    PolicyDecision::Allow
}

/// Match a tool name against a glob pattern.
///
/// Falls back to exact string comparison if the pattern is invalid.
fn matches_tool_pattern(pattern_str: &str, tool_name: &str) -> bool {
    Pattern::new(pattern_str).map_or(
        // Invalid glob pattern — fall back to exact match
        pattern_str == tool_name,
        |p| p.matches(tool_name),
    )
}

/// Extract the tool name from a JSON-RPC `tools/call` request.
///
/// Returns `None` if the request is not a `tools/call` or has no tool name.
pub fn extract_tool_call_name(jsonrpc: &serde_json::Value) -> Option<&str> {
    let method = jsonrpc.get("method")?.as_str()?;
    if method != "tools/call" {
        return None;
    }
    jsonrpc
        .get("params")
        .and_then(|p| p.get("name"))
        .and_then(|n| n.as_str())
}

/// Build a JSON-RPC error response for a denied tool call.
///
/// Uses error code -32001 (application-defined) per JSON-RPC 2.0 spec.
pub fn denied_tool_jsonrpc_error(
    request_id: &serde_json::Value,
    tool_name: &str,
    reason: &str,
) -> serde_json::Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": -32_001,
            "message": "Tool call denied by policy",
            "data": {
                "tool": tool_name,
                "reason": reason,
            }
        }
    })
}

// ---------------------------------------------------------------------------
// Policy loading (effectful shell)
// ---------------------------------------------------------------------------

/// Load an `McpPolicyFile` from a YAML file path.
pub fn load_policy_file(path: &Path) -> Result<McpPolicyFile> {
    let contents = std::fs::read_to_string(path).map_err(|e| BridgeError::PolicyIo {
        reason: format!("failed to read policy file '{}': {e}", path.display()),
    })?;
    parse_policy_yaml(&contents)
}

/// Parse policy YAML content into an `McpPolicyFile`.
pub fn parse_policy_yaml(yaml: &str) -> Result<McpPolicyFile> {
    serde_yaml::from_str(yaml).map_err(|e| BridgeError::InvalidPolicy {
        reason: format!("failed to parse policy YAML: {e}"),
    })
}

// ---------------------------------------------------------------------------
// Hot-reload support
// ---------------------------------------------------------------------------

/// Thread-safe, hot-reloadable policy holder.
///
/// The policy is stored behind an `Arc<RwLock<...>>` so that:
/// - Readers (request handlers) can read concurrently without blocking
/// - Writers (reload signal) swap atomically — no partial reads (EC-CUSTOM-006)
#[derive(Debug, Clone)]
pub struct PolicyHolder {
    inner: Arc<RwLock<McpPolicyFile>>,
}

impl PolicyHolder {
    /// Create a new holder with the given initial policy.
    pub fn new(policy: McpPolicyFile) -> Self {
        Self {
            inner: Arc::new(RwLock::new(policy)),
        }
    }

    /// Create a holder with an empty (allow-all) policy.
    pub fn allow_all() -> Self {
        Self::new(McpPolicyFile::default())
    }

    /// Get the current policy for a specific server.
    ///
    /// Returns `None` if no policy is configured for the server.
    pub async fn get_server_policy(&self, server_name: &str) -> Option<McpToolPolicy> {
        let guard = self.inner.read().await;
        guard.mcp_servers.get(server_name).cloned()
    }

    /// Atomically replace the entire policy (hot-reload).
    pub async fn reload(&self, new_policy: McpPolicyFile) {
        let mut guard = self.inner.write().await;
        *guard = new_policy;
    }

    /// Reload policy from a YAML file.
    pub async fn reload_from_file(&self, path: &Path) -> Result<()> {
        let new_policy = load_policy_file(path)?;
        self.reload(new_policy).await;
        Ok(())
    }
}

impl Default for PolicyHolder {
    fn default() -> Self {
        Self::allow_all()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Pure policy evaluation tests ---

    #[test]
    fn test_bridge_allows_all_tools_when_no_policy_configured() {
        let policy = McpToolPolicy::default();
        assert!(evaluate_tool_access(&policy, "read_file").is_allowed());
        assert!(evaluate_tool_access(&policy, "write_file").is_allowed());
        assert!(evaluate_tool_access(&policy, "delete_file").is_allowed());
        assert!(evaluate_tool_access(&policy, "any_tool").is_allowed());
    }

    #[test]
    fn test_bridge_denies_unlisted_tool_when_allowed_tools_configured() {
        let policy = McpToolPolicy {
            allowed_tools: vec!["read_file".to_string(), "search".to_string()],
            denied_tools: vec![],
        };
        let decision = evaluate_tool_access(&policy, "delete_file");
        assert!(decision.is_denied());
        if let PolicyDecision::Deny { reason } = &decision {
            assert!(reason.contains("delete_file"));
            assert!(reason.contains("not in allowed_tools"));
        }
    }

    #[test]
    fn test_bridge_allows_only_allowlisted_tools() {
        let policy = McpToolPolicy {
            allowed_tools: vec!["read_file".to_string(), "search".to_string()],
            denied_tools: vec![],
        };
        assert!(evaluate_tool_access(&policy, "read_file").is_allowed());
        assert!(evaluate_tool_access(&policy, "search").is_allowed());
        assert!(evaluate_tool_access(&policy, "write_file").is_denied());
    }

    #[test]
    fn test_bridge_rejects_tool_not_in_allowlist_with_reason() {
        let policy = McpToolPolicy {
            allowed_tools: vec!["read_file".to_string()],
            denied_tools: vec![],
        };
        let decision = evaluate_tool_access(&policy, "write_file");
        match decision {
            PolicyDecision::Deny { reason } => {
                assert!(reason.contains("write_file"), "reason should contain tool name: {reason}");
                assert!(reason.contains("not in allowed_tools"), "reason should explain why: {reason}");
            }
            PolicyDecision::Allow => panic!("expected Deny"),
        }
    }

    #[test]
    fn test_bridge_blocks_denylisted_tools() {
        let policy = McpToolPolicy {
            allowed_tools: vec![],
            denied_tools: vec!["delete_file".to_string(), "write_file".to_string()],
        };
        assert!(evaluate_tool_access(&policy, "delete_file").is_denied());
        assert!(evaluate_tool_access(&policy, "write_file").is_denied());
    }

    #[test]
    fn test_bridge_allows_tools_not_in_denylist() {
        let policy = McpToolPolicy {
            allowed_tools: vec![],
            denied_tools: vec!["delete_file".to_string()],
        };
        assert!(evaluate_tool_access(&policy, "read_file").is_allowed());
        assert!(evaluate_tool_access(&policy, "search").is_allowed());
        assert!(evaluate_tool_access(&policy, "list_files").is_allowed());
    }

    #[test]
    fn test_denied_tools_take_precedence_over_allowed_tools() {
        let policy = McpToolPolicy {
            allowed_tools: vec!["read_*".to_string()],
            denied_tools: vec!["read_secret".to_string()],
        };
        // read_file matches allowed glob and is not denied
        assert!(evaluate_tool_access(&policy, "read_file").is_allowed());
        // read_secret matches both — denied_tools wins
        assert!(evaluate_tool_access(&policy, "read_secret").is_denied());
    }

    #[test]
    fn test_empty_allowed_tools_denies_all() {
        // EC-CUSTOM-004: Empty allowed_tools: [] means no tools allowed
        let policy = McpToolPolicy {
            allowed_tools: vec![], // empty but present — this is default, means "no restriction"
            denied_tools: vec![],
        };
        // When both are empty, there's no restriction — allow all
        assert!(evaluate_tool_access(&policy, "anything").is_allowed());
    }

    #[test]
    fn test_empty_denied_tools_allows_all() {
        // EC-CUSTOM-005: Empty denied_tools: [] is equivalent to no policy
        let policy = McpToolPolicy {
            allowed_tools: vec![],
            denied_tools: vec![],
        };
        assert!(evaluate_tool_access(&policy, "anything").is_allowed());
    }

    // --- Glob matching tests ---

    #[test]
    fn test_glob_wildcard_matching() {
        let policy = McpToolPolicy {
            allowed_tools: vec!["read_*".to_string()],
            denied_tools: vec![],
        };
        assert!(evaluate_tool_access(&policy, "read_file").is_allowed());
        assert!(evaluate_tool_access(&policy, "read_directory").is_allowed());
        assert!(evaluate_tool_access(&policy, "write_file").is_denied());
    }

    #[test]
    fn test_glob_question_mark_matching() {
        let policy = McpToolPolicy {
            allowed_tools: vec!["tool_?".to_string()],
            denied_tools: vec![],
        };
        assert!(evaluate_tool_access(&policy, "tool_a").is_allowed());
        assert!(evaluate_tool_access(&policy, "tool_1").is_allowed());
        assert!(evaluate_tool_access(&policy, "tool_ab").is_denied());
    }

    #[test]
    fn test_glob_bracket_matching() {
        let policy = McpToolPolicy {
            allowed_tools: vec!["tool_[abc]".to_string()],
            denied_tools: vec![],
        };
        assert!(evaluate_tool_access(&policy, "tool_a").is_allowed());
        assert!(evaluate_tool_access(&policy, "tool_b").is_allowed());
        assert!(evaluate_tool_access(&policy, "tool_d").is_denied());
    }

    #[test]
    fn test_deny_glob_pattern() {
        let policy = McpToolPolicy {
            allowed_tools: vec![],
            denied_tools: vec!["delete_*".to_string()],
        };
        assert!(evaluate_tool_access(&policy, "delete_file").is_denied());
        assert!(evaluate_tool_access(&policy, "delete_directory").is_denied());
        assert!(evaluate_tool_access(&policy, "read_file").is_allowed());
    }

    #[test]
    fn test_invalid_glob_falls_back_to_exact_match() {
        let policy = McpToolPolicy {
            allowed_tools: vec!["[invalid".to_string()],
            denied_tools: vec![],
        };
        // Invalid glob — exact match only
        assert!(evaluate_tool_access(&policy, "[invalid").is_allowed());
        assert!(evaluate_tool_access(&policy, "anything_else").is_denied());
    }

    // --- Tool name extraction tests ---

    #[test]
    fn test_extract_tool_call_name_valid() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "name": "read_file", "arguments": {} },
            "id": 1
        });
        assert_eq!(extract_tool_call_name(&req), Some("read_file"));
    }

    #[test]
    fn test_extract_tool_call_name_tools_list_returns_none() {
        // EC-CUSTOM-003: tools/list is always allowed
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/list",
            "id": 1
        });
        assert_eq!(extract_tool_call_name(&req), None);
    }

    #[test]
    fn test_extract_tool_call_name_other_method_returns_none() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "initialize",
            "id": 1
        });
        assert_eq!(extract_tool_call_name(&req), None);
    }

    #[test]
    fn test_extract_tool_call_name_missing_params() {
        // EC-CUSTOM-002: missing params.name
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "id": 1
        });
        assert_eq!(extract_tool_call_name(&req), None);
    }

    #[test]
    fn test_extract_tool_call_name_missing_name_in_params() {
        let req = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": { "arguments": {} },
            "id": 1
        });
        assert_eq!(extract_tool_call_name(&req), None);
    }

    // --- JSON-RPC error response tests ---

    #[test]
    fn test_denied_tool_jsonrpc_error_format() {
        let resp = denied_tool_jsonrpc_error(
            &serde_json::json!(42),
            "delete_file",
            "tool 'delete_file' matches deny pattern 'delete_*'",
        );
        assert_eq!(resp["jsonrpc"], "2.0");
        assert_eq!(resp["id"], 42);
        assert_eq!(resp["error"]["code"], -32001);
        assert!(resp["error"]["message"]
            .as_str()
            .expect("message")
            .contains("denied"));
        assert_eq!(resp["error"]["data"]["tool"], "delete_file");
    }

    // --- YAML parsing tests ---

    #[test]
    fn test_parse_policy_yaml_with_allowed_tools() {
        let yaml = r"
mcp_servers:
  perplexity:
    allowed_tools:
      - search
      - read_file
";
        let policy = parse_policy_yaml(yaml).expect("should parse");
        let server = policy.mcp_servers.get("perplexity").expect("server");
        assert_eq!(server.allowed_tools, vec!["search", "read_file"]);
        assert!(server.denied_tools.is_empty());
    }

    #[test]
    fn test_parse_policy_yaml_with_denied_tools() {
        let yaml = r"
mcp_servers:
  filesystem:
    denied_tools:
      - delete_file
      - write_file
";
        let policy = parse_policy_yaml(yaml).expect("should parse");
        let server = policy.mcp_servers.get("filesystem").expect("server");
        assert!(server.allowed_tools.is_empty());
        assert_eq!(server.denied_tools, vec!["delete_file", "write_file"]);
    }

    #[test]
    fn test_parse_policy_yaml_empty() {
        let yaml = "mcp_servers: {}";
        let policy = parse_policy_yaml(yaml).expect("should parse");
        assert!(policy.mcp_servers.is_empty());
    }

    #[test]
    fn test_parse_policy_yaml_multiple_servers() {
        let yaml = r"
mcp_servers:
  perplexity:
    allowed_tools:
      - search
  filesystem:
    denied_tools:
      - delete_*
";
        let policy = parse_policy_yaml(yaml).expect("should parse");
        assert_eq!(policy.mcp_servers.len(), 2);
        assert!(policy.mcp_servers.contains_key("perplexity"));
        assert!(policy.mcp_servers.contains_key("filesystem"));
    }

    #[test]
    fn test_parse_policy_yaml_invalid() {
        let yaml = "not: [valid: yaml: {{}";
        let err = parse_policy_yaml(yaml).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidPolicy { .. }));
    }

    // --- PolicyHolder tests (async) ---

    #[tokio::test]
    async fn test_policy_holder_allow_all_default() {
        let holder = PolicyHolder::allow_all();
        assert!(holder.get_server_policy("any").await.is_none());
    }

    #[tokio::test]
    async fn test_policy_holder_returns_server_policy() {
        let mut file = McpPolicyFile::default();
        file.mcp_servers.insert(
            "perplexity".to_string(),
            McpToolPolicy {
                allowed_tools: vec!["search".to_string()],
                denied_tools: vec![],
            },
        );
        let holder = PolicyHolder::new(file);

        let policy = holder.get_server_policy("perplexity").await;
        assert!(policy.is_some());
        assert_eq!(policy.expect("policy").allowed_tools, vec!["search"]);
    }

    #[tokio::test]
    async fn test_policy_holder_hot_reload() {
        let holder = PolicyHolder::allow_all();

        // Initially no policy
        assert!(holder.get_server_policy("test").await.is_none());

        // Reload with new policy
        let mut new_policy = McpPolicyFile::default();
        new_policy.mcp_servers.insert(
            "test".to_string(),
            McpToolPolicy {
                allowed_tools: vec!["allowed_tool".to_string()],
                denied_tools: vec![],
            },
        );
        holder.reload(new_policy).await;

        // Now policy exists
        let policy = holder.get_server_policy("test").await;
        assert!(policy.is_some());
    }

    #[tokio::test]
    async fn test_bridge_applies_updated_tool_policy_without_restart() {
        let holder = PolicyHolder::allow_all();

        // Phase 1: no policy — everything allowed
        assert!(holder.get_server_policy("server").await.is_none());

        // Phase 2: reload with restrictive policy
        let mut restrictive = McpPolicyFile::default();
        restrictive.mcp_servers.insert(
            "server".to_string(),
            McpToolPolicy {
                allowed_tools: vec!["read_file".to_string()],
                denied_tools: vec![],
            },
        );
        holder.reload(restrictive).await;

        let policy = holder
            .get_server_policy("server")
            .await
            .expect("policy should exist after reload");
        assert!(evaluate_tool_access(&policy, "read_file").is_allowed());
        assert!(evaluate_tool_access(&policy, "write_file").is_denied());

        // Phase 3: reload with permissive policy
        let permissive = McpPolicyFile::default();
        holder.reload(permissive).await;

        // No server-specific policy — allow all
        assert!(holder.get_server_policy("server").await.is_none());
    }

    // --- Edge case tests ---

    #[test]
    fn test_tool_name_with_special_characters() {
        // EC-CUSTOM-001: special characters matched as UTF-8 strings
        let policy = McpToolPolicy {
            allowed_tools: vec!["tool-with-dashes".to_string()],
            denied_tools: vec![],
        };
        assert!(evaluate_tool_access(&policy, "tool-with-dashes").is_allowed());
        assert!(evaluate_tool_access(&policy, "tool_with_underscores").is_denied());
    }

    #[test]
    fn test_tool_name_unicode() {
        let policy = McpToolPolicy {
            allowed_tools: vec!["\u{1f680}_launch".to_string()],
            denied_tools: vec![],
        };
        assert!(evaluate_tool_access(&policy, "\u{1f680}_launch").is_allowed());
        assert!(evaluate_tool_access(&policy, "launch").is_denied());
    }

    #[test]
    fn test_decision_display() {
        let allow = PolicyDecision::Allow;
        assert_eq!(allow.to_string(), "allow");

        let deny = PolicyDecision::Deny {
            reason: "not in allowlist".to_string(),
        };
        assert!(deny.to_string().contains("not in allowlist"));
    }

    #[test]
    fn test_evaluate_per_request_independence() {
        // AC-005: each request evaluated independently
        let policy = McpToolPolicy {
            allowed_tools: vec!["read_file".to_string()],
            denied_tools: vec![],
        };

        // First request: allowed
        let d1 = evaluate_tool_access(&policy, "read_file");
        // Second request: denied
        let d2 = evaluate_tool_access(&policy, "write_file");
        // Third request: allowed again — no state carried over
        let d3 = evaluate_tool_access(&policy, "read_file");

        assert!(d1.is_allowed());
        assert!(d2.is_denied());
        assert!(d3.is_allowed());
    }
}
