//! Core event types for sandbox observation.
//!
//! All types in this module are pure-core: serializable, deserializable, and
//! testable without any I/O. These are the wire-format types emitted by
//! `darkshell sandbox watch`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A sandbox event emitted by the watch stream.
///
/// Every event carries a timestamp, sandbox identifier, and event type
/// discriminator alongside its type-specific payload.
///
/// The `event_type` field is computed from the payload variant (OBS-F009),
/// eliminating the dual source of truth. Custom Serialize/Deserialize impls
/// preserve the `event_type` field in the JSON wire format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    /// When the event occurred (UTC).
    timestamp: DateTime<Utc>,

    /// Which sandbox produced this event.
    sandbox: String,

    /// Type-specific payload.
    payload: EventPayload,
}

/// Helper struct for `WatchEvent` serialization that includes `event_type` in JSON.
#[derive(Serialize)]
struct WatchEventSer<'a> {
    timestamp: &'a DateTime<Utc>,
    sandbox: &'a str,
    event_type: &'a str,
    #[serde(flatten)]
    payload: &'a EventPayload,
}

/// Helper struct for `WatchEvent` deserialization.
#[derive(Deserialize)]
struct WatchEventDe {
    timestamp: DateTime<Utc>,
    sandbox: String,
    #[allow(dead_code)]
    event_type: String, // consumed but not stored; recomputed from payload
    #[serde(flatten)]
    payload: EventPayload,
}

impl Serialize for WatchEvent {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let ser = WatchEventSer {
            timestamp: &self.timestamp,
            sandbox: &self.sandbox,
            event_type: self.event_type(),
            payload: &self.payload,
        };
        ser.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WatchEvent {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let de = WatchEventDe::deserialize(deserializer)?;
        Ok(Self {
            timestamp: de.timestamp,
            sandbox: de.sandbox,
            payload: de.payload,
        })
    }
}

/// Type-specific event payloads.
///
/// This enum is `#[non_exhaustive]` because DS-017 through DS-020 will add
/// eBPF-sourced event types (process tree, file audit, inference logging).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind")]
#[non_exhaustive]
pub enum EventPayload {
    /// A command was executed inside the sandbox.
    #[serde(rename = "command_executed")]
    CommandExecuted(CommandEvent),

    /// A file was changed inside the sandbox.
    #[serde(rename = "file_changed")]
    FileChanged(FileEvent),

    /// A network request was made from the sandbox.
    #[serde(rename = "network_request")]
    NetworkRequest(NetworkEvent),

    /// A policy decision was made by the sandbox proxy/OPA.
    #[serde(rename = "policy_decision")]
    PolicyDecision(PolicyEvent),

    /// An MCP tool call was intercepted by the bridge daemon.
    #[serde(rename = "mcp_tool_call")]
    McpToolCall(McpToolCallEvent),

    /// The sandbox lifecycle state changed.
    #[serde(rename = "sandbox_state_change")]
    SandboxStateChange(LifecycleEvent),

    /// An inference request/response was captured by the proxy hook (DS-020).
    #[serde(rename = "inference")]
    Inference(crate::inference_log::InferenceEvent),

    /// Internal watch metadata event (overflow, parse errors).
    #[serde(rename = "watch_meta")]
    WatchMeta(WatchMetaEvent),
}

/// Details of a command execution event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommandEvent {
    /// The command that was executed.
    pub command: String,

    /// Exit code of the command (None if still running or unknown).
    pub exit_code: Option<i32>,

    /// Duration in milliseconds (None if still running or unknown).
    pub duration_ms: Option<u64>,
}

/// Details of a file change event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileEvent {
    /// Path of the file that changed.
    pub path: String,

    /// Type of file operation (e.g. "create", "modify", "delete", "rename").
    pub operation: String,

    /// Process that caused the change (if known).
    pub process: Option<String>,
}

/// Details of a network request event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NetworkEvent {
    /// Target host.
    pub host: String,

    /// Target port.
    pub port: u16,

    /// HTTP method (if applicable).
    pub method: Option<String>,

    /// Policy result for this request ("allowed" or "denied").
    pub policy_result: String,
}

/// Details of a policy decision event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyEvent {
    /// Action that was evaluated (e.g. `network_access`, `file_access`).
    pub action: String,

    /// Binary or process that triggered the policy check.
    pub binary: Option<String>,

    /// Target endpoint or resource.
    pub endpoint: Option<String>,

    /// Result of the policy evaluation ("allow" or "deny").
    pub result: String,

    /// Which policy rule matched (if any).
    pub rule_matched: Option<String>,
}

/// Details of an MCP tool call event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct McpToolCallEvent {
    /// Name of the MCP tool that was called.
    pub tool_name: String,

    /// MCP server that handled the call.
    pub server: String,

    /// Duration in milliseconds (None if still running).
    pub duration_ms: Option<u64>,

    /// Whether the call succeeded.
    pub success: Option<bool>,
}

/// Details of a sandbox lifecycle event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleEvent {
    /// Current lifecycle phase (e.g. "provisioning", "ready", "deleted").
    pub phase: String,

    /// Previous lifecycle phase (None for the first event).
    pub previous_phase: Option<String>,
}

/// Internal watch metadata (overflow, parse errors).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchMetaEvent {
    /// Number of events dropped due to channel overflow (EC-W01).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub overflow_count: Option<u64>,

    /// Byte offset in the log stream where a parse error occurred (EC-W03).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_error_offset: Option<u64>,

    /// Human-readable description of the meta event.
    pub message: String,
}

impl WatchEvent {
    /// Create a new `WatchEvent` with the current UTC timestamp.
    pub fn new(sandbox: impl Into<String>, payload: EventPayload) -> Self {
        Self {
            timestamp: Utc::now(),
            sandbox: sandbox.into(),
            payload,
        }
    }

    /// The event type discriminator, computed from the payload variant (OBS-F009).
    pub fn event_type(&self) -> &str {
        match &self.payload {
            EventPayload::CommandExecuted(_) => "command",
            EventPayload::FileChanged(_) => "file",
            EventPayload::NetworkRequest(_) => "network",
            EventPayload::PolicyDecision(_) => "policy",
            EventPayload::McpToolCall(_) => "mcp",
            EventPayload::SandboxStateChange(_) => "lifecycle",
            EventPayload::Inference(_) => "inference",
            EventPayload::WatchMeta(_) => "watch",
        }
    }

    /// When the event occurred (UTC).
    pub fn timestamp(&self) -> &DateTime<Utc> {
        &self.timestamp
    }

    /// Which sandbox produced this event.
    pub fn sandbox(&self) -> &str {
        &self.sandbox
    }

    /// Type-specific payload.
    pub fn payload(&self) -> &EventPayload {
        &self.payload
    }

    /// Serialize this event as a single JSON line (no trailing newline).
    ///
    /// # Errors
    ///
    /// Returns `serde_json::Error` if serialization fails (should not happen
    /// for well-formed events).
    pub fn to_json_line(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Format this event for human-readable display.
    ///
    /// When `color` is true, ANSI escape codes are included for terminal
    /// display. When false, plain text is emitted.
    pub fn to_human_readable(&self, color: bool) -> String {
        let ts = self.timestamp.format("%H:%M:%S%.3f");
        let type_label = self.event_type();

        let detail = match &self.payload {
            EventPayload::CommandExecuted(e) => {
                let exit = e
                    .exit_code
                    .map_or_else(|| "running".to_owned(), |c| format!("exit={c}"));
                let dur = e
                    .duration_ms
                    .map_or_else(String::new, |d| format!(" {d}ms"));
                format!("{} [{}]{}", e.command, exit, dur)
            }
            EventPayload::FileChanged(e) => {
                let proc = e
                    .process
                    .as_deref()
                    .map_or_else(String::new, |p| format!(" by {p}"));
                format!("{} {}{}", e.operation, e.path, proc)
            }
            EventPayload::NetworkRequest(e) => {
                let method = e.method.as_deref().unwrap_or("TCP");
                format!(
                    "{} {}:{} ({})",
                    method, e.host, e.port, e.policy_result
                )
            }
            EventPayload::PolicyDecision(e) => {
                let ep = e.endpoint.as_deref().unwrap_or("?");
                format!("{} {} -> {}", e.action, ep, e.result)
            }
            EventPayload::McpToolCall(e) => {
                let status = e.success.map_or("pending", |s| if s { "ok" } else { "failed" });
                format!("{} via {} [{}]", e.tool_name, e.server, status)
            }
            EventPayload::SandboxStateChange(e) => {
                let prev = e.previous_phase.as_deref().unwrap_or("none");
                format!("{} -> {}", prev, e.phase)
            }
            EventPayload::Inference(e) => {
                let status = if e.error { "error" } else { "ok" };
                format!(
                    "{}/{} [{}] {}ms",
                    e.model_provider, e.model, status, e.latency_ms
                )
            }
            EventPayload::WatchMeta(e) => e.message.clone(),
        };

        if color {
            let type_color = match type_label {
                "command" => "\x1b[36m",  // cyan
                "file" => "\x1b[33m",     // yellow
                "network" => "\x1b[35m",  // magenta
                "policy" => "\x1b[31m",   // red
                "mcp" => "\x1b[34m",      // blue
                "lifecycle" => "\x1b[32m",  // green
                "inference" => "\x1b[93m", // bright yellow
                _ => "\x1b[37m",           // white
            };
            format!(
                "\x1b[2m{ts}\x1b[0m {type_color}{type_label:<10}\x1b[0m {detail}"
            )
        } else {
            format!("{ts} {type_label:<10} {detail}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn watch_event_serializes_to_valid_json() {
        let event = WatchEvent::new(
            "test-sandbox",
            EventPayload::CommandExecuted(CommandEvent {
                command: "cargo build".to_owned(),
                exit_code: Some(0),
                duration_ms: Some(1234),
            }),
        );

        let json = event.to_json_line().expect("serialization should succeed");
        // Verify it's valid JSON by parsing it back
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("output should be valid JSON");
        assert_eq!(parsed["sandbox"], "test-sandbox");
        assert_eq!(parsed["event_type"], "command");
        assert_eq!(parsed["kind"], "command_executed");
        assert_eq!(parsed["command"], "cargo build");
        assert_eq!(parsed["exit_code"], 0);
    }

    #[test]
    fn watch_event_round_trips_through_json() {
        let event = WatchEvent::new(
            "my-sandbox",
            EventPayload::NetworkRequest(NetworkEvent {
                host: "api.example.com".to_owned(),
                port: 443,
                method: Some("GET".to_owned()),
                policy_result: "allowed".to_owned(),
            }),
        );

        let json = event.to_json_line().expect("serialization should succeed");
        let deserialized: WatchEvent =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(event, deserialized);
    }

    #[test]
    fn watch_event_json_is_single_line() {
        let event = WatchEvent::new(
            "sb",
            EventPayload::FileChanged(FileEvent {
                path: "/sandbox/src/main.rs".to_owned(),
                operation: "modify".to_owned(),
                process: Some("cargo".to_owned()),
            }),
        );

        let json = event.to_json_line().expect("serialization should succeed");
        assert!(
            !json.contains('\n'),
            "JSON line output must not contain newlines"
        );
    }

    #[test]
    fn watch_event_includes_timestamp_sandbox_and_event_type() {
        let event = WatchEvent::new(
            "test-sb",
            EventPayload::SandboxStateChange(LifecycleEvent {
                phase: "ready".to_owned(),
                previous_phase: Some("provisioning".to_owned()),
            }),
        );

        let json = event.to_json_line().expect("serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        assert!(parsed["timestamp"].is_string(), "must have timestamp");
        assert_eq!(parsed["sandbox"], "test-sb");
        assert_eq!(parsed["event_type"], "lifecycle");
    }

    #[test]
    fn all_event_types_serialize_successfully() {
        let payloads = vec![
            EventPayload::CommandExecuted(CommandEvent {
                command: "ls".to_owned(),
                exit_code: Some(0),
                duration_ms: Some(5),
            }),
            EventPayload::FileChanged(FileEvent {
                path: "/tmp/x".to_owned(),
                operation: "create".to_owned(),
                process: None,
            }),
            EventPayload::NetworkRequest(NetworkEvent {
                host: "example.com".to_owned(),
                port: 80,
                method: None,
                policy_result: "denied".to_owned(),
            }),
            EventPayload::PolicyDecision(PolicyEvent {
                action: "network_access".to_owned(),
                binary: Some("curl".to_owned()),
                endpoint: Some("evil.com:443".to_owned()),
                result: "deny".to_owned(),
                rule_matched: Some("default-deny".to_owned()),
            }),
            EventPayload::McpToolCall(McpToolCallEvent {
                tool_name: "read_file".to_owned(),
                server: "filesystem".to_owned(),
                duration_ms: Some(50),
                success: Some(true),
            }),
            EventPayload::SandboxStateChange(LifecycleEvent {
                phase: "deleted".to_owned(),
                previous_phase: Some("ready".to_owned()),
            }),
            EventPayload::Inference(crate::inference_log::InferenceEvent {
                request_id: "req-test".to_owned(),
                timestamp: Utc::now(),
                model_provider: "anthropic".to_owned(),
                model: "claude-3-opus".to_owned(),
                prompt: "test prompt".to_owned(),
                response: "test response".to_owned(),
                prompt_tokens: Some(10),
                completion_tokens: Some(20),
                latency_ms: 200,
                status_code: 200,
                error: false,
                truncated: false,
            }),
            EventPayload::WatchMeta(WatchMetaEvent {
                overflow_count: Some(42),
                parse_error_offset: None,
                message: "42 events dropped due to buffer overflow".to_owned(),
            }),
        ];

        for payload in payloads {
            let event = WatchEvent::new("sb", payload);
            let json = event.to_json_line().expect("all event types must serialize");
            let _: WatchEvent =
                serde_json::from_str(&json).expect("all event types must round-trip");
        }
    }

    #[test]
    fn human_readable_format_contains_event_type_and_detail() {
        let event = WatchEvent::new(
            "sb",
            EventPayload::CommandExecuted(CommandEvent {
                command: "git status".to_owned(),
                exit_code: Some(0),
                duration_ms: Some(100),
            }),
        );

        let output = event.to_human_readable(false);
        assert!(output.contains("command"), "should contain event type");
        assert!(output.contains("git status"), "should contain command");
        assert!(output.contains("exit=0"), "should contain exit code");
        assert!(output.contains("100ms"), "should contain duration");
    }

    #[test]
    fn human_readable_with_color_contains_ansi_codes() {
        let event = WatchEvent::new(
            "sb",
            EventPayload::NetworkRequest(NetworkEvent {
                host: "example.com".to_owned(),
                port: 443,
                method: Some("GET".to_owned()),
                policy_result: "allowed".to_owned(),
            }),
        );

        let output = event.to_human_readable(true);
        assert!(output.contains("\x1b["), "should contain ANSI codes");
    }

    #[test]
    fn human_readable_without_color_has_no_ansi_codes() {
        let event = WatchEvent::new(
            "sb",
            EventPayload::PolicyDecision(PolicyEvent {
                action: "network_access".to_owned(),
                binary: None,
                endpoint: Some("api.com:443".to_owned()),
                result: "allow".to_owned(),
                rule_matched: None,
            }),
        );

        let output = event.to_human_readable(false);
        assert!(!output.contains("\x1b["), "should not contain ANSI codes");
    }

    #[test]
    fn watch_meta_skips_none_fields_in_json() {
        let event = WatchEvent::new(
            "sb",
            EventPayload::WatchMeta(WatchMetaEvent {
                overflow_count: None,
                parse_error_offset: Some(1024),
                message: "parse error at offset 1024".to_owned(),
            }),
        );

        let json = event.to_json_line().expect("serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");

        assert!(
            parsed.get("overflow_count").is_none(),
            "None fields should be omitted"
        );
        assert_eq!(parsed["parse_error_offset"], 1024);
    }

    #[test]
    fn lifecycle_deleted_event_for_clean_exit() {
        let event = WatchEvent::new(
            "doomed-sandbox",
            EventPayload::SandboxStateChange(LifecycleEvent {
                phase: "deleted".to_owned(),
                previous_phase: Some("ready".to_owned()),
            }),
        );

        assert_eq!(event.event_type(), "lifecycle");
        if let EventPayload::SandboxStateChange(lc) = event.payload() {
            assert_eq!(lc.phase, "deleted");
        } else {
            panic!("expected SandboxStateChange payload");
        }
    }
}
