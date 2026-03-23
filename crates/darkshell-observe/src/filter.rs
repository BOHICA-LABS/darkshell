//! Event type filtering for the watch stream.
//!
//! Filters are specified as comma-separated event type names (e.g.,
//! `--filter command,network,policy`). This module parses filter strings
//! and applies them to events.

use crate::error::{ObserveError, Result};
use crate::event::WatchEvent;

/// Known event type names that can be used in filters.
pub const VALID_EVENT_TYPES: &[&str] = &[
    "command",
    "file",
    "network",
    "policy",
    "mcp",
    "lifecycle",
    "inference",
    "watch",
];

/// A parsed set of event type filters.
///
/// When the filter set is empty, all events pass through (no filtering).
#[derive(Debug, Clone, Default)]
pub struct EventFilter {
    /// Event types to include. Empty means "include all".
    types: Vec<String>,
}

impl EventFilter {
    /// Create a filter that passes all events.
    pub fn all() -> Self {
        Self { types: Vec::new() }
    }

    /// Parse a comma-separated filter string into an `EventFilter`.
    ///
    /// # Errors
    ///
    /// Returns `ObserveError::InvalidFilter` if any token is not a recognized
    /// event type.
    pub fn parse(filter_str: &str) -> Result<Self> {
        if filter_str.is_empty() {
            return Ok(Self::all());
        }

        let mut types = Vec::new();
        for token in filter_str.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if !VALID_EVENT_TYPES.contains(&token) {
                return Err(ObserveError::InvalidFilter {
                    filter: token.to_owned(),
                });
            }
            // OBS-F004: Deduplicate parsed types to avoid duplicate filter entries.
            let token_owned = token.to_owned();
            if !types.contains(&token_owned) {
                types.push(token_owned);
            }
        }

        Ok(Self { types })
    }

    /// Parse multiple `--type` flag values into a combined filter.
    ///
    /// Each value may itself be comma-separated. All are merged into one filter.
    ///
    /// # Errors
    ///
    /// Returns `ObserveError::InvalidFilter` if any token is not recognized.
    pub fn from_type_flags(flags: &[String]) -> Result<Self> {
        if flags.is_empty() {
            return Ok(Self::all());
        }

        let combined = flags.join(",");
        Self::parse(&combined)
    }

    /// Returns true if this event should be included in the output.
    pub fn matches(&self, event: &WatchEvent) -> bool {
        if self.types.is_empty() {
            return true;
        }
        self.types.iter().any(|t| t == event.event_type())
    }

    /// Returns true if no filtering is applied (all events pass).
    pub fn is_empty(&self) -> bool {
        self.types.is_empty()
    }

    /// Returns the list of active filter types.
    pub fn active_types(&self) -> &[String] {
        &self.types
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::*;

    fn make_event(event_type: &str) -> WatchEvent {
        let payload = match event_type {
            "command" => EventPayload::CommandExecuted(CommandEvent {
                command: "test".to_owned(),
                exit_code: None,
                duration_ms: None,
            }),
            "file" => EventPayload::FileChanged(FileEvent {
                path: "/tmp".to_owned(),
                operation: "create".to_owned(),
                process: None,
            }),
            "network" => EventPayload::NetworkRequest(NetworkEvent {
                host: "example.com".to_owned(),
                port: 443,
                method: None,
                policy_result: "allowed".to_owned(),
            }),
            "policy" => EventPayload::PolicyDecision(PolicyEvent {
                action: "network_access".to_owned(),
                binary: None,
                endpoint: None,
                result: "allow".to_owned(),
                rule_matched: None,
            }),
            "lifecycle" => EventPayload::SandboxStateChange(LifecycleEvent {
                phase: "ready".to_owned(),
                previous_phase: None,
            }),
            "inference" => EventPayload::Inference(crate::inference_log::InferenceEvent {
                request_id: "req-test".to_owned(),
                timestamp: chrono::Utc::now(),
                model_provider: "openai".to_owned(),
                model: "gpt-4".to_owned(),
                prompt: "test".to_owned(),
                response: "test".to_owned(),
                prompt_tokens: None,
                completion_tokens: None,
                latency_ms: 100,
                status_code: 200,
                error: false,
                truncated: false,
            }),
            "mcp" => EventPayload::McpToolCall(McpToolCallEvent {
                tool_name: "read_file".to_owned(),
                server: "filesystem".to_owned(),
                duration_ms: Some(50),
                success: Some(true),
            }),
            "watch" => EventPayload::WatchMeta(WatchMetaEvent {
                overflow_count: None,
                parse_error_offset: None,
                message: "test".to_owned(),
            }),
            _ => panic!("unknown event type in test helper: {event_type}"),
        };
        WatchEvent::new("sb", payload)
    }

    #[test]
    fn empty_filter_passes_all_events() {
        let filter = EventFilter::all();
        assert!(filter.matches(&make_event("command")));
        assert!(filter.matches(&make_event("network")));
        assert!(filter.matches(&make_event("lifecycle")));
    }

    #[test]
    fn parse_empty_string_returns_pass_all() {
        let filter = EventFilter::parse("").expect("empty string is valid");
        assert!(filter.is_empty());
        assert!(filter.matches(&make_event("command")));
    }

    #[test]
    fn parse_single_type_filters_correctly() {
        let filter = EventFilter::parse("network").expect("valid filter");
        assert!(filter.matches(&make_event("network")));
        assert!(!filter.matches(&make_event("command")));
        assert!(!filter.matches(&make_event("file")));
    }

    #[test]
    fn parse_multiple_types_comma_separated() {
        let filter = EventFilter::parse("network,policy").expect("valid filter");
        assert!(filter.matches(&make_event("network")));
        assert!(filter.matches(&make_event("policy")));
        assert!(!filter.matches(&make_event("command")));
        assert!(!filter.matches(&make_event("file")));
    }

    #[test]
    fn parse_trims_whitespace() {
        let filter = EventFilter::parse(" command , network ").expect("valid filter");
        assert!(filter.matches(&make_event("command")));
        assert!(filter.matches(&make_event("network")));
    }

    #[test]
    fn parse_rejects_unknown_type() {
        let err = EventFilter::parse("command,bogus").expect_err("should reject unknown type");
        match err {
            ObserveError::InvalidFilter { filter } => {
                assert_eq!(filter, "bogus");
            }
            other => panic!("expected InvalidFilter, got: {other}"),
        }
    }

    #[test]
    fn parse_skips_empty_tokens_from_trailing_commas() {
        let filter = EventFilter::parse("command,,network,").expect("valid filter");
        assert_eq!(filter.active_types().len(), 2);
    }

    #[test]
    fn from_type_flags_combines_multiple_flags() {
        let flags = vec!["command".to_owned(), "network,policy".to_owned()];
        let filter = EventFilter::from_type_flags(&flags).expect("valid flags");
        assert!(filter.matches(&make_event("command")));
        assert!(filter.matches(&make_event("network")));
        assert!(filter.matches(&make_event("policy")));
        assert!(!filter.matches(&make_event("file")));
    }

    #[test]
    fn from_type_flags_empty_returns_pass_all() {
        let filter = EventFilter::from_type_flags(&[]).expect("empty flags are valid");
        assert!(filter.is_empty());
    }

    #[test]
    fn all_valid_event_types_are_accepted() {
        for &t in VALID_EVENT_TYPES {
            EventFilter::parse(t)
                .unwrap_or_else(|_| panic!("'{t}' should be a valid event type"));
        }
    }

    #[test]
    fn invalid_filter_error_message_lists_all_valid_types() {
        let err = EventFilter::parse("bogus").expect_err("should reject unknown type");
        let msg = err.to_string();
        for &t in VALID_EVENT_TYPES {
            assert!(
                msg.contains(t),
                "InvalidFilter error message should mention '{t}', got: {msg}"
            );
        }
    }

    // --- OBS-F007: Tests for inference, mcp, and watch event types ---

    #[test]
    fn parse_inference_filter_matches_inference_events() {
        let filter = EventFilter::parse("inference").expect("valid filter");
        assert!(filter.matches(&make_event("inference")));
        assert!(!filter.matches(&make_event("command")));
    }

    #[test]
    fn parse_mcp_filter_matches_mcp_events() {
        let filter = EventFilter::parse("mcp").expect("valid filter");
        assert!(filter.matches(&make_event("mcp")));
        assert!(!filter.matches(&make_event("network")));
    }

    #[test]
    fn parse_watch_filter_matches_watch_events() {
        let filter = EventFilter::parse("watch").expect("valid filter");
        assert!(filter.matches(&make_event("watch")));
        assert!(!filter.matches(&make_event("lifecycle")));
    }

    #[test]
    fn parse_deduplicates_repeated_types() {
        let filter = EventFilter::parse("command,command,network,command").expect("valid filter");
        assert_eq!(filter.active_types().len(), 2);
        assert!(filter.matches(&make_event("command")));
        assert!(filter.matches(&make_event("network")));
    }
}
