//! Inference request/response logging with configurable redaction.
//!
//! This module is split into pure-core and effectful parts:
//! - **Pure-core:** `InferenceEvent`, `RedactionConfig`, `redact_inference_event()`
//! - **Effectful:** Channel receiver that processes events from the proxy hook
//!
//! Redaction is always applied *before* any event emission (SOUL.md Rule 4).

use std::sync::atomic::{AtomicU64, Ordering};

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::warn;

/// Counter for events dropped due to channel backpressure (EC-I02).
static DROPPED_EVENTS: AtomicU64 = AtomicU64::new(0);

/// Maximum response body size before truncation (EC-I01: 1MB).
pub const MAX_RESPONSE_BYTES: usize = 1_048_576;

/// Default bounded channel capacity (AC-003).
pub const INFERENCE_CHANNEL_CAPACITY: usize = 1000;

/// A structured inference event captured by the proxy hook.
///
/// This is a pure data type — no I/O, no side effects. It can be freely
/// serialized, deserialized, and tested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InferenceEvent {
    /// Unique identifier for request correlation (EC-I06).
    pub request_id: String,

    /// When the inference request was initiated (UTC).
    pub timestamp: DateTime<Utc>,

    /// The model provider (e.g., "openai", "anthropic", "local").
    pub model_provider: String,

    /// The specific model used (e.g., "gpt-4", "claude-3-opus").
    pub model: String,

    /// The prompt/request content sent to the model.
    pub prompt: String,

    /// The response content received from the model.
    pub response: String,

    /// Number of prompt tokens (if reported by provider).
    pub prompt_tokens: Option<u64>,

    /// Number of completion tokens (if reported by provider).
    pub completion_tokens: Option<u64>,

    /// Request latency in milliseconds.
    pub latency_ms: u64,

    /// HTTP status code of the upstream response.
    pub status_code: u16,

    /// Whether the request resulted in an error.
    pub error: bool,

    /// Whether the response was truncated (EC-I01).
    pub truncated: bool,
}

/// Configuration for inference event redaction.
///
/// Redaction is applied in order: PII strip -> field hash -> truncation.
/// Default is no redaction (operator must opt in per AC-005).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RedactionConfig {
    /// Whether to strip PII patterns (emails, phone numbers, SSNs, etc.)
    /// from prompt and response content.
    #[serde(default)]
    pub strip_pii: bool,

    /// Fields to SHA-256 hash (valid: "prompt", "response", "model", "provider").
    #[serde(default)]
    pub hash_fields: Vec<String>,

    /// Maximum number of characters to keep in prompt/response content.
    /// Content beyond this limit is truncated with a "[TRUNCATED]" marker.
    #[serde(default)]
    pub truncate_tokens: Option<usize>,
}

impl Default for RedactionConfig {
    fn default() -> Self {
        Self {
            strip_pii: false,
            hash_fields: Vec::new(),
            truncate_tokens: None,
        }
    }
}

impl RedactionConfig {
    /// Create a config with no redaction (default).
    pub fn none() -> Self {
        Self::default()
    }

    /// Validate the configuration, warning about unknown field names (EC-I05).
    ///
    /// Returns a list of warnings for unknown fields.
    pub fn validate(&self) -> Vec<String> {
        const VALID_FIELDS: &[&str] = &["prompt", "response", "model", "provider"];
        let mut warnings = Vec::new();
        for field in &self.hash_fields {
            if !VALID_FIELDS.contains(&field.as_str()) {
                warnings.push(format!(
                    "Redaction field '{}' is not a valid InferenceEvent field. \
                     Valid fields: prompt, response, model, provider.",
                    field
                ));
            }
        }
        warnings
    }
}

/// Apply redaction to an inference event (pure function).
///
/// Redaction pipeline order: PII strip -> field hash -> truncation.
/// This function has no side effects and is fully testable in isolation.
pub fn redact_inference_event(event: &InferenceEvent, config: &RedactionConfig) -> InferenceEvent {
    let mut redacted = event.clone();

    // Step 1: Strip PII patterns from prompt and response
    if config.strip_pii {
        redacted.prompt = strip_pii(&redacted.prompt);
        redacted.response = strip_pii(&redacted.response);
    }

    // Step 2: Hash specified fields
    for field in &config.hash_fields {
        match field.as_str() {
            "prompt" => redacted.prompt = sha256_hash(&redacted.prompt),
            "response" => redacted.response = sha256_hash(&redacted.response),
            "model" => redacted.model = sha256_hash(&redacted.model),
            "provider" => redacted.model_provider = sha256_hash(&redacted.model_provider),
            _ => {
                // EC-I05: silently skip unknown fields (warning emitted at config load time)
            }
        }
    }

    // Step 3: Truncate prompt/response content
    if let Some(max_chars) = config.truncate_tokens {
        redacted.prompt = truncate_content(&redacted.prompt, max_chars);
        redacted.response = truncate_content(&redacted.response, max_chars);
    }

    redacted
}

/// Strip PII patterns from text content.
///
/// Patterns matched:
/// - Email addresses
/// - US phone numbers (various formats)
/// - US Social Security Numbers
/// - Credit card numbers (basic pattern)
fn strip_pii(text: &str) -> String {
    // Email addresses
    let email_re = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
        .expect("email regex is valid");
    let result = email_re.replace_all(text, "[EMAIL_REDACTED]");

    // US phone numbers: (555) 123-4567, 555-123-4567, +1-555-123-4567, etc.
    let phone_re =
        Regex::new(r"(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}")
            .expect("phone regex is valid");
    let result = phone_re.replace_all(&result, "[PHONE_REDACTED]");

    // SSN: 123-45-6789
    let ssn_re = Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("ssn regex is valid");
    let result = ssn_re.replace_all(&result, "[SSN_REDACTED]");

    // Credit card numbers (basic 16-digit pattern with optional separators)
    let cc_re = Regex::new(r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b")
        .expect("credit card regex is valid");
    cc_re.replace_all(&result, "[CC_REDACTED]").into_owned()
}

/// SHA-256 hash a string, returning the hex-encoded digest.
fn sha256_hash(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// Truncate content to a maximum character count, appending a marker if truncated.
fn truncate_content(text: &str, max_chars: usize) -> String {
    if text.len() <= max_chars {
        return text.to_owned();
    }
    // Find a valid char boundary at or before max_chars
    let boundary = text
        .char_indices()
        .take_while(|&(i, _)| i <= max_chars)
        .last()
        .map_or(0, |(i, _)| i);
    let mut truncated = text[..boundary].to_owned();
    truncated.push_str("[TRUNCATED]");
    truncated
}

/// Get the current count of dropped inference events (EC-I02).
pub fn dropped_event_count() -> u64 {
    DROPPED_EVENTS.load(Ordering::Relaxed)
}

/// Record a dropped event and log a warning periodically (EC-I02).
pub fn record_dropped_event() {
    let count = DROPPED_EVENTS.fetch_add(1, Ordering::Relaxed) + 1;
    if count % 100 == 1 {
        warn!(
            dropped_count = count,
            "inference event channel full, event dropped"
        );
    }
}

/// Reset the dropped event counter (for testing).
#[cfg(test)]
pub fn reset_dropped_count() {
    DROPPED_EVENTS.store(0, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn make_test_event() -> InferenceEvent {
        InferenceEvent {
            request_id: "req-001".to_owned(),
            timestamp: Utc::now(),
            model_provider: "openai".to_owned(),
            model: "gpt-4".to_owned(),
            prompt: "Hello, my email is john@example.com and my phone is 555-123-4567".to_owned(),
            response: "I see your email john@example.com".to_owned(),
            prompt_tokens: Some(20),
            completion_tokens: Some(10),
            latency_ms: 150,
            status_code: 200,
            error: false,
            truncated: false,
        }
    }

    // --- AC-005: Redaction tests ---

    #[test]
    fn test_redaction_strips_pii_from_events() {
        let event = make_test_event();
        let config = RedactionConfig {
            strip_pii: true,
            hash_fields: Vec::new(),
            truncate_tokens: None,
        };

        let redacted = redact_inference_event(&event, &config);

        assert!(!redacted.prompt.contains("john@example.com"));
        assert!(redacted.prompt.contains("[EMAIL_REDACTED]"));
        assert!(!redacted.prompt.contains("555-123-4567"));
        assert!(redacted.prompt.contains("[PHONE_REDACTED]"));
        assert!(!redacted.response.contains("john@example.com"));
        assert!(redacted.response.contains("[EMAIL_REDACTED]"));
    }

    #[test]
    fn test_redaction_strips_ssn() {
        let mut event = make_test_event();
        event.prompt = "SSN is 123-45-6789".to_owned();
        let config = RedactionConfig {
            strip_pii: true,
            ..Default::default()
        };

        let redacted = redact_inference_event(&event, &config);
        assert!(!redacted.prompt.contains("123-45-6789"));
        assert!(redacted.prompt.contains("[SSN_REDACTED]"));
    }

    #[test]
    fn test_redaction_strips_credit_card() {
        let mut event = make_test_event();
        event.prompt = "Card: 4111 1111 1111 1111".to_owned();
        let config = RedactionConfig {
            strip_pii: true,
            ..Default::default()
        };

        let redacted = redact_inference_event(&event, &config);
        assert!(!redacted.prompt.contains("4111 1111 1111 1111"));
        assert!(redacted.prompt.contains("[CC_REDACTED]"));
    }

    #[test]
    fn test_redaction_hashes_specified_fields() {
        let event = make_test_event();
        let config = RedactionConfig {
            strip_pii: false,
            hash_fields: vec!["prompt".to_owned(), "response".to_owned()],
            truncate_tokens: None,
        };

        let redacted = redact_inference_event(&event, &config);

        assert!(redacted.prompt.starts_with("sha256:"));
        assert!(redacted.response.starts_with("sha256:"));
        // Model and provider should be unchanged
        assert_eq!(redacted.model, "gpt-4");
        assert_eq!(redacted.model_provider, "openai");
    }

    #[test]
    fn test_redaction_hashes_model_and_provider() {
        let event = make_test_event();
        let config = RedactionConfig {
            strip_pii: false,
            hash_fields: vec!["model".to_owned(), "provider".to_owned()],
            truncate_tokens: None,
        };

        let redacted = redact_inference_event(&event, &config);

        assert!(redacted.model.starts_with("sha256:"));
        assert!(redacted.model_provider.starts_with("sha256:"));
        // Prompt and response should be unchanged
        assert_eq!(redacted.prompt, event.prompt);
        assert_eq!(redacted.response, event.response);
    }

    #[test]
    fn test_redaction_truncates_to_token_limit() {
        let mut event = make_test_event();
        event.prompt = "a".repeat(1000);
        event.response = "b".repeat(2000);
        let config = RedactionConfig {
            strip_pii: false,
            hash_fields: Vec::new(),
            truncate_tokens: Some(100),
        };

        let redacted = redact_inference_event(&event, &config);

        assert!(redacted.prompt.len() <= 100 + "[TRUNCATED]".len());
        assert!(redacted.prompt.ends_with("[TRUNCATED]"));
        assert!(redacted.response.len() <= 100 + "[TRUNCATED]".len());
        assert!(redacted.response.ends_with("[TRUNCATED]"));
    }

    #[test]
    fn test_redaction_truncate_does_not_affect_short_content() {
        let event = make_test_event();
        let config = RedactionConfig {
            strip_pii: false,
            hash_fields: Vec::new(),
            truncate_tokens: Some(10000),
        };

        let redacted = redact_inference_event(&event, &config);
        assert_eq!(redacted.prompt, event.prompt);
        assert_eq!(redacted.response, event.response);
    }

    #[test]
    fn test_no_redaction_passes_through_unchanged() {
        let event = make_test_event();
        let config = RedactionConfig::none();

        let redacted = redact_inference_event(&event, &config);
        assert_eq!(redacted, event);
    }

    #[test]
    fn test_redaction_pipeline_order_pii_then_hash_then_truncate() {
        // When all three are active, PII is stripped first, then the stripped
        // content is hashed, then truncation is applied to the hash output.
        let event = make_test_event();
        let config = RedactionConfig {
            strip_pii: true,
            hash_fields: vec!["prompt".to_owned()],
            truncate_tokens: Some(20),
        };

        let redacted = redact_inference_event(&event, &config);

        // The prompt was PII-stripped, then hashed (sha256:...), then truncated
        // sha256 hex output is 71 chars ("sha256:" + 64 hex), so it will be truncated
        assert!(redacted.prompt.ends_with("[TRUNCATED]"));
    }

    // --- EC-I05: Unknown field validation ---

    #[test]
    fn test_redaction_config_validates_known_fields() {
        let config = RedactionConfig {
            strip_pii: false,
            hash_fields: vec!["prompt".to_owned(), "response".to_owned()],
            truncate_tokens: None,
        };
        assert!(config.validate().is_empty());
    }

    #[test]
    fn test_redaction_config_warns_on_unknown_fields() {
        let config = RedactionConfig {
            strip_pii: false,
            hash_fields: vec!["prompt".to_owned(), "foo".to_owned(), "bar".to_owned()],
            truncate_tokens: None,
        };
        let warnings = config.validate();
        assert_eq!(warnings.len(), 2);
        assert!(warnings[0].contains("foo"));
        assert!(warnings[1].contains("bar"));
    }

    #[test]
    fn test_unknown_hash_field_is_silently_skipped_during_redaction() {
        let event = make_test_event();
        let config = RedactionConfig {
            strip_pii: false,
            hash_fields: vec!["nonexistent".to_owned()],
            truncate_tokens: None,
        };

        // Should not panic, event unchanged
        let redacted = redact_inference_event(&event, &config);
        assert_eq!(redacted, event);
    }

    // --- Serialization round-trip (VP-004) ---

    #[test]
    fn test_inference_event_serialization_round_trip() {
        let event = make_test_event();
        let json = serde_json::to_string(&event).expect("serialization should succeed");
        let deserialized: InferenceEvent =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_inference_event_json_includes_all_fields() {
        let event = make_test_event();
        let json = serde_json::to_string(&event).expect("serialization should succeed");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("should be valid JSON");

        assert_eq!(parsed["request_id"], "req-001");
        assert_eq!(parsed["model_provider"], "openai");
        assert_eq!(parsed["model"], "gpt-4");
        assert_eq!(parsed["latency_ms"], 150);
        assert_eq!(parsed["status_code"], 200);
        assert!(!parsed["error"].as_bool().unwrap());
        assert!(!parsed["truncated"].as_bool().unwrap());
    }

    #[test]
    fn test_inference_event_with_none_tokens() {
        let mut event = make_test_event();
        event.prompt_tokens = None;
        event.completion_tokens = None;

        let json = serde_json::to_string(&event).expect("serialization should succeed");
        let deserialized: InferenceEvent =
            serde_json::from_str(&json).expect("deserialization should succeed");
        assert_eq!(event, deserialized);
    }

    #[test]
    fn test_inference_event_error_case() {
        let event = InferenceEvent {
            request_id: "req-err".to_owned(),
            timestamp: Utc::now(),
            model_provider: "openai".to_owned(),
            model: "gpt-4".to_owned(),
            prompt: "test prompt".to_owned(),
            response: String::new(),
            prompt_tokens: None,
            completion_tokens: None,
            latency_ms: 5000,
            status_code: 500,
            error: true,
            truncated: false,
        };

        let json = serde_json::to_string(&event).expect("serialization should succeed");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        assert!(parsed["error"].as_bool().unwrap());
        assert_eq!(parsed["status_code"], 500);
        assert_eq!(parsed["response"], "");
    }

    // --- SHA-256 hashing ---

    #[test]
    fn test_sha256_hash_is_deterministic() {
        let h1 = sha256_hash("hello world");
        let h2 = sha256_hash("hello world");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sha256_hash_different_inputs_differ() {
        let h1 = sha256_hash("hello");
        let h2 = sha256_hash("world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_sha256_hash_format() {
        let h = sha256_hash("test");
        assert!(h.starts_with("sha256:"));
        // sha256 hex digest is 64 chars
        assert_eq!(h.len(), 7 + 64);
    }

    // --- Truncation ---

    #[test]
    fn test_truncate_content_within_limit() {
        assert_eq!(truncate_content("short", 100), "short");
    }

    #[test]
    fn test_truncate_content_at_exact_limit() {
        assert_eq!(truncate_content("12345", 5), "12345");
    }

    #[test]
    fn test_truncate_content_over_limit() {
        let result = truncate_content("1234567890", 5);
        assert!(result.ends_with("[TRUNCATED]"));
        assert!(result.starts_with("12345"));
    }

    #[test]
    fn test_truncate_empty_string() {
        assert_eq!(truncate_content("", 10), "");
    }

    // --- PII stripping ---

    #[test]
    fn test_strip_pii_email() {
        let result = strip_pii("Contact user@example.com for info");
        assert!(!result.contains("user@example.com"));
        assert!(result.contains("[EMAIL_REDACTED]"));
    }

    #[test]
    fn test_strip_pii_phone_formats() {
        assert!(strip_pii("Call 555-123-4567").contains("[PHONE_REDACTED]"));
        assert!(strip_pii("Call (555) 123-4567").contains("[PHONE_REDACTED]"));
        assert!(strip_pii("Call +1-555-123-4567").contains("[PHONE_REDACTED]"));
    }

    #[test]
    fn test_strip_pii_no_pii_unchanged() {
        let clean = "This is a normal prompt about coding";
        assert_eq!(strip_pii(clean), clean);
    }

    #[test]
    fn test_strip_pii_multiple_patterns() {
        let text = "Email: a@b.com, Phone: 555-111-2222, SSN: 123-45-6789";
        let result = strip_pii(text);
        assert!(result.contains("[EMAIL_REDACTED]"));
        assert!(result.contains("[PHONE_REDACTED]"));
        assert!(result.contains("[SSN_REDACTED]"));
    }

    // --- Dropped events ---

    #[test]
    fn test_dropped_event_counter() {
        reset_dropped_count();
        assert_eq!(dropped_event_count(), 0);
        record_dropped_event();
        assert_eq!(dropped_event_count(), 1);
        record_dropped_event();
        assert_eq!(dropped_event_count(), 2);
    }

    // --- RedactionConfig serialization ---

    #[test]
    fn test_redaction_config_default_is_no_redaction() {
        let config = RedactionConfig::default();
        assert!(!config.strip_pii);
        assert!(config.hash_fields.is_empty());
        assert!(config.truncate_tokens.is_none());
    }

    #[test]
    fn test_redaction_config_yaml_round_trip() {
        let config = RedactionConfig {
            strip_pii: true,
            hash_fields: vec!["prompt".to_owned()],
            truncate_tokens: Some(500),
        };
        let yaml = serde_json::to_string(&config).expect("serialize");
        let deserialized: RedactionConfig = serde_json::from_str(&yaml).expect("deserialize");
        assert_eq!(config, deserialized);
    }
}
