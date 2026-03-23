//! Live event stream implementation for `darkshell sandbox watch`.
//!
//! This module is the effectful shell: it manages long-lived connections,
//! log tailing, channel-based event delivery, auto-reconnect with exponential
//! backoff, and bounded channel overflow detection.
//!
//! Event parsing and filtering are delegated to the pure-core `parser` and
//! `filter` modules.

use std::time::Duration;

use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::error::ObserveError;
use crate::event::{EventPayload, LifecycleEvent, WatchEvent, WatchMetaEvent};
use crate::filter::EventFilter;

/// Default capacity for the event channel buffer (EC-W01).
const DEFAULT_CHANNEL_CAPACITY: usize = 1000;

/// Maximum backoff duration for auto-reconnect (AC-003).
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Initial backoff duration for auto-reconnect.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);

/// Configuration for a watch stream.
#[derive(Debug, Clone)]
pub struct WatchConfig {
    /// Name of the sandbox to watch.
    pub sandbox: String,

    /// Event type filter (empty = all events).
    pub filter: EventFilter,

    /// Output format: true for JSON lines, false for human-readable.
    pub json: bool,

    /// Whether the output is a TTY (for color decisions).
    pub is_tty: bool,

    /// Channel buffer capacity (defaults to 1000).
    pub channel_capacity: usize,
}

impl WatchConfig {
    /// Create a new `WatchConfig` with default settings.
    pub fn new(sandbox: impl Into<String>) -> Self {
        Self {
            sandbox: sandbox.into(),
            filter: EventFilter::all(),
            json: false,
            is_tty: false,
            channel_capacity: DEFAULT_CHANNEL_CAPACITY,
        }
    }

    /// Set the event filter.
    #[must_use]
    pub fn with_filter(mut self, filter: EventFilter) -> Self {
        self.filter = filter;
        self
    }

    /// Set JSON output mode.
    #[must_use]
    pub fn with_json(mut self, json: bool) -> Self {
        self.json = json;
        self
    }

    /// Set TTY detection result.
    #[must_use]
    pub fn with_tty(mut self, is_tty: bool) -> Self {
        self.is_tty = is_tty;
        self
    }
}

/// The live event stream that aggregates events from multiple sources.
///
/// In v1, event sources are:
/// - Gateway logs (polled via exec or gateway API)
/// - Sandbox exec output (commands run by the agent)
///
/// DS-017 through DS-019 will add eBPF sources.
pub struct EventStream {
    /// Configuration for this stream.
    config: WatchConfig,

    /// Receiving end of the event channel.
    receiver: mpsc::Receiver<WatchEvent>,

    /// Sending end (held so we can give clones to source tasks).
    sender: mpsc::Sender<WatchEvent>,

    /// Count of dropped events for overflow reporting.
    dropped_count: u64,
}

impl EventStream {
    /// Create a new event stream with the given configuration.
    pub fn new(config: WatchConfig) -> Self {
        let (sender, receiver) = mpsc::channel(config.channel_capacity);
        Self {
            config,
            receiver,
            sender,
            dropped_count: 0,
        }
    }

    /// Get a clone of the sender for feeding events from a source task.
    pub fn sender(&self) -> mpsc::Sender<WatchEvent> {
        self.sender.clone()
    }

    /// Get the watch configuration.
    pub fn config(&self) -> &WatchConfig {
        &self.config
    }

    /// Receive the next event that passes the filter.
    ///
    /// Returns `None` when all senders are dropped (stream ended).
    pub async fn next_event(&mut self) -> Option<WatchEvent> {
        loop {
            let event = self.receiver.recv().await?;
            if self.config.filter.matches(&event) {
                return Some(event);
            }
        }
    }

    /// Try to send an event, handling backpressure with overflow detection
    /// (EC-W01).
    ///
    /// When the channel is full, the event is dropped and the overflow count
    /// is incremented. An overflow meta-event is emitted periodically.
    pub fn try_send(&mut self, event: WatchEvent) {
        match self.sender.try_send(event) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped_count += 1;
                // Emit overflow warning every 100 drops to avoid flooding
                if self.dropped_count % 100 == 1 {
                    let overflow_event = WatchEvent::new(
                        &self.config.sandbox,
                        EventPayload::WatchMeta(WatchMetaEvent {
                            overflow_count: Some(self.dropped_count),
                            parse_error_offset: None,
                            message: format!(
                                "{} events dropped due to buffer overflow",
                                self.dropped_count
                            ),
                        }),
                    );
                    // OBS-F011: Always write overflow warning to stderr so it's visible
                    // even if tracing is not configured or the channel is full.
                    eprintln!(
                        "warning: {} events dropped due to buffer overflow",
                        self.dropped_count
                    );
                    // Best-effort: if we can't send the overflow event either, just log it
                    if self.sender.try_send(overflow_event).is_err() {
                        warn!(
                            dropped = self.dropped_count,
                            "event channel full, unable to emit overflow notification"
                        );
                    }
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                warn!("event channel closed, dropping event");
            }
        }
    }

    /// Format an event for output according to the stream configuration.
    pub fn format_event(&self, event: &WatchEvent) -> String {
        if self.config.json {
            // JSON mode: always produce JSON regardless of TTY
            event
                .to_json_line()
                .unwrap_or_else(|e| format!("{{\"error\": \"serialization failed: {e}\"}}"))
        } else {
            // Human-readable mode: color only when TTY
            event.to_human_readable(self.config.is_tty)
        }
    }
}

/// Check whether eBPF is available on the current platform.
///
/// Returns a human-readable reason if eBPF is NOT available.
/// On Linux with appropriate capabilities, returns `None` (available).
///
/// This is the graceful degradation check per AC-007 / EC-018.
pub fn check_ebpf_availability() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        // On Linux, eBPF may still be unavailable due to kernel version or
        // missing CAP_BPF. Full runtime check deferred to DS-017 when aya is
        // integrated. For now, indicate that eBPF probes are not yet
        // implemented.
        Some("eBPF probes not yet implemented (DS-017). Using log-based monitoring.".to_owned())
    }

    #[cfg(not(target_os = "linux"))]
    {
        Some(
            "eBPF unavailable on this platform. Falling back to log-based monitoring. \
             Some event types may be limited."
                .to_owned(),
        )
    }
}

/// Compute the next backoff duration for auto-reconnect (AC-003).
///
/// Uses exponential backoff: 1s, 2s, 4s, 8s, 16s, 30s (capped).
pub fn next_backoff(current: Duration) -> Duration {
    let doubled = current.saturating_mul(2);
    if doubled > MAX_BACKOFF {
        MAX_BACKOFF
    } else {
        doubled
    }
}

/// Get the initial backoff duration for reconnect attempts.
pub fn initial_backoff() -> Duration {
    INITIAL_BACKOFF
}

/// Create a "sandbox deleted" lifecycle event for clean exit (AC-005).
///
/// OBS-F010: `previous_phase` is caller-provided instead of hardcoded,
/// since the sandbox may be deleted from any phase (not just "ready").
pub fn sandbox_deleted_event(sandbox: &str, previous_phase: Option<&str>) -> WatchEvent {
    WatchEvent::new(
        sandbox,
        EventPayload::SandboxStateChange(LifecycleEvent {
            phase: "deleted".to_owned(),
            previous_phase: previous_phase.map(ToOwned::to_owned),
        }),
    )
}

/// Create a "sandbox not found" error with the list of available sandboxes
/// (AC-006).
pub fn sandbox_not_found_error(name: &str, available: &[String]) -> ObserveError {
    let available_str = if available.is_empty() {
        "(none)".to_owned()
    } else {
        available.join(", ")
    };
    ObserveError::SandboxNotFound {
        name: name.to_owned(),
        available: available_str,
    }
}

/// Emit the eBPF degradation message to stderr (AC-007 / EC-018).
pub fn emit_degradation_warning() {
    if let Some(msg) = check_ebpf_availability() {
        eprintln!("{msg}");
        info!(message = %msg, "eBPF availability check");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{CommandEvent, EventPayload, NetworkEvent};

    #[tokio::test]
    async fn event_stream_receives_sent_events() {
        let config = WatchConfig::new("test-sb");
        let mut stream = EventStream::new(config);
        let sender = stream.sender();

        let event = WatchEvent::new(
            "test-sb",
            EventPayload::CommandExecuted(CommandEvent {
                command: "echo hello".to_owned(),
                exit_code: Some(0),
                duration_ms: Some(5),
            }),
        );

        sender.send(event.clone()).await.expect("send should succeed");
        // Drop the extra sender so we can detect stream end
        drop(sender);

        let received = stream.next_event().await.expect("should receive event");
        assert_eq!(received.sandbox(), "test-sb");
        assert_eq!(received.event_type(), "command");
    }

    #[tokio::test]
    async fn event_stream_filters_events() {
        let filter = EventFilter::parse("network").expect("valid filter");
        let config = WatchConfig::new("sb").with_filter(filter);
        let mut stream = EventStream::new(config);
        let sender = stream.sender();

        // Send a command event (should be filtered out)
        let cmd_event = WatchEvent::new(
            "sb",
            EventPayload::CommandExecuted(CommandEvent {
                command: "ls".to_owned(),
                exit_code: None,
                duration_ms: None,
            }),
        );
        sender.send(cmd_event).await.expect("send should succeed");

        // Send a network event (should pass through)
        let net_event = WatchEvent::new(
            "sb",
            EventPayload::NetworkRequest(NetworkEvent {
                host: "example.com".to_owned(),
                port: 443,
                method: Some("GET".to_owned()),
                policy_result: "allowed".to_owned(),
            }),
        );
        sender.send(net_event).await.expect("send should succeed");

        // Drop sender to end the stream
        drop(sender);

        let received = stream.next_event().await.expect("should receive network event");
        assert_eq!(received.event_type(), "network");
    }

    #[test]
    fn format_event_json_mode() {
        let config = WatchConfig::new("sb").with_json(true);
        let stream = EventStream::new(config);

        let event = WatchEvent::new(
            "sb",
            EventPayload::CommandExecuted(CommandEvent {
                command: "test".to_owned(),
                exit_code: Some(0),
                duration_ms: None,
            }),
        );

        let output = stream.format_event(&event);
        // Should be valid JSON
        let _: serde_json::Value =
            serde_json::from_str(&output).expect("output should be valid JSON");
    }

    #[test]
    fn format_event_human_readable_no_tty() {
        let config = WatchConfig::new("sb").with_json(false).with_tty(false);
        let stream = EventStream::new(config);

        let event = WatchEvent::new(
            "sb",
            EventPayload::CommandExecuted(CommandEvent {
                command: "cargo build".to_owned(),
                exit_code: Some(0),
                duration_ms: Some(500),
            }),
        );

        let output = stream.format_event(&event);
        assert!(!output.contains("\x1b["), "non-TTY output should have no ANSI codes");
        assert!(output.contains("cargo build"));
    }

    #[test]
    fn format_event_human_readable_with_tty() {
        let config = WatchConfig::new("sb").with_json(false).with_tty(true);
        let stream = EventStream::new(config);

        let event = WatchEvent::new(
            "sb",
            EventPayload::CommandExecuted(CommandEvent {
                command: "test".to_owned(),
                exit_code: None,
                duration_ms: None,
            }),
        );

        let output = stream.format_event(&event);
        assert!(output.contains("\x1b["), "TTY output should have ANSI codes");
    }

    #[test]
    fn backoff_doubles_up_to_max() {
        let b1 = initial_backoff();
        assert_eq!(b1, Duration::from_secs(1));

        let b2 = next_backoff(b1);
        assert_eq!(b2, Duration::from_secs(2));

        let b3 = next_backoff(b2);
        assert_eq!(b3, Duration::from_secs(4));

        let b4 = next_backoff(b3);
        assert_eq!(b4, Duration::from_secs(8));

        let b5 = next_backoff(b4);
        assert_eq!(b5, Duration::from_secs(16));

        let b6 = next_backoff(b5);
        assert_eq!(b6, Duration::from_secs(30));

        // Should not exceed max
        let b7 = next_backoff(b6);
        assert_eq!(b7, Duration::from_secs(30));
    }

    #[test]
    fn check_ebpf_returns_degradation_message() {
        // On any platform, v1 always returns a degradation message
        let msg = check_ebpf_availability();
        assert!(msg.is_some(), "v1 should always report eBPF unavailable");
    }

    #[test]
    fn sandbox_deleted_event_has_correct_shape() {
        let event = sandbox_deleted_event("doomed", Some("ready"));
        assert_eq!(event.event_type(), "lifecycle");
        assert_eq!(event.sandbox(), "doomed");
        if let EventPayload::SandboxStateChange(lc) = event.payload() {
            assert_eq!(lc.phase, "deleted");
            assert_eq!(lc.previous_phase.as_deref(), Some("ready"));
        } else {
            panic!("expected SandboxStateChange");
        }
    }

    #[test]
    fn sandbox_deleted_event_accepts_none_previous_phase() {
        let event = sandbox_deleted_event("doomed", None);
        if let EventPayload::SandboxStateChange(lc) = event.payload() {
            assert_eq!(lc.phase, "deleted");
            assert_eq!(lc.previous_phase, None);
        } else {
            panic!("expected SandboxStateChange");
        }
    }

    #[test]
    fn sandbox_not_found_error_includes_available_list() {
        let err = sandbox_not_found_error("missing", &["sb-1".to_owned(), "sb-2".to_owned()]);
        let msg = err.to_string();
        assert!(msg.contains("missing"));
        assert!(msg.contains("sb-1, sb-2"));
    }

    #[test]
    fn sandbox_not_found_error_with_empty_list() {
        let err = sandbox_not_found_error("missing", &[]);
        let msg = err.to_string();
        assert!(msg.contains("(none)"));
    }

    #[test]
    fn try_send_overflow_increments_count() {
        // Create a stream with capacity 1
        let mut config = WatchConfig::new("sb");
        config.channel_capacity = 1;
        let mut stream = EventStream::new(config);

        // Fill the channel
        let event = WatchEvent::new(
            "sb",
            EventPayload::CommandExecuted(CommandEvent {
                command: "fill".to_owned(),
                exit_code: None,
                duration_ms: None,
            }),
        );
        stream.try_send(event.clone());

        // This should overflow
        stream.try_send(event.clone());
        assert_eq!(stream.dropped_count, 1);

        // Send more to see the count increase
        stream.try_send(event);
        assert_eq!(stream.dropped_count, 2);
    }

    #[test]
    fn watch_config_builder_with_tty_sets_field() {
        let config = WatchConfig::new("sb").with_tty(true);
        assert!(config.is_tty);
        assert_eq!(config.sandbox, "sb");
        // Defaults should be preserved
        assert!(!config.json);
        assert_eq!(config.channel_capacity, DEFAULT_CHANNEL_CAPACITY);
    }

    #[test]
    fn watch_config_builder_with_json_sets_field() {
        let config = WatchConfig::new("sb").with_json(true);
        assert!(config.json);
        assert_eq!(config.sandbox, "sb");
        // Defaults should be preserved
        assert!(!config.is_tty);
        assert_eq!(config.channel_capacity, DEFAULT_CHANNEL_CAPACITY);
    }
}
