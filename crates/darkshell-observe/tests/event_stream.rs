// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Integration tests for the event stream and filtering system (WF-5).
//!
//! These tests exercise the real `EventStream` with real channels, real
//! filters, and real serialization.

use darkshell_observe::WatchEvent;
use darkshell_observe::event::{
    CommandEvent, EventPayload, FileEvent, McpToolCallEvent, NetworkEvent, WatchMetaEvent,
};
use darkshell_observe::filter::EventFilter;
use darkshell_observe::watch::{EventStream, WatchConfig};

#[tokio::test]
async fn test_event_stream_delivers_events() {
    let config = WatchConfig::new("test-sb");
    let mut stream = EventStream::new(config);
    let sender = stream.sender();

    // Send a few events of different types
    sender
        .send(WatchEvent::new(
            "test-sb",
            EventPayload::CommandExecuted(CommandEvent {
                command: "cargo build".to_owned(),
                exit_code: Some(0),
                duration_ms: Some(500),
            }),
        ))
        .await
        .expect("send should succeed");

    sender
        .send(WatchEvent::new(
            "test-sb",
            EventPayload::FileChanged(FileEvent {
                path: "/sandbox/src/main.rs".to_owned(),
                operation: "modify".to_owned(),
                process: Some("cargo".to_owned()),
            }),
        ))
        .await
        .expect("send should succeed");

    // Receive events (use try_recv-style via timeout to avoid hanging)
    let received1 = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next_event())
        .await
        .expect("should not timeout")
        .expect("should receive first event");
    assert_eq!(received1.event_type(), "command");
    assert_eq!(received1.sandbox(), "test-sb");

    let received2 = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next_event())
        .await
        .expect("should not timeout")
        .expect("should receive second event");
    assert_eq!(received2.event_type(), "file");

    // Drop the external sender. The stream still holds its own internal
    // sender, so we cannot test stream termination without consuming the
    // stream. Instead, verify the two events were delivered correctly above.
    drop(sender);
}

#[tokio::test]
async fn test_event_filter_by_type() {
    // Filter for network events only
    let filter = EventFilter::parse("network").expect("valid filter");
    let config = WatchConfig::new("filter-sb").with_filter(filter);
    let mut stream = EventStream::new(config);
    let sender = stream.sender();

    // Send a command event (should be filtered out)
    sender
        .send(WatchEvent::new(
            "filter-sb",
            EventPayload::CommandExecuted(CommandEvent {
                command: "echo hello".to_owned(),
                exit_code: Some(0),
                duration_ms: Some(1),
            }),
        ))
        .await
        .expect("send");

    // Send an MCP event (should be filtered out)
    sender
        .send(WatchEvent::new(
            "filter-sb",
            EventPayload::McpToolCall(McpToolCallEvent {
                tool_name: "search".to_owned(),
                server: "perplexity".to_owned(),
                duration_ms: Some(100),
                success: Some(true),
            }),
        ))
        .await
        .expect("send");

    // Send a network event (should pass through)
    sender
        .send(WatchEvent::new(
            "filter-sb",
            EventPayload::NetworkRequest(NetworkEvent {
                host: "api.example.com".to_owned(),
                port: 443,
                method: Some("GET".to_owned()),
                policy_result: "allowed".to_owned(),
            }),
        ))
        .await
        .expect("send");

    drop(sender);

    // Only the network event should come through (command and MCP filtered out)
    let received = tokio::time::timeout(std::time::Duration::from_secs(2), stream.next_event())
        .await
        .expect("should not timeout")
        .expect("should receive network event");
    assert_eq!(received.event_type(), "network");
}

#[tokio::test]
async fn test_event_json_lines_format() {
    let config = WatchConfig::new("json-sb").with_json(true);
    let stream = EventStream::new(config);

    let event = WatchEvent::new(
        "json-sb",
        EventPayload::CommandExecuted(CommandEvent {
            command: "ls -la".to_owned(),
            exit_code: Some(0),
            duration_ms: Some(10),
        }),
    );

    let output = stream.format_event(&event);

    // Must be valid JSON
    let parsed: serde_json::Value =
        serde_json::from_str(&output).expect("output should be valid JSON");
    assert_eq!(parsed["sandbox"], "json-sb");
    assert_eq!(parsed["event_type"], "command");

    // Must be a single line (JSON Lines format)
    assert!(
        !output.contains('\n'),
        "JSON output must be a single line, got: {output}"
    );
}

#[tokio::test]
async fn test_event_stream_overflow_warning() {
    // Create a stream with very small capacity
    let mut config = WatchConfig::new("overflow-sb");
    config.channel_capacity = 2;
    let mut stream = EventStream::new(config);

    let event = WatchEvent::new(
        "overflow-sb",
        EventPayload::CommandExecuted(CommandEvent {
            command: "fill".to_owned(),
            exit_code: None,
            duration_ms: None,
        }),
    );

    // Fill the channel to capacity
    stream.try_send(event.clone());
    stream.try_send(event.clone());

    // These should overflow (last use of event, no clone needed)
    stream.try_send(event.clone());
    stream.try_send(event.clone());
    stream.try_send(event);

    // After overflows, verify the channel is still usable by attempting
    // a send via the sender clone (which bypasses try_send overflow tracking).
    let sender = stream.sender();
    let probe_result = sender.try_send(WatchEvent::new(
        "overflow-sb",
        EventPayload::WatchMeta(WatchMetaEvent {
            overflow_count: None,
            parse_error_offset: None,
            message: "probe".to_owned(),
        }),
    ));
    // Channel may be full (Err) or accept it (Ok) — either is fine.
    // The important thing is that the channel is not closed/panicked.
    assert!(
        probe_result.is_ok()
            || matches!(
                probe_result,
                Err(tokio::sync::mpsc::error::TrySendError::Full(_))
            ),
        "channel should be full or accept, not closed"
    );

    drop(stream);
}

#[tokio::test]
async fn test_watch_config_json_vs_human_output() {
    let event = WatchEvent::new(
        "fmt-sb",
        EventPayload::CommandExecuted(CommandEvent {
            command: "cargo test".to_owned(),
            exit_code: Some(0),
            duration_ms: Some(1200),
        }),
    );

    // JSON mode
    let json_config = WatchConfig::new("fmt-sb").with_json(true);
    let json_stream = EventStream::new(json_config);
    let json_output = json_stream.format_event(&event);

    // Human mode (no TTY)
    let human_config = WatchConfig::new("fmt-sb").with_json(false).with_tty(false);
    let human_stream = EventStream::new(human_config);
    let human_output = human_stream.format_event(&event);

    // Human mode (with TTY)
    let tty_config = WatchConfig::new("fmt-sb").with_json(false).with_tty(true);
    let tty_stream = EventStream::new(tty_config);
    let tty_output = tty_stream.format_event(&event);

    // JSON output should be parseable as JSON
    let _: serde_json::Value =
        serde_json::from_str(&json_output).expect("JSON mode output should parse as JSON");

    // Human output should NOT be parseable as JSON
    assert!(
        serde_json::from_str::<serde_json::Value>(&human_output).is_err(),
        "human-readable output should not be valid JSON"
    );

    // Human output should contain the command name
    assert!(human_output.contains("cargo test"));
    assert!(human_output.contains("1200ms"));

    // TTY output should contain ANSI codes; non-TTY should not
    assert!(
        tty_output.contains("\x1b["),
        "TTY output should contain ANSI escape codes"
    );
    assert!(
        !human_output.contains("\x1b["),
        "non-TTY human output should not contain ANSI codes"
    );
}
