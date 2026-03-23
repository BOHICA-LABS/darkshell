//! Pure log-line-to-event parser.
//!
//! Transforms raw gateway log lines and proxy decision logs into structured
//! `WatchEvent` instances. This module is pure-core: no I/O, no side effects,
//! fully testable in isolation.
//!
//! The parser is intentionally lenient — malformed lines produce a
//! `WatchMeta` parse-error event rather than failing, per EC-W03.

use crate::event::{
    CommandEvent, EventPayload, FileEvent, LifecycleEvent, NetworkEvent, PolicyEvent,
    WatchEvent, WatchMetaEvent,
};

/// Attempt to parse a raw log line into a `WatchEvent`.
///
/// Returns `Some(event)` if the line contains a recognized pattern, or `None`
/// if the line is unrecognized (not an error — just not relevant).
///
/// Malformed lines that look like they *should* be events but can't be parsed
/// are returned as `WatchMeta` parse-error events.
pub fn parse_log_line(sandbox: &str, line: &str, byte_offset: u64) -> Option<WatchEvent> {
    // Skip empty lines and pure whitespace
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Check for non-UTF-8 replacement characters (EC-W03)
    if trimmed.contains('\u{FFFD}') {
        return Some(WatchEvent::new(
            sandbox,
            EventPayload::WatchMeta(WatchMetaEvent {
                overflow_count: None,
                parse_error_offset: Some(byte_offset),
                message: format!("skipped log line with non-UTF-8 bytes at offset {byte_offset}"),
            }),
        ));
    }

    // Try each pattern in order of specificity
    if let Some(event) = try_parse_policy_decision(sandbox, trimmed) {
        return Some(event);
    }
    if let Some(event) = try_parse_network_request(sandbox, trimmed) {
        return Some(event);
    }
    if let Some(event) = try_parse_command_executed(sandbox, trimmed) {
        return Some(event);
    }
    if let Some(event) = try_parse_file_changed(sandbox, trimmed) {
        return Some(event);
    }
    if let Some(event) = try_parse_lifecycle(sandbox, trimmed) {
        return Some(event);
    }

    // Unrecognized line — not an error, just not a known event pattern
    None
}

/// Try to parse a policy decision log line.
///
/// Expected pattern: `policy: <action> <endpoint> -> <result> [rule: <rule>]`
fn try_parse_policy_decision(sandbox: &str, line: &str) -> Option<WatchEvent> {
    let rest = line.strip_prefix("policy:")?;
    let rest = rest.trim();

    // Split on " -> " to get action/endpoint and result
    let (left, right) = rest.split_once(" -> ")?;
    let parts: Vec<&str> = left.trim().splitn(2, ' ').collect();
    let action = (*parts.first()?).to_string();
    let endpoint = parts.get(1).map(ToString::to_string);

    // Check for rule match after result
    let (result, rule_matched) = if let Some((r, rule_part)) = right.split_once(" [rule: ") {
        let rule = rule_part.strip_suffix(']').unwrap_or(rule_part);
        (r.trim().to_owned(), Some(rule.to_owned()))
    } else {
        (right.trim().to_owned(), None)
    };

    Some(WatchEvent::new(
        sandbox,
        EventPayload::PolicyDecision(PolicyEvent {
            action,
            binary: None,
            endpoint,
            result,
            rule_matched,
        }),
    ))
}

/// Try to parse a network request log line.
///
/// Expected pattern: `network: <method> <host>:<port> <result>`
fn try_parse_network_request(sandbox: &str, line: &str) -> Option<WatchEvent> {
    let rest = line.strip_prefix("network:")?;
    let rest = rest.trim();

    let parts: Vec<&str> = rest.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }

    let method = parts[0].to_owned();
    let host_port = parts[1];
    let policy_result = parts[2..].join(" ");

    let (host, port_str) = host_port.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;

    Some(WatchEvent::new(
        sandbox,
        EventPayload::NetworkRequest(NetworkEvent {
            host: host.to_owned(),
            port,
            method: Some(method),
            policy_result,
        }),
    ))
}

/// Try to parse a command executed log line.
///
/// Expected pattern: `exec: <command> [exit=<code>] [<duration>ms]`
fn try_parse_command_executed(sandbox: &str, line: &str) -> Option<WatchEvent> {
    let rest = line.strip_prefix("exec:")?;
    let rest = rest.trim();

    // Extract exit code if present
    let (command_part, exit_code) = if let Some(idx) = rest.find("[exit=") {
        let before = rest[..idx].trim();
        let after = &rest[idx + 6..];
        let end = after.find(']')?;
        let code = after[..end].parse::<i32>().ok();
        (before, code)
    } else {
        (rest, None)
    };

    // Extract duration if present
    let duration_ms = if let Some(idx) = rest.rfind("ms]") {
        // Look backwards for the opening bracket
        let bracket = rest[..idx].rfind('[')?;
        rest[bracket + 1..idx].trim().parse::<u64>().ok()
    } else {
        None
    };

    let command = command_part.trim_end_matches('[').trim().to_owned();
    if command.is_empty() {
        return None;
    }

    Some(WatchEvent::new(
        sandbox,
        EventPayload::CommandExecuted(CommandEvent {
            command,
            exit_code,
            duration_ms,
        }),
    ))
}

/// Try to parse a file changed log line.
///
/// Expected pattern: `file: <operation> <path> [by <process>]`
fn try_parse_file_changed(sandbox: &str, line: &str) -> Option<WatchEvent> {
    let rest = line.strip_prefix("file:")?;
    let rest = rest.trim();

    let (main_part, process) = if let Some((left, right)) = rest.split_once(" by ") {
        (left, Some(right.to_owned()))
    } else {
        (rest, None)
    };

    let parts: Vec<&str> = main_part.splitn(2, ' ').collect();
    if parts.len() < 2 {
        return None;
    }

    Some(WatchEvent::new(
        sandbox,
        EventPayload::FileChanged(FileEvent {
            operation: parts[0].to_owned(),
            path: parts[1].to_owned(),
            process,
        }),
    ))
}

/// Try to parse a lifecycle log line.
///
/// Expected pattern: `lifecycle: <phase> [from <previous_phase>]`
fn try_parse_lifecycle(sandbox: &str, line: &str) -> Option<WatchEvent> {
    let rest = line.strip_prefix("lifecycle:")?;
    let rest = rest.trim();

    let (phase, previous_phase) = if let Some((left, right)) = rest.split_once(" from ") {
        (left.trim().to_owned(), Some(right.trim().to_owned()))
    } else {
        (rest.to_owned(), None)
    };

    if phase.is_empty() {
        return None;
    }

    Some(WatchEvent::new(
        sandbox,
        EventPayload::SandboxStateChange(LifecycleEvent {
            phase,
            previous_phase,
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_policy_decision_line() {
        let event = parse_log_line("sb", "policy: network_access api.com:443 -> allow [rule: default-allow]", 0)
            .expect("should parse");
        assert_eq!(event.event_type(), "policy");
        if let EventPayload::PolicyDecision(p) = event.payload() {
            assert_eq!(p.action, "network_access");
            assert_eq!(p.endpoint.as_deref(), Some("api.com:443"));
            assert_eq!(p.result, "allow");
            assert_eq!(p.rule_matched.as_deref(), Some("default-allow"));
        } else {
            panic!("expected PolicyDecision");
        }
    }

    #[test]
    fn parse_network_request_line() {
        let event = parse_log_line("sb", "network: GET example.com:443 allowed", 0)
            .expect("should parse");
        assert_eq!(event.event_type(), "network");
        if let EventPayload::NetworkRequest(n) = event.payload() {
            assert_eq!(n.host, "example.com");
            assert_eq!(n.port, 443);
            assert_eq!(n.method.as_deref(), Some("GET"));
            assert_eq!(n.policy_result, "allowed");
        } else {
            panic!("expected NetworkRequest");
        }
    }

    #[test]
    fn parse_command_executed_line() {
        let event = parse_log_line("sb", "exec: cargo build [exit=0] [1234ms]", 0)
            .expect("should parse");
        assert_eq!(event.event_type(), "command");
        if let EventPayload::CommandExecuted(c) = event.payload() {
            assert_eq!(c.command, "cargo build");
            assert_eq!(c.exit_code, Some(0));
            assert_eq!(c.duration_ms, Some(1234));
        } else {
            panic!("expected CommandExecuted");
        }
    }

    #[test]
    fn parse_command_without_exit_or_duration() {
        let event = parse_log_line("sb", "exec: git status", 0).expect("should parse");
        if let EventPayload::CommandExecuted(c) = event.payload() {
            assert_eq!(c.command, "git status");
            assert_eq!(c.exit_code, None);
            assert_eq!(c.duration_ms, None);
        } else {
            panic!("expected CommandExecuted");
        }
    }

    #[test]
    fn parse_file_changed_line() {
        let event =
            parse_log_line("sb", "file: modify /sandbox/src/main.rs by cargo", 0)
                .expect("should parse");
        assert_eq!(event.event_type(), "file");
        if let EventPayload::FileChanged(f) = event.payload() {
            assert_eq!(f.operation, "modify");
            assert_eq!(f.path, "/sandbox/src/main.rs");
            assert_eq!(f.process.as_deref(), Some("cargo"));
        } else {
            panic!("expected FileChanged");
        }
    }

    #[test]
    fn parse_file_changed_without_process() {
        let event =
            parse_log_line("sb", "file: create /tmp/output.txt", 0).expect("should parse");
        if let EventPayload::FileChanged(f) = event.payload() {
            assert_eq!(f.process, None);
        } else {
            panic!("expected FileChanged");
        }
    }

    #[test]
    fn parse_lifecycle_line() {
        let event = parse_log_line("sb", "lifecycle: ready from provisioning", 0)
            .expect("should parse");
        assert_eq!(event.event_type(), "lifecycle");
        if let EventPayload::SandboxStateChange(lc) = event.payload() {
            assert_eq!(lc.phase, "ready");
            assert_eq!(lc.previous_phase.as_deref(), Some("provisioning"));
        } else {
            panic!("expected SandboxStateChange");
        }
    }

    #[test]
    fn parse_lifecycle_without_previous() {
        let event =
            parse_log_line("sb", "lifecycle: provisioning", 0).expect("should parse");
        if let EventPayload::SandboxStateChange(lc) = event.payload() {
            assert_eq!(lc.phase, "provisioning");
            assert_eq!(lc.previous_phase, None);
        } else {
            panic!("expected SandboxStateChange");
        }
    }

    #[test]
    fn parse_empty_line_returns_none() {
        assert!(parse_log_line("sb", "", 0).is_none());
        assert!(parse_log_line("sb", "   ", 0).is_none());
    }

    #[test]
    fn parse_unrecognized_line_returns_none() {
        assert!(parse_log_line("sb", "some random log output", 0).is_none());
    }

    #[test]
    fn parse_line_with_replacement_char_returns_parse_error() {
        let line = "exec: \u{FFFD}bad bytes\u{FFFD}";
        let event = parse_log_line("sb", line, 42).expect("should return meta event");
        assert_eq!(event.event_type(), "watch");
        if let EventPayload::WatchMeta(m) = event.payload() {
            assert_eq!(m.parse_error_offset, Some(42));
            assert!(m.message.contains("non-UTF-8"));
        } else {
            panic!("expected WatchMeta");
        }
    }

    #[test]
    fn parse_policy_without_rule() {
        let event =
            parse_log_line("sb", "policy: file_access /etc/passwd -> deny", 0)
                .expect("should parse");
        if let EventPayload::PolicyDecision(p) = event.payload() {
            assert_eq!(p.result, "deny");
            assert_eq!(p.rule_matched, None);
        } else {
            panic!("expected PolicyDecision");
        }
    }
}
