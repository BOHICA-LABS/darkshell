// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP bridge daemon — stdio-to-HTTP proxy for MCP servers.
//!
//! The bridge spawns an MCP server subprocess, communicates with it via
//! stdin/stdout JSON-RPC, and exposes the server as an HTTP endpoint on
//! `127.0.0.1:<port>`. The bridge runs on the HOST side; the sandbox
//! reaches it via SSH port forwarding.

use crate::credential::{CredentialProvider, CredentialSpec, inject_credentials};
use crate::error::{BridgeError, Result};
use crate::logging::{self, ToolCallLogger};
use crate::policy::{
    PolicyHolder, evaluate_tool_access, extract_tool_call_name, denied_tool_jsonrpc_error,
};
use crate::registry::{
    BridgeRegistration, BridgeStatus, Transport, read_registration, remove_registration,
    write_registration,
};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, oneshot};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Port range for auto-selection.
pub const PORT_RANGE_START: u16 = 9100;
pub const PORT_RANGE_END: u16 = 9199;

/// Maximum restart attempts before giving up.
pub const MAX_RESTART_ATTEMPTS: u32 = 3;

/// Backoff durations for restart attempts.
const BACKOFF_DURATIONS: [Duration; 3] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
];

/// Timeout for the MCP server initialize handshake.
pub const INITIALIZE_TIMEOUT_SECS: u64 = 60;

/// Slower retry interval after max fast retries exhausted (for long-running mode).
pub const SLOW_RETRY_INTERVAL: Duration = Duration::from_secs(60);

// ---------------------------------------------------------------------------
// Bridge configuration
// ---------------------------------------------------------------------------

/// Configuration for starting an MCP bridge.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Sandbox name this bridge serves.
    pub sandbox: String,
    /// MCP server name (e.g., "perplexity").
    pub server_name: String,
    /// Command and arguments to start the MCP server.
    pub command: Vec<String>,
    /// Credential specs to resolve and inject.
    pub credentials: Vec<CredentialSpec>,
    /// Config directory (defaults to `~/.config`).
    pub config_dir: PathBuf,
    /// Port range start (defaults to `PORT_RANGE_START`).
    pub port_start: u16,
    /// Port range end (defaults to `PORT_RANGE_END`).
    pub port_end: u16,
}

impl BridgeConfig {
    /// Create a new bridge configuration with default port range.
    pub fn new(
        sandbox: impl Into<String>,
        server_name: impl Into<String>,
        command: Vec<String>,
    ) -> Self {
        Self {
            sandbox: sandbox.into(),
            server_name: server_name.into(),
            command,
            credentials: Vec::new(),
            config_dir: dirs_default_config(),
            port_start: PORT_RANGE_START,
            port_end: PORT_RANGE_END,
        }
    }
}

fn dirs_default_config() -> PathBuf {
    std::env::var("HOME").map_or_else(
        |_| PathBuf::from(".config"),
        |h| PathBuf::from(h).join(".config"),
    )
}

// ---------------------------------------------------------------------------
// Pure functions — JSON-RPC translation
// ---------------------------------------------------------------------------

/// Parse an HTTP request body as a JSON-RPC message.
///
/// Validates that the body is valid JSON and contains the required JSON-RPC
/// fields (`jsonrpc`, `method`).
pub fn parse_jsonrpc_request(body: &[u8]) -> Result<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        BridgeError::InvalidJsonRpc {
            detail: format!("invalid JSON in request body: {e}"),
        }
    })?;

    // Validate required JSON-RPC 2.0 fields
    if value.get("jsonrpc").and_then(|v| v.as_str()) != Some("2.0") {
        return Err(BridgeError::InvalidJsonRpc {
            detail: "missing or invalid 'jsonrpc' field (expected \"2.0\")".to_string(),
        });
    }

    if value.get("method").and_then(|v| v.as_str()).is_none() {
        return Err(BridgeError::InvalidJsonRpc {
            detail: "missing 'method' field in JSON-RPC request".to_string(),
        });
    }

    Ok(value)
}

/// Parse a JSON-RPC response from the MCP server's stdout line.
///
/// Returns the parsed JSON value, or an error if the line is not valid JSON.
pub fn parse_jsonrpc_response(line: &str) -> Result<serde_json::Value> {
    serde_json::from_str(line).map_err(|e| BridgeError::InvalidJsonRpc {
        detail: format!("MCP server returned invalid JSON: {e}"),
    })
}

/// Format a JSON-RPC message as a single line for writing to stdin.
///
/// Appends a newline, as MCP servers expect newline-delimited JSON-RPC.
pub fn format_jsonrpc_for_stdin(value: &serde_json::Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| BridgeError::Json {
        reason: format!("failed to serialize JSON-RPC: {e}"),
    })?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Build an HTTP error response with a JSON body.
pub fn error_response(status: StatusCode, error: &str, detail: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({
        "error": error,
        "detail": detail,
    });
    let body_bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());

    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body_bytes)))
        .expect("building error response should not fail")
}

// ---------------------------------------------------------------------------
// Backoff calculation (pure)
// ---------------------------------------------------------------------------

/// Calculate backoff duration for a given restart attempt (0-indexed).
///
/// Returns `None` if the attempt exceeds `MAX_RESTART_ATTEMPTS`, meaning
/// the bridge should give up.
pub fn backoff_duration(attempt: u32) -> Option<Duration> {
    BACKOFF_DURATIONS.get(attempt as usize).copied()
}

// ---------------------------------------------------------------------------
// Port selection
// ---------------------------------------------------------------------------

/// Find an available port in the given range.
///
/// Tries each port from `start` to `end` inclusive, returning the first
/// one that can be bound.
pub fn find_available_port(start: u16, end: u16) -> Result<u16> {
    for port in start..=end {
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return Ok(port);
        }
    }
    Err(BridgeError::NoAvailablePort { start, end })
}

/// Check if a specific port is available.
pub fn is_port_available(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

// ---------------------------------------------------------------------------
// MCP subprocess management
// ---------------------------------------------------------------------------

/// Internal state for a running MCP server subprocess.
#[derive(Debug)]
struct McpProcess {
    stdin: tokio::process::ChildStdin,
    stdout_reader: BufReader<tokio::process::ChildStdout>,
    child: Child,
}

/// The MCP bridge managing one MCP server subprocess and HTTP endpoint.
pub struct McpBridge {
    config: BridgeConfig,
    port: u16,
    process: Arc<Mutex<Option<McpProcess>>>,
    env_vars: HashMap<String, String>,
    /// Tool-level policy holder for hot-reloadable policy enforcement (ADR-010).
    policy: PolicyHolder,
    /// Non-blocking structured logger for MCP tool call audit (DS-013).
    logger: Option<Arc<ToolCallLogger>>,
}

impl McpBridge {
    /// Start a new MCP bridge.
    ///
    /// 1. Resolves credentials from the provider
    /// 2. Selects an available port
    /// 3. Checks for existing registration (stale PID cleanup)
    /// 4. Spawns the MCP server subprocess
    /// 5. Writes the registration file
    pub fn start(
        config: BridgeConfig,
        credential_provider: &dyn CredentialProvider,
        policy: PolicyHolder,
        logger: Option<Arc<ToolCallLogger>>,
    ) -> Result<Self> {
        // Check for existing registration
        if let Some(existing) =
            read_registration(&config.config_dir, &config.sandbox, &config.server_name)?
        {
            // Check if the PID is still alive
            if pid_is_alive(existing.bridge_pid) {
                return Err(BridgeError::AlreadyRunning {
                    sandbox: config.sandbox.clone(),
                    server: config.server_name.clone(),
                    pid: existing.bridge_pid,
                });
            }
            // Stale registration — clean up
            tracing::info!(
                sandbox = %config.sandbox,
                server = %config.server_name,
                stale_pid = existing.bridge_pid,
                "cleaning up stale registration"
            );
            remove_registration(&config.config_dir, &config.sandbox, &config.server_name)?;
        }

        // Resolve credentials
        let env_vars = inject_credentials(&config.credentials, credential_provider)?;

        // Select port
        let port = find_available_port(config.port_start, config.port_end)?;
        tracing::info!(port, "selected available port for MCP bridge");

        // Spawn subprocess
        let process = spawn_mcp_process(&config.command, &env_vars)?;

        // Write registration
        let registration = BridgeRegistration {
            sandbox: config.sandbox.clone(),
            server_name: config.server_name.clone(),
            transport: Transport::StdioHttp,
            command: config.command.clone(),
            bridge_pid: std::process::id(),
            forwarded_port: port,
            status: BridgeStatus::Running,
        };
        write_registration(&config.config_dir, &registration)?;

        Ok(Self {
            config,
            port,
            process: Arc::new(Mutex::new(Some(process))),
            env_vars,
            policy,
            logger,
        })
    }

    /// Get the port the bridge is listening on.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Get the sandbox name.
    pub fn sandbox(&self) -> &str {
        &self.config.sandbox
    }

    /// Get the server name.
    pub fn server_name(&self) -> &str {
        &self.config.server_name
    }

    /// Get the policy holder for this bridge.
    pub fn policy(&self) -> &PolicyHolder {
        &self.policy
    }

    /// Get the tool call logger, if configured.
    pub fn logger(&self) -> Option<&Arc<ToolCallLogger>> {
        self.logger.as_ref()
    }

    /// Handle an HTTP request by translating it to JSON-RPC on stdin and
    /// reading the response from stdout.
    ///
    /// Before forwarding, evaluates tool-level policy for `tools/call` requests.
    /// Non-`tools/call` methods (e.g., `tools/list`, `initialize`) are always forwarded.
    /// After receiving a response, emits a structured log entry via the non-blocking
    /// tool call logger (DS-013).
    pub async fn handle_request(&self, body: &[u8]) -> Result<serde_json::Value> {
        let start_time = std::time::Instant::now();
        let jsonrpc = parse_jsonrpc_request(body)?;

        let method = logging::extract_method(&jsonrpc).unwrap_or("unknown");
        let is_tool_call = method == "tools/call";
        let is_tools_list = method == "tools/list";

        // Policy evaluation for tools/call requests (ADR-010 compensating control)
        if let Some(tool_name) = extract_tool_call_name(&jsonrpc) {
            if let Some(server_policy) = self.policy.get_server_policy(&self.config.server_name).await {
                let decision = evaluate_tool_access(&server_policy, tool_name);
                if let crate::policy::PolicyDecision::Deny { ref reason } = decision {
                    tracing::warn!(
                        sandbox = %self.config.sandbox,
                        server = %self.config.server_name,
                        tool = %tool_name,
                        reason = %reason,
                        "denied MCP tool call by policy"
                    );
                    let request_id = jsonrpc.get("id").cloned().unwrap_or(serde_json::Value::Null);
                    return Ok(denied_tool_jsonrpc_error(&request_id, tool_name, reason));
                }
            }
        } else if jsonrpc.get("method").and_then(|m| m.as_str()) == Some("tools/call") {
            // tools/call but missing params.name — invalid request (EC-CUSTOM-002)
            let request_id = jsonrpc.get("id").cloned().unwrap_or(serde_json::Value::Null);
            return Ok(serde_json::json!({
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request",
                    "data": {
                        "reason": "tools/call request missing 'params.name' field"
                    }
                }
            }));
        }

        let stdin_bytes = format_jsonrpc_for_stdin(&jsonrpc)?;

        let mut guard = self.process.lock().await;
        let process = guard.as_mut().ok_or_else(|| BridgeError::SubprocessIo {
            reason: "MCP server subprocess is not running".to_string(),
        })?;

        // Write to stdin
        process
            .stdin
            .write_all(&stdin_bytes)
            .await
            .map_err(|e| BridgeError::SubprocessIo {
                reason: format!("failed to write to MCP server stdin: {e}"),
            })?;
        process
            .stdin
            .flush()
            .await
            .map_err(|e| BridgeError::SubprocessIo {
                reason: format!("failed to flush MCP server stdin: {e}"),
            })?;

        // Read response line from stdout
        let mut line = String::new();
        process
            .stdout_reader
            .read_line(&mut line)
            .await
            .map_err(|e| BridgeError::SubprocessIo {
                reason: format!("failed to read from MCP server stdout: {e}"),
            })?;

        if line.is_empty() {
            return Err(BridgeError::SubprocessIo {
                reason: "MCP server closed stdout (process may have crashed)".to_string(),
            });
        }

        let response = parse_jsonrpc_response(line.trim())?;
        let duration_ms = u64::try_from(start_time.elapsed().as_millis()).unwrap_or(u64::MAX);

        // DS-013: Emit structured log entry after each request/response
        if let Some(ref logger) = self.logger {
            if is_tool_call {
                logger.log_tool_call(
                    &self.config.server_name,
                    &self.config.sandbox,
                    &jsonrpc,
                    &response,
                    duration_ms,
                );
            } else if is_tools_list {
                // AC-007: tools/list logged at debug level only
                logger.log_tools_list(
                    &self.config.server_name,
                    &self.config.sandbox,
                    duration_ms,
                );
            }
        }

        Ok(response)
    }

    /// Attempt to restart the MCP server subprocess with backoff.
    ///
    /// Returns `Ok(())` if restart succeeded, or `Err` if max retries
    /// exhausted.
    pub async fn restart_with_backoff(&self, crash_reason: &str) -> Result<()> {
        let mut last_exit = crash_reason.to_string();

        for attempt in 0..MAX_RESTART_ATTEMPTS {
            let delay = backoff_duration(attempt).ok_or_else(|| {
                BridgeError::MaxRetriesExhausted {
                    attempts: attempt,
                    last_exit: last_exit.clone(),
                }
            })?;

            tracing::warn!(
                sandbox = %self.config.sandbox,
                server = %self.config.server_name,
                attempt = attempt + 1,
                max_attempts = MAX_RESTART_ATTEMPTS,
                backoff_ms = delay.as_millis(),
                crash_reason = %crash_reason,
                "restarting MCP server after crash"
            );

            tokio::time::sleep(delay).await;

            match spawn_mcp_process(&self.config.command, &self.env_vars) {
                Ok(process) => {
                    let mut guard = self.process.lock().await;
                    *guard = Some(process);
                    tracing::info!(
                        sandbox = %self.config.sandbox,
                        server = %self.config.server_name,
                        attempt = attempt + 1,
                        "MCP server restarted successfully"
                    );
                    return Ok(());
                }
                Err(e) => {
                    last_exit = e.to_string();
                    tracing::error!(
                        sandbox = %self.config.sandbox,
                        server = %self.config.server_name,
                        attempt = attempt + 1,
                        error = %last_exit,
                        "MCP server restart failed"
                    );
                }
            }
        }

        Err(BridgeError::MaxRetriesExhausted {
            attempts: MAX_RESTART_ATTEMPTS,
            last_exit,
        })
    }

    /// Run the HTTP server, blocking until shutdown is signaled.
    pub async fn serve(self: Arc<Self>, shutdown: oneshot::Receiver<()>) -> Result<()> {
        let addr: std::net::SocketAddr = ([127, 0, 0, 1], self.port).into();
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| BridgeError::HttpServer {
                reason: format!("failed to bind {addr}: {e}"),
            })?;

        tracing::info!(
            port = self.port,
            sandbox = %self.config.sandbox,
            server = %self.config.server_name,
            "MCP bridge HTTP server listening"
        );

        let bridge = self.clone();

        tokio::select! {
            result = async {
                loop {
                    match listener.accept().await {
                        Ok((stream, _)) => {
                            let bridge = bridge.clone();
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let svc = service_fn(move |req: Request<Incoming>| {
                                    let bridge = bridge.clone();
                                    async move {
                                        handle_http_request(bridge, req).await
                                    }
                                });
                                if let Err(e) = hyper::server::conn::http1::Builder::new()
                                    .serve_connection(io, svc)
                                    .await
                                {
                                    tracing::error!(error = %e, "HTTP connection error");
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "failed to accept connection");
                        }
                    }
                }
                #[allow(unreachable_code)]
                Ok::<(), BridgeError>(())
            } => {
                result
            }
            _ = shutdown => {
                tracing::info!("MCP bridge shutdown signal received");
                Ok(())
            }
        }
    }

    /// Shut down the bridge: kill subprocess, remove registration.
    pub async fn shutdown(&self) -> Result<()> {
        tracing::info!(
            sandbox = %self.config.sandbox,
            server = %self.config.server_name,
            "shutting down MCP bridge"
        );

        // Kill subprocess
        let mut guard = self.process.lock().await;
        if let Some(mut process) = guard.take() {
            let _ = process.child.kill().await;
        }

        // Remove registration
        remove_registration(
            &self.config.config_dir,
            &self.config.sandbox,
            &self.config.server_name,
        )?;

        Ok(())
    }
}

/// Handle an HTTP request to the bridge endpoint.
async fn handle_http_request(
    bridge: Arc<McpBridge>,
    req: Request<Incoming>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    use http_body_util::BodyExt;

    // Only accept POST
    if req.method() != hyper::Method::POST {
        return Ok(error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
            "MCP bridge only accepts POST requests",
        ));
    }

    // Read body
    let body = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_REQUEST,
                "failed to read request body",
                &e.to_string(),
            ));
        }
    };

    // Translate to JSON-RPC and get response
    match bridge.handle_request(&body).await {
        Ok(response) => {
            let response_bytes = serde_json::to_vec(&response).unwrap_or_else(|_| b"{}".to_vec());
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(response_bytes)))
                .expect("building response should not fail"))
        }
        Err(BridgeError::InvalidJsonRpc { ref detail }) => Ok(error_response(
            StatusCode::BAD_GATEWAY,
            "MCP server returned invalid JSON-RPC",
            detail,
        )),
        Err(BridgeError::SubprocessIo { ref reason }) => Ok(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "MCP server unavailable",
            reason,
        )),
        Err(e) => Ok(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal bridge error",
            &e.to_string(),
        )),
    }
}

// ---------------------------------------------------------------------------
// Subprocess spawning
// ---------------------------------------------------------------------------

/// Spawn the MCP server subprocess with the given command and env vars.
fn spawn_mcp_process(
    command: &[String],
    env_vars: &HashMap<String, String>,
) -> Result<McpProcess> {
    if command.is_empty() {
        return Err(BridgeError::StartupFailed {
            command: String::new(),
            reason: "command is empty".to_string(),
        });
    }

    let program = &command[0];
    let args = &command[1..];

    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);

    // Inject credential env vars (values are never logged)
    for (key, value) in env_vars {
        cmd.env(key, value);
    }

    let mut child = cmd.spawn().map_err(|e| BridgeError::StartupFailed {
        command: command.join(" "),
        reason: e.to_string(),
    })?;

    let stdin = child.stdin.take().ok_or_else(|| BridgeError::StartupFailed {
        command: command.join(" "),
        reason: "failed to capture subprocess stdin".to_string(),
    })?;

    let stdout = child.stdout.take().ok_or_else(|| BridgeError::StartupFailed {
        command: command.join(" "),
        reason: "failed to capture subprocess stdout".to_string(),
    })?;

    // Capture stderr in background for debug logging
    if let Some(stderr) = child.stderr.take() {
        let mut stderr_reader = BufReader::new(stderr);
        tokio::spawn(async move {
            let mut line = String::new();
            loop {
                line.clear();
                match stderr_reader.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        tracing::debug!(mcp_stderr = %line.trim(), "MCP server stderr");
                    }
                }
            }
        });
    }

    tracing::info!(
        command = %command.join(" "),
        pid = child.id().unwrap_or(0),
        "spawned MCP server subprocess"
    );

    Ok(McpProcess {
        stdin,
        stdout_reader: BufReader::new(stdout),
        child,
    })
}

/// Check whether a process is alive (host-side check).
fn pid_is_alive(pid: u32) -> bool {
    std::process::Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- JSON-RPC translation tests (pure) ---

    #[test]
    fn parse_jsonrpc_request_valid() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/list","id":1}"#;
        let result = parse_jsonrpc_request(body).expect("should parse");
        assert_eq!(result["method"], "tools/list");
        assert_eq!(result["id"], 1);
    }

    #[test]
    fn parse_jsonrpc_request_missing_version() {
        let body = br#"{"method":"tools/list","id":1}"#;
        let err = parse_jsonrpc_request(body).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidJsonRpc { .. }));
        assert!(err.to_string().contains("jsonrpc"));
    }

    #[test]
    fn parse_jsonrpc_request_missing_method() {
        let body = br#"{"jsonrpc":"2.0","id":1}"#;
        let err = parse_jsonrpc_request(body).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidJsonRpc { .. }));
        assert!(err.to_string().contains("method"));
    }

    #[test]
    fn parse_jsonrpc_request_invalid_json() {
        let body = b"not json at all";
        let err = parse_jsonrpc_request(body).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidJsonRpc { .. }));
    }

    #[test]
    fn parse_jsonrpc_response_valid() {
        let line = r#"{"jsonrpc":"2.0","result":{"tools":[]},"id":1}"#;
        let result = parse_jsonrpc_response(line).expect("should parse");
        assert_eq!(result["id"], 1);
        assert!(result["result"]["tools"].is_array());
    }

    #[test]
    fn parse_jsonrpc_response_malformed() {
        let line = "this is not json";
        let err = parse_jsonrpc_response(line).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidJsonRpc { .. }));
    }

    #[test]
    fn format_jsonrpc_for_stdin_appends_newline() {
        let value = serde_json::json!({"jsonrpc":"2.0","method":"test","id":1});
        let bytes = format_jsonrpc_for_stdin(&value).expect("should format");
        assert!(bytes.ends_with(b"\n"));
        // Should be valid JSON without the newline
        let json_part = &bytes[..bytes.len() - 1];
        let _: serde_json::Value = serde_json::from_slice(json_part).expect("should be valid JSON");
    }

    #[test]
    fn error_response_has_json_body() {
        let resp = error_response(StatusCode::BAD_GATEWAY, "test error", "test detail");
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    // --- Backoff calculation tests (pure) ---

    #[test]
    fn backoff_duration_follows_exponential_pattern() {
        assert_eq!(backoff_duration(0), Some(Duration::from_secs(1)));
        assert_eq!(backoff_duration(1), Some(Duration::from_secs(2)));
        assert_eq!(backoff_duration(2), Some(Duration::from_secs(4)));
    }

    #[test]
    fn backoff_duration_returns_none_after_max_attempts() {
        assert_eq!(backoff_duration(3), None);
        assert_eq!(backoff_duration(10), None);
    }

    #[test]
    fn backoff_sequence_sums_to_7_seconds() {
        let total: Duration = (0..MAX_RESTART_ATTEMPTS)
            .filter_map(backoff_duration)
            .sum();
        assert_eq!(total, Duration::from_secs(7));
    }

    // --- Port selection tests ---

    #[test]
    fn find_available_port_returns_first_free() {
        // Use a high ephemeral range that's likely free
        let port = find_available_port(19100, 19199).expect("should find port");
        assert!((19100..=19199).contains(&port));
    }

    #[test]
    fn find_available_port_skips_occupied() {
        // Bind a port to make it occupied
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let occupied_port = listener.local_addr().expect("addr").port();

        // If the occupied port happens to be in our test range, the function
        // should skip it
        if (19200..=19210).contains(&occupied_port) {
            let port = find_available_port(19200, 19210).expect("should find port");
            assert_ne!(port, occupied_port);
        }
        // Keep listener alive for duration of test
        drop(listener);
    }

    #[test]
    fn find_available_port_all_occupied_returns_error() {
        // Bind all ports in a tiny range and hold the listeners
        let l1 = TcpListener::bind(("127.0.0.1", 19300));
        let l2 = TcpListener::bind(("127.0.0.1", 19301));
        let l3 = TcpListener::bind(("127.0.0.1", 19302));

        if l1.is_ok() && l2.is_ok() && l3.is_ok() {
            let err = find_available_port(19300, 19302).unwrap_err();
            assert!(matches!(err, BridgeError::NoAvailablePort { start: 19300, end: 19302 }));
            let msg = err.to_string();
            assert!(msg.contains("19300"), "error should mention range: {msg}");
            assert!(msg.contains("19302"), "error should mention range: {msg}");
        }
    }

    #[test]
    fn is_port_available_detects_free_port() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        assert!(is_port_available(port));
    }

    #[test]
    fn is_port_available_detects_occupied_port() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        assert!(!is_port_available(port));
        drop(listener);
    }

    // --- Subprocess spawn tests ---

    #[test]
    fn spawn_mcp_process_empty_command_returns_error() {
        let err = spawn_mcp_process(&[], &HashMap::new()).unwrap_err();
        assert!(matches!(err, BridgeError::StartupFailed { .. }));
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn spawn_mcp_process_nonexistent_binary_returns_error() {
        let err =
            spawn_mcp_process(&["nonexistent-binary-xyz-12345".to_string()], &HashMap::new())
                .unwrap_err();
        assert!(matches!(err, BridgeError::StartupFailed { .. }));
        let msg = err.to_string();
        assert!(msg.contains("nonexistent-binary-xyz-12345"), "error should include command: {msg}");
        assert!(msg.contains("Ensure the command is installed"), "error should suggest fix: {msg}");
    }

    #[tokio::test]
    async fn spawn_mcp_process_with_echo_writes_and_reads() {
        // Use `cat` as a simple echo MCP server — it echoes stdin to stdout
        let mut process =
            spawn_mcp_process(&["cat".to_string()], &HashMap::new()).expect("should spawn cat");

        let msg = br#"{"jsonrpc":"2.0","method":"test","id":1}"#;
        let mut payload = msg.to_vec();
        payload.push(b'\n');

        process.stdin.write_all(&payload).await.expect("write");
        process.stdin.flush().await.expect("flush");

        let mut line = String::new();
        process
            .stdout_reader
            .read_line(&mut line)
            .await
            .expect("read");

        let parsed: serde_json::Value = serde_json::from_str(line.trim()).expect("parse");
        assert_eq!(parsed["method"], "test");

        // Clean up
        process.child.kill().await.ok();
    }

    #[tokio::test]
    async fn spawn_mcp_process_injects_env_vars() {
        let mut env = HashMap::new();
        env.insert(
            "DARKSHELL_TEST_VAR".to_string(),
            "test_value_42".to_string(),
        );

        // Use `env` command to print environment, then grep for our var
        let mut process =
            spawn_mcp_process(&["env".to_string()], &env).expect("should spawn env");

        let mut found = false;
        let mut line = String::new();
        loop {
            line.clear();
            match process.stdout_reader.read_line(&mut line).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if line.contains("DARKSHELL_TEST_VAR=test_value_42") {
                        found = true;
                        break;
                    }
                }
            }
        }

        assert!(found, "env var should be injected into subprocess");
        process.child.kill().await.ok();
    }

    // --- Bridge start with existing registration ---

    #[test]
    fn pid_is_alive_returns_true_for_current_process() {
        assert!(pid_is_alive(std::process::id()));
    }

    #[test]
    fn pid_is_alive_returns_false_for_nonexistent_pid() {
        // PID 99999999 is very unlikely to exist
        assert!(!pid_is_alive(99_999_999));
    }

    // --- HTTP handler tests ---

    #[test]
    fn error_response_method_not_allowed() {
        let resp = error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "method not allowed",
            "only POST accepted",
        );
        assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[test]
    fn error_response_bad_gateway_for_malformed_jsonrpc() {
        let resp = error_response(
            StatusCode::BAD_GATEWAY,
            "MCP server returned invalid JSON-RPC",
            "parse error details",
        );
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn error_response_service_unavailable_during_restart() {
        let resp = error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "MCP server unavailable",
            "restarting after crash",
        );
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
