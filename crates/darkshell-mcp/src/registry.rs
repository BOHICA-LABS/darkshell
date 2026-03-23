// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! MCP server registration file management.
//!
//! Each running MCP bridge writes a YAML registration file at
//! `~/.config/darkshell/mcp/<sandbox>-<server>.yaml` containing bridge state.
//! The registry provides CRUD operations for these files.

use crate::error::{BridgeError, Result};
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Name validation (MCP-F007: path injection prevention)
// ---------------------------------------------------------------------------

/// Validate that a sandbox or server name contains only safe characters.
///
/// Allowed: lowercase letters, digits, and hyphens (`[a-z0-9-]`).
/// Rejects: `/`, `..`, null bytes, uppercase, underscores, spaces, etc.
///
/// This prevents path injection attacks where a malicious name like
/// `../../etc/passwd` could write registration files outside the registry dir.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(BridgeError::RegistrationIo {
            reason: "name must not be empty".to_string(),
        });
    }

    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
        return Err(BridgeError::RegistrationIo {
            reason: format!(
                "name '{name}' contains invalid characters. \
                 Only lowercase letters, digits, and hyphens [a-z0-9-] are allowed"
            ),
        });
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Registration data types (pure-core — no I/O)
// ---------------------------------------------------------------------------

/// Transport mode for the MCP bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum Transport {
    /// stdio JSON-RPC to HTTP proxy (the primary mode).
    #[serde(rename = "stdio-http")]
    StdioHttp,
}

/// Bridge lifecycle status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum BridgeStatus {
    /// Bridge is starting up (subprocess not yet ready).
    #[serde(rename = "starting")]
    Starting,
    /// Bridge is running and accepting requests.
    #[serde(rename = "running")]
    Running,
    /// Bridge is shutting down.
    #[serde(rename = "stopping")]
    Stopping,
    /// Bridge has stopped (registration file may be stale).
    #[serde(rename = "stopped")]
    Stopped,
    /// Bridge has failed after max retries.
    #[serde(rename = "failed")]
    Failed,
}

/// Registration file contents — serialized to/from YAML.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BridgeRegistration {
    /// Sandbox this bridge serves.
    pub sandbox: String,
    /// MCP server name (e.g., "perplexity", "tavily").
    pub server_name: String,
    /// Transport mode.
    pub transport: Transport,
    /// Command used to start the MCP server.
    pub command: Vec<String>,
    /// Bridge daemon PID on the host.
    pub bridge_pid: u32,
    /// Port the HTTP bridge listens on.
    pub forwarded_port: u16,
    /// Current bridge status.
    pub status: BridgeStatus,
    /// Process start time in seconds since UNIX epoch.
    ///
    /// Used alongside `bridge_pid` to detect PID reuse: if the PID is alive
    /// but was started at a different time, the registration is stale.
    #[serde(default)]
    pub process_start_time: Option<u64>,
}

// ---------------------------------------------------------------------------
// Registry operations (effectful-shell — file I/O)
// ---------------------------------------------------------------------------

/// Base directory for MCP registration files.
///
/// Defaults to `~/.config/darkshell/mcp/`. Uses `config_dir` parameter
/// to allow testing with temp directories.
pub fn registry_dir(config_dir: &Path) -> PathBuf {
    config_dir.join("darkshell").join("mcp")
}

/// Default config directory (the user's `~/.config`).
pub fn default_config_dir() -> Result<PathBuf> {
    dirs_or_home().map(|p| p.join(".config"))
}

/// Get the user's home directory, or fall back to current dir.
fn dirs_or_home() -> Result<PathBuf> {
    std::env::var("HOME")
        .map(PathBuf::from)
        .map_err(|_| BridgeError::RegistrationIo {
            reason: "HOME environment variable not set".to_string(),
        })
}

/// Registration file path for a sandbox+server pair.
///
/// Validates that sandbox and server names contain only `[a-z0-9-]` to
/// prevent path injection (MCP-F007).
pub fn registration_path(config_dir: &Path, sandbox: &str, server: &str) -> Result<PathBuf> {
    validate_name(sandbox)?;
    validate_name(server)?;
    Ok(registry_dir(config_dir).join(format!("{sandbox}-{server}.yaml")))
}

/// Write a registration file for a bridge.
///
/// Uses atomic write (write to temp file, then rename) to prevent partial
/// reads by concurrent processes.
pub fn write_registration(
    config_dir: &Path,
    registration: &BridgeRegistration,
) -> Result<()> {
    let dir = registry_dir(config_dir);
    std::fs::create_dir_all(&dir).map_err(|e| BridgeError::RegistrationIo {
        reason: format!("failed to create directory {}: {e}", dir.display()),
    })?;

    let path = registration_path(
        config_dir,
        &registration.sandbox,
        &registration.server_name,
    )?;

    let yaml = serde_yaml::to_string(registration).map_err(|e| BridgeError::RegistrationIo {
        reason: format!("failed to serialize registration: {e}"),
    })?;

    // Atomic write: write to temp file in same directory, then rename.
    // rename() is atomic on POSIX when src and dst are on the same filesystem.
    let tmp_path = path.with_extension("yaml.tmp");
    std::fs::write(&tmp_path, &yaml).map_err(|e| BridgeError::RegistrationIo {
        reason: format!("failed to write temp file {}: {e}", tmp_path.display()),
    })?;

    std::fs::rename(&tmp_path, &path).map_err(|e| {
        // Clean up temp file on rename failure
        let _ = std::fs::remove_file(&tmp_path);
        BridgeError::RegistrationIo {
            reason: format!("failed to rename {} -> {}: {e}", tmp_path.display(), path.display()),
        }
    })?;

    tracing::info!(
        sandbox = %registration.sandbox,
        server = %registration.server_name,
        port = registration.forwarded_port,
        pid = registration.bridge_pid,
        path = %path.display(),
        "wrote registration file"
    );

    Ok(())
}

/// Read a registration file for a sandbox+server pair.
pub fn read_registration(
    config_dir: &Path,
    sandbox: &str,
    server: &str,
) -> Result<Option<BridgeRegistration>> {
    let path = registration_path(config_dir, sandbox, server)?;

    match std::fs::read_to_string(&path) {
        Ok(contents) => {
            let reg: BridgeRegistration =
                serde_yaml::from_str(&contents).map_err(|e| BridgeError::RegistrationIo {
                    reason: format!("failed to parse {}: {e}", path.display()),
                })?;
            Ok(Some(reg))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(BridgeError::RegistrationIo {
            reason: format!("failed to read {}: {e}", path.display()),
        }),
    }
}

/// Remove a registration file for a sandbox+server pair.
///
/// Returns `true` if the file existed and was removed, `false` if it
/// did not exist.
pub fn remove_registration(
    config_dir: &Path,
    sandbox: &str,
    server: &str,
) -> Result<bool> {
    let path = registration_path(config_dir, sandbox, server)?;

    match std::fs::remove_file(&path) {
        Ok(()) => {
            tracing::info!(
                sandbox = %sandbox,
                server = %server,
                path = %path.display(),
                "removed registration file"
            );
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(BridgeError::RegistrationIo {
            reason: format!("failed to remove {}: {e}", path.display()),
        }),
    }
}

/// List all registrations in the registry directory.
pub fn list_registrations(config_dir: &Path) -> Result<Vec<BridgeRegistration>> {
    let dir = registry_dir(config_dir);
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => {
            return Err(BridgeError::RegistrationIo {
                reason: format!("failed to read directory {}: {e}", dir.display()),
            });
        }
    };

    let mut registrations = Vec::new();
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    dir = %dir.display(),
                    error = %e,
                    "skipping unreadable directory entry in registry"
                );
                continue;
            }
        };
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(contents) => match serde_yaml::from_str::<BridgeRegistration>(&contents) {
                Ok(reg) => registrations.push(reg),
                Err(e) => {
                    tracing::warn!(
                        path = %path.display(),
                        error = %e,
                        "skipping malformed registration file"
                    );
                }
            },
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "skipping unreadable registration file"
                );
            }
        }
    }

    registrations.sort_by(|a, b| {
        a.sandbox
            .cmp(&b.sandbox)
            .then(a.server_name.cmp(&b.server_name))
    });

    Ok(registrations)
}

/// Remove all registrations for a sandbox.
///
/// Returns the list of server names that were removed.
pub fn cleanup_sandbox(config_dir: &Path, sandbox: &str) -> Result<Vec<String>> {
    let registrations = list_registrations(config_dir)?;
    let mut removed = Vec::new();

    for reg in &registrations {
        if reg.sandbox == sandbox {
            remove_registration(config_dir, &reg.sandbox, &reg.server_name)?;
            removed.push(reg.server_name.clone());
        }
    }

    if !removed.is_empty() {
        tracing::info!(
            sandbox = %sandbox,
            count = removed.len(),
            servers = ?removed,
            "cleaned up sandbox registrations"
        );
    }

    Ok(removed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registration(sandbox: &str, server: &str, port: u16) -> BridgeRegistration {
        BridgeRegistration {
            sandbox: sandbox.to_string(),
            server_name: server.to_string(),
            transport: Transport::StdioHttp,
            command: vec!["npx".to_string(), "-y".to_string(), format!("@test/{server}")],
            bridge_pid: std::process::id(),
            forwarded_port: port,
            status: BridgeStatus::Running,
            process_start_time: Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time")
                    .as_secs(),
            ),
        }
    }

    #[test]
    fn registration_roundtrip_yaml() {
        let reg = test_registration("dev", "perplexity", 9100);
        let yaml = serde_yaml::to_string(&reg).expect("serialize");
        let parsed: BridgeRegistration = serde_yaml::from_str(&yaml).expect("deserialize");

        assert_eq!(parsed.sandbox, "dev");
        assert_eq!(parsed.server_name, "perplexity");
        assert_eq!(parsed.transport, Transport::StdioHttp);
        assert_eq!(parsed.forwarded_port, 9100);
        assert_eq!(parsed.status, BridgeStatus::Running);
        assert_eq!(parsed.command, vec!["npx", "-y", "@test/perplexity"]);
        assert!(parsed.process_start_time.is_some());
    }

    #[test]
    fn write_and_read_registration() {
        let dir = tempfile::tempdir().expect("tempdir");
        let config_dir = dir.path();
        let reg = test_registration("dev", "perplexity", 9100);

        write_registration(config_dir, &reg).expect("write");

        let read_back = read_registration(config_dir, "dev", "perplexity")
            .expect("read")
            .expect("should exist");

        assert_eq!(read_back.sandbox, "dev");
        assert_eq!(read_back.server_name, "perplexity");
        assert_eq!(read_back.forwarded_port, 9100);
    }

    #[test]
    fn read_nonexistent_registration_returns_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = read_registration(dir.path(), "dev", "nonexistent").expect("read");
        assert!(result.is_none());
    }

    #[test]
    fn remove_registration_returns_true_when_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let reg = test_registration("dev", "perplexity", 9100);
        write_registration(dir.path(), &reg).expect("write");

        let removed = remove_registration(dir.path(), "dev", "perplexity").expect("remove");
        assert!(removed);

        // Verify it's gone
        let after = read_registration(dir.path(), "dev", "perplexity").expect("read");
        assert!(after.is_none());
    }

    #[test]
    fn remove_registration_returns_false_when_not_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let removed = remove_registration(dir.path(), "dev", "nonexistent").expect("remove");
        assert!(!removed);
    }

    #[test]
    fn list_registrations_returns_all_sorted() {
        let dir = tempfile::tempdir().expect("tempdir");

        write_registration(dir.path(), &test_registration("dev", "tavily", 9101)).expect("write");
        write_registration(dir.path(), &test_registration("dev", "perplexity", 9100))
            .expect("write");
        write_registration(dir.path(), &test_registration("staging", "github", 9102))
            .expect("write");

        let list = list_registrations(dir.path()).expect("list");
        assert_eq!(list.len(), 3);
        // Sorted by sandbox then server_name
        assert_eq!(list[0].server_name, "perplexity");
        assert_eq!(list[1].server_name, "tavily");
        assert_eq!(list[2].server_name, "github");
    }

    #[test]
    fn list_registrations_empty_dir_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let list = list_registrations(dir.path()).expect("list");
        assert!(list.is_empty());
    }

    #[test]
    fn list_registrations_nonexistent_dir_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent = dir.path().join("does-not-exist");
        let list = list_registrations(&nonexistent).expect("list");
        assert!(list.is_empty());
    }

    #[test]
    fn cleanup_sandbox_removes_all_for_sandbox() {
        let dir = tempfile::tempdir().expect("tempdir");

        write_registration(dir.path(), &test_registration("dev", "perplexity", 9100))
            .expect("write");
        write_registration(dir.path(), &test_registration("dev", "tavily", 9101)).expect("write");
        write_registration(dir.path(), &test_registration("staging", "github", 9102))
            .expect("write");

        let removed = cleanup_sandbox(dir.path(), "dev").expect("cleanup");
        assert_eq!(removed.len(), 2);
        assert!(removed.contains(&"perplexity".to_string()));
        assert!(removed.contains(&"tavily".to_string()));

        // staging should remain
        let remaining = list_registrations(dir.path()).expect("list");
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].sandbox, "staging");
    }

    #[test]
    fn cleanup_sandbox_no_matches_returns_empty() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_registration(dir.path(), &test_registration("dev", "perplexity", 9100))
            .expect("write");

        let removed = cleanup_sandbox(dir.path(), "nonexistent").expect("cleanup");
        assert!(removed.is_empty());
    }

    #[test]
    fn registration_path_format() {
        let config_dir = Path::new("/tmp/test-config");
        let path = registration_path(config_dir, "dev", "perplexity").expect("valid names");
        assert_eq!(
            path,
            PathBuf::from("/tmp/test-config/darkshell/mcp/dev-perplexity.yaml")
        );
    }

    // --- MCP-F007: Name validation tests ---

    #[test]
    fn validate_name_accepts_lowercase_alphanumeric_and_hyphens() {
        assert!(validate_name("dev").is_ok());
        assert!(validate_name("my-sandbox-1").is_ok());
        assert!(validate_name("abc123").is_ok());
        assert!(validate_name("a").is_ok());
    }

    #[test]
    fn validate_name_rejects_empty() {
        assert!(validate_name("").is_err());
    }

    #[test]
    fn validate_name_rejects_path_traversal() {
        assert!(validate_name("../etc/passwd").is_err());
        assert!(validate_name("foo/bar").is_err());
    }

    #[test]
    fn validate_name_rejects_null_bytes() {
        assert!(validate_name("foo\0bar").is_err());
    }

    #[test]
    fn validate_name_rejects_uppercase() {
        assert!(validate_name("Dev").is_err());
        assert!(validate_name("SANDBOX").is_err());
    }

    #[test]
    fn validate_name_rejects_special_characters() {
        assert!(validate_name("my_sandbox").is_err());
        assert!(validate_name("my sandbox").is_err());
        assert!(validate_name("foo.bar").is_err());
    }

    #[test]
    fn registration_path_rejects_invalid_names() {
        let config_dir = Path::new("/tmp/test-config");
        assert!(registration_path(config_dir, "../etc", "passwd").is_err());
        assert!(registration_path(config_dir, "dev", "foo/bar").is_err());
        assert!(registration_path(config_dir, "dev", "").is_err());
    }

    #[test]
    fn bridge_status_serializes_correctly() {
        let reg = test_registration("dev", "test", 9100);
        let yaml = serde_yaml::to_string(&reg).expect("serialize");
        assert!(yaml.contains("running"), "status should serialize as 'running': {yaml}");
    }

    #[test]
    fn transport_serializes_correctly() {
        let reg = test_registration("dev", "test", 9100);
        let yaml = serde_yaml::to_string(&reg).expect("serialize");
        assert!(
            yaml.contains("stdio-http"),
            "transport should serialize as 'stdio-http': {yaml}"
        );
    }

    #[test]
    fn multiple_servers_per_sandbox_have_separate_files() {
        let dir = tempfile::tempdir().expect("tempdir");

        let reg1 = test_registration("dev", "perplexity", 9100);
        let reg2 = test_registration("dev", "tavily", 9101);

        write_registration(dir.path(), &reg1).expect("write 1");
        write_registration(dir.path(), &reg2).expect("write 2");

        let r1 = read_registration(dir.path(), "dev", "perplexity")
            .expect("read")
            .expect("should exist");
        let r2 = read_registration(dir.path(), "dev", "tavily")
            .expect("read")
            .expect("should exist");

        assert_eq!(r1.forwarded_port, 9100);
        assert_eq!(r2.forwarded_port, 9101);
    }
}
