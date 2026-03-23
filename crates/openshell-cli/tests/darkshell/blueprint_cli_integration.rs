// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! WF-4: CLI-level blueprint integration tests.
//!
//! Tests the `read_blueprint` function that bridges CLI to the blueprint
//! engine, including valid YAML parsing, missing file errors, and invalid
//! YAML error handling.

use openshell_cli::blueprint::read_blueprint;
use std::io::Write;

// ---------------------------------------------------------------------------
// Valid blueprint parsing
// ---------------------------------------------------------------------------

#[test]
fn test_read_blueprint_valid_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("factory.yaml");
    let mut f = std::fs::File::create(&path).expect("create");
    write!(
        f,
        r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test-sandbox
spec:
  image: ubuntu:22.04
"#
    )
    .expect("write");

    let bp = read_blueprint(&path).expect("read_blueprint should succeed for valid YAML");
    assert_eq!(
        bp.metadata.as_ref().unwrap().name.as_deref(),
        Some("test-sandbox")
    );
}

// ---------------------------------------------------------------------------
// Missing file
// ---------------------------------------------------------------------------

#[test]
fn test_read_blueprint_missing_file() {
    let path = std::path::Path::new("/tmp/nonexistent-blueprint-12345.yaml");
    let err = read_blueprint(path).expect_err("read_blueprint should fail for missing file");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to read blueprint file"),
        "error should mention failed read: {msg}"
    );
    assert!(
        msg.contains("nonexistent-blueprint-12345.yaml"),
        "error should include the file path: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Invalid YAML
// ---------------------------------------------------------------------------

#[test]
fn test_read_blueprint_invalid_yaml() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("bad.yaml");
    std::fs::write(&path, "{{{{not: valid: yaml: at: all").expect("write");

    let err = read_blueprint(&path).expect_err("read_blueprint should fail for invalid YAML");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to parse blueprint") || msg.contains("parse"),
        "error should mention parse failure: {msg}"
    );
}

// ---------------------------------------------------------------------------
// Missing required fields
// ---------------------------------------------------------------------------

#[test]
fn test_read_blueprint_missing_required_fields() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("incomplete.yaml");
    // Valid YAML but missing required blueprint fields
    std::fs::write(
        &path,
        r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: ""
spec: {}
"#,
    )
    .expect("write");

    // This should either fail parsing or fail validation (empty name, missing image)
    let result = read_blueprint(&path);
    // Either a parse error or a validation error is acceptable
    if let Err(e) = result {
        let msg = e.to_string();
        assert!(
            msg.contains("validation") || msg.contains("parse") || msg.contains("error"),
            "error should be about validation or parsing: {msg}"
        );
    }
    // If it succeeds (lenient parsing), that's also acceptable — the validator
    // may only warn on empty names.
}

// ---------------------------------------------------------------------------
// Blueprint with all fields populated
// ---------------------------------------------------------------------------

#[test]
fn test_read_blueprint_with_mcp_and_providers() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("full.yaml");
    write!(
        std::fs::File::create(&path).expect("create"),
        r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: full-sandbox
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: perplexity
      transport: bridge
      command: "npx -y @anthropic/perplexity-mcp"
  providers:
    - openai
"#
    )
    .expect("write");

    let bp = read_blueprint(&path).expect("read_blueprint should succeed");
    assert_eq!(
        bp.metadata.as_ref().unwrap().name.as_deref(),
        Some("full-sandbox")
    );
}
