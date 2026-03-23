//! End-to-end validation workflow tests: parse YAML -> validate -> collect errors/warnings.

use darkshell_blueprint::{parse_blueprint, validate, ParseError, MAX_BLUEPRINT_SIZE};

#[test]
fn test_valid_factory_blueprint() {
    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: factory-sandbox
  description: Full factory blueprint for integration testing
spec:
  image: ghcr.io/org/factory:latest
  policy: policies/default.yaml
  providers:
    - github
    - docker
  mcp_servers:
    - name: tally
      transport: bridge
      command: mcp-tally
      env:
        - GITHUB_TOKEN
    - name: local-tools
      transport: in-sandbox
      command: /usr/local/bin/mcp-tools
    - name: remote-api
      transport: streamable-http
      url: https://api.example.com/mcp
  forwards:
    - "8080"
    - "127.0.0.1:3000"
  resources:
    cpu: "2"
    memory: 4Gi
  upload:
    - src:/workspace/src
    - config.yaml:/workspace/config.yaml
"#;

    let blueprint = parse_blueprint(yaml).expect("should parse valid YAML");
    let result = validate(&blueprint);

    assert!(
        result.errors.is_empty(),
        "valid factory blueprint should have no errors, got: {:?}",
        result.errors
    );
}

#[test]
fn test_missing_image_reports_error() {
    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: no-image
spec:
  providers:
    - github
"#;

    let blueprint = parse_blueprint(yaml).expect("should parse");
    let result = validate(&blueprint);

    assert!(
        !result.errors.is_empty(),
        "missing image should produce at least one error"
    );
    let image_err = result
        .errors
        .iter()
        .find(|e| e.field.contains("image"))
        .expect("should have an error mentioning 'image'");
    assert!(
        image_err.field.contains("spec.image"),
        "error field path should contain 'spec.image', got: {}",
        image_err.field
    );
}

#[test]
fn test_invalid_mcp_transport_reports_error() {
    // Bridge transport without command field.
    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: bad-mcp
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: no-command-bridge
      transport: bridge
"#;

    let blueprint = parse_blueprint(yaml).expect("should parse");
    let result = validate(&blueprint);

    let cmd_err = result
        .errors
        .iter()
        .find(|e| e.field.contains("command"))
        .expect("bridge without command should produce command error");
    assert!(
        cmd_err.message.contains("command"),
        "error message should mention 'command', got: {}",
        cmd_err.message
    );
}

#[test]
fn test_path_traversal_rejected() {
    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: path-traversal
spec:
  image: ubuntu:22.04
  upload:
    - "../../etc/passwd:/workspace/stolen"
"#;

    let blueprint = parse_blueprint(yaml).expect("should parse");
    let result = validate(&blueprint);

    let traversal_err = result
        .errors
        .iter()
        .find(|e| e.field.contains("upload") && e.message.contains(".."))
        .expect("path traversal should produce an error mentioning '..'");
    assert!(
        traversal_err.message.to_lowercase().contains("traversal"),
        "error should mention path traversal, got: {}",
        traversal_err.message
    );
}

#[test]
fn test_shell_metachar_in_command_warns() {
    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: shell-metachar
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: dangerous
      transport: bridge
      command: "echo hello; rm -rf /"
"#;

    let blueprint = parse_blueprint(yaml).expect("should parse");
    let result = validate(&blueprint);

    let metachar_warning = result
        .warnings
        .iter()
        .find(|w| w.field.contains("command") && w.message.contains("metacharacter"))
        .expect("shell metacharacters should produce a warning");
    assert!(
        metachar_warning.message.contains("shell"),
        "warning should mention shell, got: {}",
        metachar_warning.message
    );

    // It should be a warning, not an error (the command is still valid).
    assert!(
        !result.errors.iter().any(|e| e.field.contains("command")
            && e.message.to_lowercase().contains("metacharacter")),
        "shell metacharacters should be a warning, not an error"
    );
}

#[test]
fn test_unknown_fields_produce_warnings() {
    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: extra-fields
spec:
  image: ubuntu:22.04
  foo: bar
"#;

    let blueprint = parse_blueprint(yaml).expect("should parse with unknown fields");
    let result = validate(&blueprint);

    // Should parse OK (no errors about the unknown field).
    let non_unknown_errors: Vec<_> = result
        .errors
        .iter()
        .filter(|e| e.field.contains("foo"))
        .collect();
    assert!(
        non_unknown_errors.is_empty(),
        "unknown fields should not produce errors, got: {non_unknown_errors:?}"
    );

    // Should produce a warning about the unknown field.
    let unknown_warning = result
        .warnings
        .iter()
        .find(|w| w.field.contains("foo") || w.message.contains("foo"));
    assert!(
        unknown_warning.is_some(),
        "unknown field 'foo' should produce a warning. Warnings: {:?}",
        result.warnings
    );
}

#[test]
fn test_blueprint_size_limit() {
    // Create a YAML string larger than MAX_BLUEPRINT_SIZE.
    let oversized = "a".repeat(MAX_BLUEPRINT_SIZE + 1);
    let err = parse_blueprint(&oversized).unwrap_err();

    assert!(
        matches!(err, ParseError::InputTooLarge { .. }),
        "oversized input should produce InputTooLarge, got: {err}"
    );
}

#[test]
fn test_multiple_errors_collected() {
    // Blueprint with three distinct problems:
    // 1. Missing apiVersion
    // 2. Missing image
    // 3. Upload with path traversal
    let yaml = r#"
kind: Blueprint
metadata:
  name: multi-error
spec:
  providers:
    - github
  upload:
    - "../../etc/shadow:/workspace/shadow"
"#;

    let blueprint = parse_blueprint(yaml).expect("should parse");
    let result = validate(&blueprint);

    // Should have at least 3 errors (apiVersion missing, image missing, path traversal).
    assert!(
        result.errors.len() >= 3,
        "should collect at least 3 errors (not fail-fast), got {} error(s): {:?}",
        result.errors.len(),
        result.errors
    );

    // Verify each specific error is present.
    assert!(
        result.errors.iter().any(|e| e.field.contains("apiVersion")),
        "should report missing apiVersion"
    );
    assert!(
        result.errors.iter().any(|e| e.field.contains("image")),
        "should report missing image"
    );
    assert!(
        result.errors.iter().any(|e| e.field.contains("upload")),
        "should report upload path traversal"
    );
}
