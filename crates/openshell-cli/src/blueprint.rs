// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI handler for `darkshell sandbox create --from-blueprint <file>`.
//!
//! Parses a blueprint YAML file and delegates to the blueprint orchestrator
//! for full sandbox creation. This module is the effectful-shell that bridges
//! the CLI layer to the blueprint engine.

use std::path::Path;

/// Read and parse a blueprint YAML file from disk.
///
/// # Errors
///
/// Returns a user-friendly error if the file cannot be read or parsed.
pub fn read_blueprint(path: &Path) -> miette::Result<darkshell_blueprint::Blueprint> {
    let yaml = std::fs::read_to_string(path).map_err(|e| {
        miette::miette!(
            "Failed to read blueprint file '{}': {e}. \
             Check that the file exists and is readable.",
            path.display()
        )
    })?;

    let blueprint = darkshell_blueprint::parse_blueprint(&yaml)
        .map_err(|e| miette::miette!("Failed to parse blueprint '{}': {e}", path.display()))?;

    // Run schema validation and report all errors at once.
    let validation = darkshell_blueprint::validate(&blueprint);

    for warning in &validation.warnings {
        eprintln!(
            "{} {}: {}",
            owo_colors::OwoColorize::yellow(&"!"),
            warning.field,
            warning.message
        );
    }

    if !validation.errors.is_empty() {
        let mut msg = format!(
            "Blueprint '{}' has {} validation error(s):\n",
            path.display(),
            validation.errors.len()
        );
        for err in &validation.errors {
            msg.push_str(&format!("  - {err}\n"));
        }
        return Err(miette::miette!("{msg}"));
    }

    Ok(blueprint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn read_blueprint_from_valid_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blueprint.yaml");
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

        let result = read_blueprint(&path);
        assert!(result.is_ok(), "should parse valid blueprint: {result:?}");
    }

    #[test]
    fn read_blueprint_nonexistent_file() {
        let result = read_blueprint(Path::new("/nonexistent/blueprint.yaml"));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Failed to read"),
            "should report read failure: {msg}"
        );
    }

    #[test]
    fn read_blueprint_invalid_yaml() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.yaml");
        std::fs::write(&path, "not: [valid: yaml: {{{").expect("write");

        let result = read_blueprint(&path);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Failed to parse"),
            "should report parse failure: {msg}"
        );
    }

    #[test]
    fn read_blueprint_validation_errors_reported() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("invalid.yaml");
        // Missing apiVersion, kind, spec.image.
        std::fs::write(
            &path,
            r#"
metadata:
  name: broken
spec:
  providers:
    - github
"#,
        )
        .expect("write");

        let result = read_blueprint(&path);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("validation error"),
            "should report validation errors: {msg}"
        );
    }
}
