//! Blueprint YAML schema types and validation logic.
//!
//! All types in this module are pure-core: no IO, no async, no side effects.
//! Validation is a pure function that takes a `&Blueprint` and returns a
//! `ValidationResult` containing collected errors and warnings.

use std::collections::HashMap;

use serde::Deserialize;
use thiserror::Error;

// ---------------------------------------------------------------------------
// Schema types
// ---------------------------------------------------------------------------

/// A lenient blueprint that captures unknown fields as warnings instead of
/// rejecting them. This is the primary parse target for forward compatibility.
#[derive(Debug, Clone, Deserialize)]
pub struct Blueprint {
    /// Must be `darkshell/v1`.
    #[serde(rename = "apiVersion")]
    pub api_version: Option<String>,

    /// Must be `Blueprint`.
    pub kind: Option<String>,

    /// Blueprint metadata (name, description).
    pub metadata: Option<BlueprintMetadata>,

    /// Blueprint specification (image, policy, providers, etc.).
    pub spec: Option<BlueprintSpec>,

    /// Unknown top-level fields captured for forward compatibility warnings.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

/// Blueprint metadata.
#[derive(Debug, Clone, Deserialize)]
pub struct BlueprintMetadata {
    /// Required. Blueprint identifier. Must match `[a-z0-9-]+`.
    pub name: Option<String>,

    /// Optional. Human-readable description.
    pub description: Option<String>,

    /// Unknown fields captured for forward compatibility.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

/// Blueprint specification — the desired sandbox configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct BlueprintSpec {
    /// Required. Container image reference.
    pub image: Option<String>,

    /// Optional. Path to policy YAML file.
    pub policy: Option<String>,

    /// Optional. List of provider names to attach.
    pub providers: Option<Vec<String>>,

    /// Optional. MCP servers to connect.
    pub mcp_servers: Option<Vec<McpServerEntry>>,

    /// Optional. Port forwards in `[bind:]port` format.
    pub forwards: Option<Vec<String>>,

    /// Optional. Resource limits.
    pub resources: Option<ResourceSpec>,

    /// Optional. Files to upload on creation in `local:remote` format.
    pub upload: Option<Vec<String>>,

    /// Unknown fields captured for forward compatibility.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

/// An MCP server entry within a blueprint.
#[derive(Debug, Clone, Deserialize)]
pub struct McpServerEntry {
    /// Required. Server identifier.
    pub name: Option<String>,

    /// Required. Transport type.
    pub transport: Option<McpTransport>,

    /// Required for bridge/in-sandbox. Server launch command.
    pub command: Option<String>,

    /// Optional. Environment variable names for credentials.
    pub env: Option<Vec<String>>,

    /// Required for streamable-http. Server endpoint URL.
    pub url: Option<String>,

    /// Unknown fields captured for forward compatibility.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

/// Transport type for MCP servers.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum McpTransport {
    /// stdio bridge running on the host.
    Bridge,
    /// Server running inside the sandbox.
    InSandbox,
    /// HTTP endpoint accessible via URL.
    StreamableHttp,
}

impl std::fmt::Display for McpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bridge => write!(f, "bridge"),
            Self::InSandbox => write!(f, "in-sandbox"),
            Self::StreamableHttp => write!(f, "streamable-http"),
        }
    }
}

/// Resource limits for the sandbox.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceSpec {
    /// CPU quantity in Kubernetes format (e.g., "2", "500m").
    pub cpu: Option<String>,

    /// Memory quantity in Kubernetes format (e.g., "4Gi", "512Mi").
    pub memory: Option<String>,

    /// Unknown fields captured for forward compatibility.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

// ---------------------------------------------------------------------------
// Validation types
// ---------------------------------------------------------------------------

/// A validation error with field path, message, and optional line context.
///
/// **Note:** Line numbers are not included because `serde_yaml` does not preserve
/// source locations after deserialization into typed structs. Adding line numbers
/// would require a custom YAML parser or a two-pass approach (raw YAML AST +
/// typed deserialization), which is deferred to a future enhancement.
#[derive(Debug, Clone, Error)]
#[error("{field}: {message}")]
pub struct ValidationError {
    /// Dot-separated path to the field (e.g., `spec.mcp_servers[0].command`).
    pub field: String,

    /// Human-readable error message with fix suggestion.
    pub message: String,
}

/// A validation warning (e.g., unknown fields).
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    /// Dot-separated path to the field.
    pub field: String,

    /// Human-readable warning message.
    pub message: String,
}

/// Result of blueprint validation. Contains all collected errors and warnings.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Errors that must be fixed before the blueprint can be used.
    pub errors: Vec<ValidationError>,

    /// Warnings that don't prevent usage but may indicate issues.
    pub warnings: Vec<ValidationWarning>,
}

// ---------------------------------------------------------------------------
// Parse error
// ---------------------------------------------------------------------------

/// Errors that can occur when parsing blueprint YAML.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ParseError {
    /// The input was empty.
    #[error("Empty blueprint file. See `darkshell blueprint --help` for format.")]
    EmptyInput,

    /// The input exceeds the maximum allowed size.
    #[error(
        "Blueprint input is {size} bytes, exceeding the {max} byte limit. \
         Reduce the blueprint size or split into multiple files."
    )]
    InputTooLarge { size: usize, max: usize },

    /// The YAML was not a mapping (e.g., it was a list or scalar).
    #[error(
        "Blueprint must be a YAML mapping, not a {actual_type}. Expected `apiVersion`, `kind`, `metadata`, `spec`."
    )]
    NotAMapping { actual_type: String },

    /// YAML syntax error or deserialization failure.
    #[error("YAML parse error: {source}")]
    YamlError {
        #[from]
        source: serde_yaml::Error,
    },
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a blueprint from a YAML string.
///
/// This uses lenient parsing: unknown fields are captured (not rejected) so that
/// older `DarkShell` versions can partially process blueprints written for newer
/// versions. Unknown fields will produce warnings during validation.
///
/// # Errors
///
/// Returns `ParseError` for empty input, non-mapping YAML, or syntax errors.
/// Maximum blueprint input size (1 MB). Protects against excessive memory
/// usage from very large or malicious inputs (e.g., YAML anchor bombs).
pub const MAX_BLUEPRINT_SIZE: usize = 1_048_576;

pub fn parse_blueprint(yaml: &str) -> Result<Blueprint, ParseError> {
    if yaml.len() > MAX_BLUEPRINT_SIZE {
        return Err(ParseError::InputTooLarge {
            size: yaml.len(),
            max: MAX_BLUEPRINT_SIZE,
        });
    }

    let trimmed = yaml.trim();
    if trimmed.is_empty() {
        return Err(ParseError::EmptyInput);
    }

    // Parse once into a generic Value to check structure, then deserialize
    // from that same Value (BP-M006: avoid double YAML parse).
    let value: serde_yaml::Value = serde_yaml::from_str(trimmed)?;
    if !value.is_mapping() {
        let actual_type = if value.is_sequence() {
            "sequence".to_owned()
        } else if value.is_string() {
            "string".to_owned()
        } else if value.is_number() {
            "number".to_owned()
        } else if value.is_bool() {
            "boolean".to_owned()
        } else if value.is_null() {
            return Err(ParseError::EmptyInput);
        } else {
            "unknown type".to_owned()
        };
        return Err(ParseError::NotAMapping { actual_type });
    }

    let blueprint: Blueprint = serde_yaml::from_value(value)?;
    Ok(blueprint)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Validate a parsed blueprint, collecting all errors and warnings.
///
/// This is a pure function with no side effects. All errors are collected
/// (not fail-fast) so the operator can fix everything in one pass.
pub fn validate(blueprint: &Blueprint) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Collect unknown top-level field warnings.
    collect_unknown_field_warnings(&blueprint.extra, "", &mut warnings);

    // AC-005: apiVersion is required and must be "darkshell/v1".
    validate_api_version(blueprint, &mut errors);

    // kind must be "Blueprint" if present.
    validate_kind(blueprint, &mut errors);

    // metadata validation.
    validate_metadata(blueprint, &mut errors, &mut warnings);

    // spec validation.
    validate_spec(blueprint, &mut errors, &mut warnings);

    ValidationResult { errors, warnings }
}

fn validate_api_version(blueprint: &Blueprint, errors: &mut Vec<ValidationError>) {
    match &blueprint.api_version {
        None => {
            errors.push(ValidationError {
                field: "apiVersion".to_owned(),
                message: "Required field 'apiVersion' is missing. Expected: 'darkshell/v1'."
                    .to_owned(),
            });
        }
        Some(version) if version != "darkshell/v1" => {
            errors.push(ValidationError {
                field: "apiVersion".to_owned(),
                message: format!(
                    "Unsupported apiVersion '{version}'. Expected 'darkshell/v1'. \
                     You may need to upgrade DarkShell to support this version."
                ),
            });
        }
        Some(_) => {} // Valid.
    }
}

fn validate_kind(blueprint: &Blueprint, errors: &mut Vec<ValidationError>) {
    match &blueprint.kind {
        None => {
            errors.push(ValidationError {
                field: "kind".to_owned(),
                message: "Required field 'kind' is missing. Expected: 'Blueprint'.".to_owned(),
            });
        }
        Some(kind) if kind != "Blueprint" => {
            errors.push(ValidationError {
                field: "kind".to_owned(),
                message: format!("Invalid kind '{kind}'. Expected: 'Blueprint'."),
            });
        }
        Some(_) => {} // Valid.
    }
}

fn validate_metadata(
    blueprint: &Blueprint,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    match &blueprint.metadata {
        None => {
            errors.push(ValidationError {
                field: "metadata".to_owned(),
                message: "Required section 'metadata' is missing.".to_owned(),
            });
        }
        Some(metadata) => {
            collect_unknown_field_warnings(&metadata.extra, "metadata", warnings);

            match &metadata.name {
                None => {
                    errors.push(ValidationError {
                        field: "metadata.name".to_owned(),
                        message: "Required field 'metadata.name' is missing.".to_owned(),
                    });
                }
                Some(name) if name.is_empty() => {
                    errors.push(ValidationError {
                        field: "metadata.name".to_owned(),
                        message: "Blueprint name must not be empty.".to_owned(),
                    });
                }
                Some(name) => {
                    // BP-M001: name must start and end with alphanumeric,
                    // contain only [a-z0-9-], and be at most 63 characters.
                    // Pattern: [a-z0-9]([a-z0-9-]*[a-z0-9])?
                    if name.len() > 63 {
                        errors.push(ValidationError {
                            field: "metadata.name".to_owned(),
                            message: format!(
                                "Blueprint name '{name}' is {} characters long. \
                                 Maximum length is 63 characters.",
                                name.len()
                            ),
                        });
                    }
                    if !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                        errors.push(ValidationError {
                            field: "metadata.name".to_owned(),
                            message: format!(
                                "Blueprint name '{name}' contains invalid characters. \
                                 Sandbox names must match [a-z0-9]([a-z0-9-]*[a-z0-9])?."
                            ),
                        });
                    } else if !name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                        || !name.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
                    {
                        errors.push(ValidationError {
                            field: "metadata.name".to_owned(),
                            message: format!(
                                "Blueprint name '{name}' must start and end with an \
                                 alphanumeric character [a-z0-9]. Leading or trailing \
                                 hyphens are not allowed."
                            ),
                        });
                    }
                }
            }
        }
    }
}

fn validate_spec(
    blueprint: &Blueprint,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    match &blueprint.spec {
        None => {
            errors.push(ValidationError {
                field: "spec".to_owned(),
                message: "Required section 'spec' is missing.".to_owned(),
            });
        }
        Some(spec) => {
            collect_unknown_field_warnings(&spec.extra, "spec", warnings);

            // spec.image is required.
            match &spec.image {
                None => {
                    errors.push(ValidationError {
                        field: "spec.image".to_owned(),
                        message: "Required field 'spec.image' is missing.".to_owned(),
                    });
                }
                Some(image) if image.is_empty() => {
                    errors.push(ValidationError {
                        field: "spec.image".to_owned(),
                        message: "Image reference must not be empty.".to_owned(),
                    });
                }
                Some(_) => {} // Valid (existence is a runtime check).
            }

            // BP-M002: validate policy path.
            if let Some(ref policy) = spec.policy {
                if policy.contains("..") {
                    warnings.push(ValidationWarning {
                        field: "spec.policy".to_owned(),
                        message: format!(
                            "Policy path '{policy}' contains '..'. This may cause \
                             unexpected behavior. Use a direct relative path instead."
                        ),
                    });
                }
                if policy.starts_with('/') {
                    errors.push(ValidationError {
                        field: "spec.policy".to_owned(),
                        message: format!(
                            "Policy path '{policy}' is absolute. Policy paths should be \
                             relative to the blueprint file."
                        ),
                    });
                }
            }

            // Validate MCP servers.
            if let Some(servers) = &spec.mcp_servers {
                validate_mcp_servers(servers, errors, warnings);
            }

            // Validate port forwards.
            if let Some(forwards) = &spec.forwards {
                validate_forwards(forwards, errors, warnings);
            }

            // Validate resources.
            if let Some(resources) = &spec.resources {
                validate_resources(resources, errors, warnings);
            }

            // Validate upload specs.
            if let Some(uploads) = &spec.upload {
                validate_uploads(uploads, errors, warnings);
            }
        }
    }
}

fn validate_mcp_servers(
    servers: &[McpServerEntry],
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    let mut seen_names: HashMap<String, usize> = HashMap::new();

    for (i, server) in servers.iter().enumerate() {
        let prefix = format!("spec.mcp_servers[{i}]");

        collect_unknown_field_warnings(&server.extra, &prefix, warnings);

        // Name is required.
        match &server.name {
            None => {
                errors.push(ValidationError {
                    field: format!("{prefix}.name"),
                    message: "MCP server name is required.".to_owned(),
                });
            }
            Some(name) if name.is_empty() => {
                errors.push(ValidationError {
                    field: format!("{prefix}.name"),
                    message: "MCP server name must not be empty.".to_owned(),
                });
            }
            Some(name) => {
                // EC-CUSTOM-005: check for duplicate names.
                if let Some(&first_idx) = seen_names.get(name) {
                    errors.push(ValidationError {
                        field: format!("{prefix}.name"),
                        message: format!(
                            "Duplicate MCP server name '{name}' in blueprint. \
                             First defined at spec.mcp_servers[{first_idx}]. \
                             Each server must have a unique name."
                        ),
                    });
                } else {
                    seen_names.insert(name.clone(), i);
                }
            }
        }

        // Transport is required.
        match &server.transport {
            None => {
                errors.push(ValidationError {
                    field: format!("{prefix}.transport"),
                    message:
                        "MCP server transport is required. Valid values: bridge, in-sandbox, streamable-http."
                            .to_owned(),
                });
            }
            Some(transport) => {
                validate_mcp_transport(transport, server, &prefix, errors, warnings);
            }
        }
    }
}

fn validate_mcp_transport(
    transport: &McpTransport,
    server: &McpServerEntry,
    prefix: &str,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    // BP-H001: warn when command contains shell metacharacters.
    if let Some(ref command) = server.command {
        let shell_metacharacters = [";", "|", "&&", "$(", "`"];
        if shell_metacharacters.iter().any(|mc| command.contains(mc)) {
            warnings.push(ValidationWarning {
                field: format!("{prefix}.command"),
                message: "MCP server command contains shell metacharacters. \
                          Consider using an array format to prevent shell interpretation."
                    .to_owned(),
            });
        }
    }

    match transport {
        McpTransport::Bridge => {
            // command required, url forbidden.
            if server.command.is_none() {
                errors.push(ValidationError {
                    field: format!("{prefix}.command"),
                    message: "Transport 'bridge' requires 'command' field.".to_owned(),
                });
            }
            if server.url.is_some() {
                errors.push(ValidationError {
                    field: format!("{prefix}.url"),
                    message: "Transport 'bridge' does not use 'url'. Remove this field."
                        .to_owned(),
                });
            }
        }
        McpTransport::InSandbox => {
            // command required, env forbidden.
            if server.command.is_none() {
                errors.push(ValidationError {
                    field: format!("{prefix}.command"),
                    message: "Transport 'in-sandbox' requires 'command' field.".to_owned(),
                });
            }
            if server.env.is_some() {
                errors.push(ValidationError {
                    field: format!("{prefix}.env"),
                    message: "Transport 'in-sandbox' does not support 'env' (credentials are not injected into the sandbox). Remove this field.".to_owned(),
                });
            }
        }
        McpTransport::StreamableHttp => {
            // url required, command forbidden.
            match &server.url {
                None => {
                    errors.push(ValidationError {
                        field: format!("{prefix}.url"),
                        message: "Transport 'streamable-http' requires 'url' field.".to_owned(),
                    });
                }
                Some(url) => {
                    // BP-H003: validate URL scheme for streamable-http.
                    let dangerous_schemes = ["file://", "ftp://", "javascript:"];
                    if dangerous_schemes.iter().any(|s| url.starts_with(s)) {
                        errors.push(ValidationError {
                            field: format!("{prefix}.url"),
                            message: format!(
                                "URL scheme is not allowed for streamable-http transport. \
                                 Only 'http://' and 'https://' are supported. Got: '{url}'."
                            ),
                        });
                    } else if !url.starts_with("http://") && !url.starts_with("https://") {
                        errors.push(ValidationError {
                            field: format!("{prefix}.url"),
                            message: format!(
                                "URL must start with 'http://' or 'https://'. Got: '{url}'."
                            ),
                        });
                    } else if url.starts_with("http://") {
                        warnings.push(ValidationWarning {
                            field: format!("{prefix}.url"),
                            message: "MCP server URL uses insecure 'http://' scheme. \
                                      Consider using 'https://' for production."
                                .to_owned(),
                        });
                    }
                }
            }
            if server.command.is_some() {
                errors.push(ValidationError {
                    field: format!("{prefix}.command"),
                    message:
                        "Transport 'streamable-http' does not use 'command'. Remove this field."
                            .to_owned(),
                });
            }
        }
    }
}

fn validate_forwards(
    forwards: &[String],
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    for (i, spec) in forwards.iter().enumerate() {
        let field = format!("spec.forwards[{i}]");

        // Format: [bind_address:]port
        let (bind_addr, port_str) = if let Some((bind, port)) = spec.rsplit_once(':') {
            (Some(bind), port)
        } else {
            (None, spec.as_str())
        };

        // BP-M003: validate bind address format if present.
        if let Some(addr) = bind_addr
            && !addr.is_empty()
            && addr.parse::<std::net::Ipv4Addr>().is_err()
            && addr.parse::<std::net::Ipv6Addr>().is_err()
            && addr != "localhost"
        {
            warnings.push(ValidationWarning {
                field: field.clone(),
                message: format!(
                    "Bind address '{addr}' does not appear to be a valid IP address \
                     or 'localhost'. Got: '{spec}'."
                ),
            });
        }

        // BP-M003: parse as u16 directly instead of u32.
        match port_str.parse::<u16>() {
            Ok(0) => {
                errors.push(ValidationError {
                    field,
                    message: format!(
                        "Port 0 is out of range. Must be 1-65535. Got: '{spec}'."
                    ),
                });
            }
            Ok(_) => {} // Valid: 1-65535 (u16 range minus 0).
            Err(_) => {
                errors.push(ValidationError {
                    field,
                    message: format!(
                        "Invalid port forward spec. Expected format: '[bind_address:]port' \
                         where port is 1-65535. Got: '{spec}'."
                    ),
                });
            }
        }
    }
}

fn validate_resources(
    resources: &ResourceSpec,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    collect_unknown_field_warnings(&resources.extra, "spec.resources", warnings);

    if let Some(cpu) = &resources.cpu
        && !is_valid_k8s_cpu(cpu)
    {
        errors.push(ValidationError {
            field: "spec.resources.cpu".to_owned(),
            message: format!(
                "Invalid CPU quantity '{cpu}'. \
                 Valid examples: '2', '500m', '0.5', '100m'. \
                 Use integer/decimal for cores or suffix 'm' for millicores."
            ),
        });
    }

    if let Some(memory) = &resources.memory
        && !is_valid_k8s_memory(memory)
    {
        errors.push(ValidationError {
            field: "spec.resources.memory".to_owned(),
            message: format!(
                "Invalid memory quantity '{memory}'. \
                 Valid examples: '4Gi', '512Mi', '1G', '256M'. \
                 Use suffix: Ki, Mi, Gi, Ti, K, M, G, T."
            ),
        });
    }
}

fn validate_uploads(
    uploads: &[String],
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<ValidationWarning>,
) {
    /// System directories that should not be written to via upload.
    const SYSTEM_DIRS: &[&str] = &["/etc", "/usr", "/bin", "/sbin"];

    for (i, spec) in uploads.iter().enumerate() {
        let field = format!("spec.upload[{i}]");

        // EC-CUSTOM-006: must contain colon separator (but not just a drive letter on Windows).
        // Format: local:remote — we look for the colon that separates local from remote.
        if !spec.contains(':') {
            errors.push(ValidationError {
                field,
                message: format!(
                    "Upload spec must be in format 'local:remote'. Got: '{spec}'."
                ),
            });
            continue;
        }

        // BP-H002: validate local and remote paths.
        if let Some((local, remote)) = spec.split_once(':') {
            // Reject local paths containing ".." (path traversal).
            if local.contains("..") {
                errors.push(ValidationError {
                    field: field.clone(),
                    message: format!(
                        "Upload local path contains '..'. Path traversal is not allowed. \
                         Use a direct relative path instead. Got: '{local}'."
                    ),
                });
            }

            // Warn on absolute local paths.
            if local.starts_with('/') {
                warnings.push(ValidationWarning {
                    field: field.clone(),
                    message: format!(
                        "Upload local path '{local}' is absolute. Consider using a \
                         relative path for portability."
                    ),
                });
            }

            // Reject remote paths writing to system directories.
            for sys_dir in SYSTEM_DIRS {
                if remote == *sys_dir || remote.starts_with(&format!("{sys_dir}/")) {
                    errors.push(ValidationError {
                        field: field.clone(),
                        message: format!(
                            "Upload remote path '{remote}' targets system directory '{sys_dir}'. \
                             Writing to system directories is not allowed."
                        ),
                    });
                    break;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn collect_unknown_field_warnings(
    extra: &HashMap<String, serde_yaml::Value>,
    parent_path: &str,
    warnings: &mut Vec<ValidationWarning>,
) {
    for key in extra.keys() {
        let field = if parent_path.is_empty() {
            key.clone()
        } else {
            format!("{parent_path}.{key}")
        };
        warnings.push(ValidationWarning {
            field: field.clone(),
            message: format!(
                "Unknown field '{field}'. This field is not recognized by the current \
                 schema version and will be ignored. If this is intentional, you may \
                 need a newer version of DarkShell."
            ),
        });
    }
}

/// Validate a Kubernetes CPU quantity.
///
/// Valid formats: integer ("2"), decimal ("0.5"), millicores ("500m").
fn is_valid_k8s_cpu(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    s.strip_suffix('m').map_or_else(
        // Cores: must be a positive number.
        || s.parse::<f64>().is_ok_and(|v| v > 0.0 && v.is_finite()),
        // Millicores: must be a positive integer.
        |millis| millis.parse::<u64>().is_ok_and(|v| v > 0),
    )
}

/// Validate a Kubernetes memory quantity.
///
/// Valid formats: with binary suffix (Ki, Mi, Gi, Ti) or decimal suffix (K, M, G, T),
/// or plain bytes as integer.
fn is_valid_k8s_memory(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }

    // Try binary suffixes first (must check before single-char).
    for suffix in &["Ki", "Mi", "Gi", "Ti", "Pi", "Ei"] {
        if let Some(num) = s.strip_suffix(suffix) {
            return num.parse::<u64>().is_ok_and(|v| v > 0);
        }
    }

    // Decimal suffixes.
    for suffix in &["K", "M", "G", "T", "P", "E"] {
        if let Some(num) = s.strip_suffix(suffix) {
            return num.parse::<u64>().is_ok_and(|v| v > 0);
        }
    }

    // Plain bytes (integer only).
    s.parse::<u64>().is_ok_and(|v| v > 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::needless_raw_string_hashes)]
mod tests {
    use super::*;

    // -- Helpers --

    fn full_blueprint_yaml() -> &'static str {
        r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: my-dev-sandbox
  description: Development sandbox with MCP servers
spec:
  image: ubuntu:22.04
  policy: policies/dev.yaml
  providers:
    - github
    - openai
  mcp_servers:
    - name: code-assist
      transport: bridge
      command: npx @modelcontextprotocol/server-code
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
    - "./src:~/project/src"
    - "./config:~/project/config"
"#
    }

    fn minimal_blueprint_yaml() -> &'static str {
        r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: minimal
spec:
  image: ubuntu:22.04
"#
    }

    // -----------------------------------------------------------------------
    // AC-001: Blueprint YAML schema includes all required fields
    // -----------------------------------------------------------------------

    #[test]
    fn test_blueprint_schema_parses_full_spec_with_all_fields() {
        let bp = parse_blueprint(full_blueprint_yaml()).expect("should parse full blueprint");

        assert_eq!(bp.api_version.as_deref(), Some("darkshell/v1"));
        assert_eq!(bp.kind.as_deref(), Some("Blueprint"));

        let meta = bp.metadata.as_ref().expect("metadata present");
        assert_eq!(meta.name.as_deref(), Some("my-dev-sandbox"));
        assert_eq!(
            meta.description.as_deref(),
            Some("Development sandbox with MCP servers")
        );

        let spec = bp.spec.as_ref().expect("spec present");
        assert_eq!(spec.image.as_deref(), Some("ubuntu:22.04"));
        assert_eq!(spec.policy.as_deref(), Some("policies/dev.yaml"));
        assert_eq!(
            spec.providers.as_deref(),
            Some(["github", "openai"].map(String::from).as_slice())
        );

        let servers = spec.mcp_servers.as_ref().expect("mcp_servers present");
        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0].name.as_deref(), Some("code-assist"));
        assert_eq!(servers[0].transport, Some(McpTransport::Bridge));
        assert_eq!(servers[1].transport, Some(McpTransport::InSandbox));
        assert_eq!(servers[2].transport, Some(McpTransport::StreamableHttp));
        assert_eq!(
            servers[2].url.as_deref(),
            Some("https://api.example.com/mcp")
        );

        let forwards = spec.forwards.as_ref().expect("forwards present");
        assert_eq!(forwards.len(), 2);

        let resources = spec.resources.as_ref().expect("resources present");
        assert_eq!(resources.cpu.as_deref(), Some("2"));
        assert_eq!(resources.memory.as_deref(), Some("4Gi"));

        let uploads = spec.upload.as_ref().expect("upload present");
        assert_eq!(uploads.len(), 2);
    }

    #[test]
    fn test_blueprint_schema_parses_minimal_spec_with_only_required_fields() {
        let bp = parse_blueprint(minimal_blueprint_yaml()).expect("should parse minimal blueprint");
        let result = validate(&bp);

        assert!(result.errors.is_empty(), "errors: {:?}", result.errors);

        assert_eq!(bp.api_version.as_deref(), Some("darkshell/v1"));
        let meta = bp.metadata.as_ref().expect("metadata present");
        assert_eq!(meta.name.as_deref(), Some("minimal"));
        let spec = bp.spec.as_ref().expect("spec present");
        assert_eq!(spec.image.as_deref(), Some("ubuntu:22.04"));
    }

    // -----------------------------------------------------------------------
    // AC-002: Schema validated before sandbox creation — all errors collected
    // -----------------------------------------------------------------------

    #[test]
    fn test_blueprint_validate_rejects_missing_required_fields() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata: {}
spec: {}
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let error_fields: Vec<&str> = result.errors.iter().map(|e| e.field.as_str()).collect();
        assert!(
            error_fields.contains(&"metadata.name"),
            "expected metadata.name error, got: {error_fields:?}"
        );
        assert!(
            error_fields.contains(&"spec.image"),
            "expected spec.image error, got: {error_fields:?}"
        );
    }

    #[test]
    fn test_blueprint_validate_reports_all_errors_not_just_first() {
        let yaml = r#"
kind: Blueprint
spec: {}
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        // Should report errors for: apiVersion, metadata (missing entirely), spec.image.
        assert!(
            result.errors.len() >= 3,
            "expected at least 3 errors, got {}: {:?}",
            result.errors.len(),
            result.errors
        );
    }

    // -----------------------------------------------------------------------
    // AC-003: Validation errors reference field paths
    // -----------------------------------------------------------------------

    #[test]
    fn test_validation_error_includes_field_path() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: broken
      transport: bridge
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let has_field_path = result
            .errors
            .iter()
            .any(|e| e.field.starts_with("spec.mcp_servers[0]"));
        assert!(
            has_field_path,
            "expected error with field path containing 'spec.mcp_servers[0]', got: {:?}",
            result.errors
        );
    }

    // -----------------------------------------------------------------------
    // AC-004: Unknown fields produce warnings, not errors
    // -----------------------------------------------------------------------

    #[test]
    fn test_unknown_fields_produce_warning_not_error() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test-sandbox
  custom_label: my-label
spec:
  image: ubuntu:22.04
  future_field: some-value
extra_top_level: hello
"#;
        let bp = parse_blueprint(yaml).expect("should parse with unknown fields");
        let result = validate(&bp);

        assert!(
            result.errors.is_empty(),
            "unknown fields should not cause errors: {:?}",
            result.errors
        );
        assert!(
            result.warnings.len() >= 3,
            "expected at least 3 warnings for unknown fields, got {}: {:?}",
            result.warnings.len(),
            result.warnings
        );

        let warning_fields: Vec<&str> = result.warnings.iter().map(|w| w.field.as_str()).collect();
        assert!(warning_fields.iter().any(|f| f.contains("extra_top_level")));
        assert!(warning_fields.iter().any(|f| f.contains("custom_label")));
        assert!(warning_fields.iter().any(|f| f.contains("future_field")));
    }

    // -----------------------------------------------------------------------
    // AC-005: apiVersion is checked
    // -----------------------------------------------------------------------

    #[test]
    fn test_invalid_api_version_rejected_with_upgrade_suggestion() {
        let yaml = r#"
apiVersion: darkshell/v2
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let version_error = result
            .errors
            .iter()
            .find(|e| e.field == "apiVersion")
            .expect("expected apiVersion error");
        assert!(
            version_error.message.contains("upgrade"),
            "error should suggest upgrading: {}",
            version_error.message
        );
    }

    #[test]
    fn test_missing_api_version_rejected() {
        let yaml = r#"
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        assert!(
            result.errors.iter().any(|e| e.field == "apiVersion"),
            "expected apiVersion error, got: {:?}",
            result.errors
        );
    }

    // -----------------------------------------------------------------------
    // AC-006: MCP server entries validated per transport type
    // -----------------------------------------------------------------------

    #[test]
    fn test_bridge_transport_requires_command_forbids_url() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: bad-bridge
      transport: bridge
      url: https://example.com
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let error_fields: Vec<&str> = result.errors.iter().map(|e| e.field.as_str()).collect();
        assert!(
            error_fields
                .iter()
                .any(|f| f.contains("command")),
            "expected command-required error: {error_fields:?}"
        );
        assert!(
            error_fields
                .iter()
                .any(|f| f.contains("url")),
            "expected url-forbidden error: {error_fields:?}"
        );
    }

    #[test]
    fn test_in_sandbox_transport_requires_command_forbids_env() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: bad-insandbox
      transport: in-sandbox
      env:
        - SECRET_KEY
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let error_fields: Vec<&str> = result.errors.iter().map(|e| e.field.as_str()).collect();
        assert!(
            error_fields
                .iter()
                .any(|f| f.contains("command")),
            "expected command-required error: {error_fields:?}"
        );
        assert!(
            error_fields
                .iter()
                .any(|f| f.contains("env")),
            "expected env-forbidden error: {error_fields:?}"
        );
    }

    #[test]
    fn test_streamable_http_transport_requires_url_forbids_command() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: bad-http
      transport: streamable-http
      command: some-command
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let error_fields: Vec<&str> = result.errors.iter().map(|e| e.field.as_str()).collect();
        assert!(
            error_fields
                .iter()
                .any(|f| f.contains("url")),
            "expected url-required error: {error_fields:?}"
        );
        assert!(
            error_fields
                .iter()
                .any(|f| f.contains("command")),
            "expected command-forbidden error: {error_fields:?}"
        );
    }

    // -----------------------------------------------------------------------
    // AC-007: Port forward specs validated for correct format
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_port_forward_specs_accepted() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  forwards:
    - "8080"
    - "127.0.0.1:3000"
    - "0.0.0.0:443"
    - "1"
    - "65535"
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let forward_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.field.starts_with("spec.forwards"))
            .collect();
        assert!(
            forward_errors.is_empty(),
            "valid forwards should not produce errors: {forward_errors:?}"
        );
    }

    #[test]
    fn test_invalid_port_forward_spec_rejected_with_format_hint() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  forwards:
    - "abc"
    - "0"
    - "99999"
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let forward_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.field.starts_with("spec.forwards"))
            .collect();
        assert_eq!(
            forward_errors.len(),
            3,
            "expected 3 forward errors, got: {forward_errors:?}"
        );
    }

    // -----------------------------------------------------------------------
    // AC-008: Resource limit values validated
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_resource_limits_accepted() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  resources:
    cpu: "500m"
    memory: 4Gi
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let resource_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.field.starts_with("spec.resources"))
            .collect();
        assert!(
            resource_errors.is_empty(),
            "valid resources should not produce errors: {resource_errors:?}"
        );
    }

    #[test]
    fn test_invalid_resource_cpu_rejected_with_examples() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  resources:
    cpu: "lots"
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let cpu_error = result
            .errors
            .iter()
            .find(|e| e.field == "spec.resources.cpu")
            .expect("expected CPU error");
        assert!(
            cpu_error.message.contains("500m"),
            "error should include valid example: {}",
            cpu_error.message
        );
    }

    #[test]
    fn test_invalid_resource_memory_rejected_with_examples() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  resources:
    memory: "big"
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let mem_error = result
            .errors
            .iter()
            .find(|e| e.field == "spec.resources.memory")
            .expect("expected memory error");
        assert!(
            mem_error.message.contains("4Gi"),
            "error should include valid example: {}",
            mem_error.message
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_input_produces_clear_error() {
        let err = parse_blueprint("").unwrap_err();
        assert!(
            err.to_string().contains("Empty blueprint file"),
            "expected empty file error, got: {err}"
        );
    }

    #[test]
    fn test_whitespace_only_input_produces_clear_error() {
        let err = parse_blueprint("   \n  \n  ").unwrap_err();
        assert!(
            err.to_string().contains("Empty blueprint file"),
            "expected empty file error, got: {err}"
        );
    }

    #[test]
    fn test_yaml_list_instead_of_map_produces_clear_error() {
        let err = parse_blueprint("- item1\n- item2").unwrap_err();
        assert!(
            err.to_string().contains("sequence"),
            "expected 'sequence' in error, got: {err}"
        );
    }

    #[test]
    fn test_invalid_yaml_syntax_produces_parse_error() {
        let result = parse_blueprint("invalid: yaml: [broken");
        assert!(result.is_err());
    }

    #[test]
    fn test_blueprint_name_with_invalid_chars_rejected() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: My_Sandbox!
spec:
  image: ubuntu:22.04
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let name_error = result
            .errors
            .iter()
            .find(|e| e.field == "metadata.name")
            .expect("expected name validation error");
        assert!(
            name_error.message.contains("[a-z0-9]"),
            "error should show valid pattern: {}",
            name_error.message
        );
    }

    #[test]
    fn test_duplicate_mcp_server_names_rejected() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: my-server
      transport: bridge
      command: cmd1
    - name: my-server
      transport: bridge
      command: cmd2
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let dup_error = result
            .errors
            .iter()
            .find(|e| e.message.contains("Duplicate MCP server name"));
        assert!(
            dup_error.is_some(),
            "expected duplicate name error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_upload_spec_missing_colon_rejected() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  upload:
    - "path-without-colon"
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let upload_error = result
            .errors
            .iter()
            .find(|e| e.field.starts_with("spec.upload"))
            .expect("expected upload error");
        assert!(
            upload_error.message.contains("local:remote"),
            "error should show expected format: {}",
            upload_error.message
        );
    }

    // -----------------------------------------------------------------------
    // Full valid blueprint produces no errors
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_valid_blueprint_produces_no_errors_or_warnings() {
        let bp = parse_blueprint(full_blueprint_yaml()).expect("should parse");
        let result = validate(&bp);

        assert!(
            result.errors.is_empty(),
            "full valid blueprint should have no errors: {:?}",
            result.errors
        );
        assert!(
            result.warnings.is_empty(),
            "full valid blueprint should have no warnings: {:?}",
            result.warnings
        );
    }

    // -----------------------------------------------------------------------
    // Resource validation edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_various_valid_cpu_values() {
        assert!(is_valid_k8s_cpu("1"));
        assert!(is_valid_k8s_cpu("2"));
        assert!(is_valid_k8s_cpu("0.5"));
        assert!(is_valid_k8s_cpu("100m"));
        assert!(is_valid_k8s_cpu("500m"));
        assert!(is_valid_k8s_cpu("2500m"));
    }

    #[test]
    fn test_various_invalid_cpu_values() {
        assert!(!is_valid_k8s_cpu(""));
        assert!(!is_valid_k8s_cpu("abc"));
        assert!(!is_valid_k8s_cpu("0"));
        assert!(!is_valid_k8s_cpu("0m"));
        assert!(!is_valid_k8s_cpu("-1"));
        assert!(!is_valid_k8s_cpu("m"));
    }

    #[test]
    fn test_various_valid_memory_values() {
        assert!(is_valid_k8s_memory("512Mi"));
        assert!(is_valid_k8s_memory("4Gi"));
        assert!(is_valid_k8s_memory("1Ti"));
        assert!(is_valid_k8s_memory("256M"));
        assert!(is_valid_k8s_memory("1G"));
        assert!(is_valid_k8s_memory("1024"));
        assert!(is_valid_k8s_memory("1Ki"));
    }

    #[test]
    fn test_various_invalid_memory_values() {
        assert!(!is_valid_k8s_memory(""));
        assert!(!is_valid_k8s_memory("abc"));
        assert!(!is_valid_k8s_memory("0"));
        assert!(!is_valid_k8s_memory("0Gi"));
        assert!(!is_valid_k8s_memory("Gi"));
    }

    // -----------------------------------------------------------------------
    // kind validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_missing_kind_rejected() {
        let yaml = r#"
apiVersion: darkshell/v1
metadata:
  name: test
spec:
  image: ubuntu:22.04
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        assert!(
            result.errors.iter().any(|e| e.field == "kind"),
            "expected kind error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_wrong_kind_rejected() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Deployment
metadata:
  name: test
spec:
  image: ubuntu:22.04
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let kind_error = result
            .errors
            .iter()
            .find(|e| e.field == "kind")
            .expect("expected kind error");
        assert!(
            kind_error.message.contains("Blueprint"),
            "should suggest correct kind: {}",
            kind_error.message
        );
    }

    // -----------------------------------------------------------------------
    // Valid MCP server configurations
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_bridge_server() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: my-bridge
      transport: bridge
      command: npx @modelcontextprotocol/server
      env:
        - API_KEY
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let mcp_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.field.starts_with("spec.mcp_servers"))
            .collect();
        assert!(
            mcp_errors.is_empty(),
            "valid bridge server should not produce errors: {mcp_errors:?}"
        );
    }

    #[test]
    fn test_valid_streamable_http_server() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: my-http
      transport: streamable-http
      url: https://api.example.com/mcp
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let mcp_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.field.starts_with("spec.mcp_servers"))
            .collect();
        assert!(
            mcp_errors.is_empty(),
            "valid streamable-http server should not produce errors: {mcp_errors:?}"
        );
    }

    // -----------------------------------------------------------------------
    // DS-011: In-sandbox MCP server blueprint validation
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_in_sandbox_server() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: tally
      transport: in-sandbox
      command: /usr/local/bin/mcp-tally
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let mcp_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.field.starts_with("spec.mcp_servers"))
            .collect();
        assert!(
            mcp_errors.is_empty(),
            "valid in-sandbox server should not produce errors: {mcp_errors:?}"
        );
    }

    #[test]
    fn test_in_sandbox_transport_rejects_env_with_actionable_message() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: bad-insandbox
      transport: in-sandbox
      command: /usr/local/bin/mcp-tally
      env:
        - GITHUB_TOKEN
        - OPENAI_API_KEY
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        let env_errors: Vec<_> = result
            .errors
            .iter()
            .filter(|e| e.field.contains(".env"))
            .collect();
        assert!(
            !env_errors.is_empty(),
            "in-sandbox transport with env should produce an error"
        );
        let msg = &env_errors[0].message;
        assert!(
            msg.contains("credentials are not injected"),
            "error should explain why env is forbidden: {msg}"
        );
    }

    #[test]
    fn test_in_sandbox_transport_requires_command() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: no-cmd
      transport: in-sandbox
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        assert!(
            result.errors.iter().any(|e| e.field.contains(".command")),
            "in-sandbox transport without command should produce an error"
        );
    }

    // -----------------------------------------------------------------------
    // BP-L002 / BP-L003: Input size limit and YAML bomb protection
    // -----------------------------------------------------------------------

    #[test]
    fn test_oversized_input_rejected_with_actionable_error() {
        let huge_input = "x".repeat(MAX_BLUEPRINT_SIZE + 1);
        let err = parse_blueprint(&huge_input).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exceeding"),
            "error should mention size limit: {msg}"
        );
    }

    #[test]
    fn test_yaml_anchor_bomb_handled_safely() {
        // YAML anchor bomb: exponential expansion via aliases.
        // serde_yaml may reject this, or our size limit catches the raw input.
        // Either way, it must not cause excessive memory usage or panic.
        let bomb = r#"
a: &a ["lol","lol","lol","lol","lol","lol","lol","lol","lol"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]
"#;
        // This should either parse as an unknown-fields blueprint (not a valid
        // blueprint, but parseable YAML) or fail with a parse/size error.
        // The key assertion is that it does NOT panic or OOM.
        let result = parse_blueprint(bomb);
        if let Ok(bp) = result {
            // Parsed but won't validate — that's fine
            let validation = validate(&bp);
            assert!(
                !validation.errors.is_empty(),
                "anchor bomb should not produce a valid blueprint"
            );
        }
        // If Err, rejected at parse level — also fine
    }

    // -----------------------------------------------------------------------
    // BP-L004: Empty list fields produce no errors
    // -----------------------------------------------------------------------

    #[test]
    fn test_empty_list_fields_produce_no_errors() {
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: test
spec:
  image: ubuntu:22.04
  mcp_servers: []
  forwards: []
  providers: []
  upload: []
"#;
        let bp = parse_blueprint(yaml).expect("should parse");
        let result = validate(&bp);

        assert!(
            result.errors.is_empty(),
            "empty lists should produce no errors: {:?}",
            result.errors
        );
    }
}
