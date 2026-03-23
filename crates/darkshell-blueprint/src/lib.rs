//! # darkshell-blueprint
//!
//! Blueprint YAML schema and validation for `DarkShell` sandbox configurations.
//!
//! A blueprint is a declarative YAML document that describes a complete sandbox
//! configuration: image, policy, providers, MCP servers, port forwards, resources,
//! and file uploads. Validation catches misconfigurations at parse time rather than
//! mid-creation.
//!
//! # Example
//!
//! ```
//! use darkshell_blueprint::{parse_blueprint, validate};
//!
//! let yaml = r#"
//! apiVersion: darkshell/v1
//! kind: Blueprint
//! metadata:
//!   name: my-sandbox
//! spec:
//!   image: ubuntu:22.04
//! "#;
//!
//! let blueprint = parse_blueprint(yaml).unwrap();
//! let result = validate(&blueprint);
//! assert!(result.errors.is_empty());
//! ```

#![forbid(unsafe_code)]

mod schema;

pub use schema::{
    Blueprint, BlueprintMetadata, BlueprintSpec, McpServerEntry, McpTransport, ResourceSpec,
    ValidationError, ValidationResult, ValidationWarning, parse_blueprint, validate,
};
