// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Blueprint-to-sandbox orchestration logic (effectful-shell).
//!
//! The [`BlueprintOrchestrator`] coordinates the full sandbox creation lifecycle
//! from a validated blueprint: validate resources -> create sandbox -> apply policy
//! -> attach providers -> start MCP bridges -> configure port forwards -> upload files.
//!
//! On partial failure, all completed steps are rolled back in reverse order.

use crate::schema::{Blueprint, McpTransport};
use std::fmt;

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during blueprint orchestration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum OrchestrateError {
    /// Blueprint schema validation failed (pre-creation).
    #[error("blueprint validation failed with {count} error(s):\n{details}")]
    ValidationFailed { count: usize, details: String },

    /// Image is not pullable / not found (EC-009).
    #[error(
        "Image `{image}` not found. Check registry access and image name in `spec.image`."
    )]
    ImageNotFound { image: String },

    /// Provider does not exist (EC-010).
    #[error(
        "Provider '{provider}' not found. Create with: `darkshell provider create --name {provider} --type {provider}`"
    )]
    ProviderNotFound { provider: String },

    /// Policy file does not exist on disk (EC-B04).
    #[error(
        "Policy file '{path}' not found. Provide an absolute path or a path relative to the blueprint file."
    )]
    PolicyFileNotFound { path: String },

    /// Empty image (EC-B06).
    #[error("`spec.image` is required. Specify a container image reference (e.g., `ghcr.io/org/image:tag`).")]
    EmptyImage,

    /// Blueprint is structurally invalid (missing required fields that should have been caught by validation).
    #[error("invalid blueprint: {reason}")]
    InvalidBlueprint { reason: String },

    /// Sandbox creation failed via gateway API.
    #[error("sandbox creation failed: {reason}")]
    SandboxCreateFailed { reason: String },

    /// Policy apply failed.
    #[error("failed to apply policy '{policy}': {reason}")]
    PolicyApplyFailed { policy: String, reason: String },

    /// Provider attach failed.
    #[error("failed to attach provider '{provider}': {reason}")]
    ProviderAttachFailed { provider: String, reason: String },

    /// MCP bridge start failed.
    #[error("failed to start MCP bridge for server '{server}': {reason}")]
    McpBridgeFailed { server: String, reason: String },

    /// In-sandbox MCP server configuration failed.
    #[error("failed to configure in-sandbox MCP server '{server}': {reason}")]
    McpInSandboxFailed { server: String, reason: String },

    /// Port forward failed.
    #[error("failed to configure port forward '{spec}': {reason}")]
    PortForwardFailed { spec: String, reason: String },

    /// Resource limits failed.
    #[error("failed to apply resource limits: {reason}")]
    ResourceLimitsFailed { reason: String },

    /// File upload failed.
    #[error("failed to upload '{spec}': {reason}")]
    UploadFailed { spec: String, reason: String },

    /// Rollback encountered errors (reported as warnings alongside the original error).
    #[error("rollback completed with warnings: {warnings}")]
    RollbackWarnings { warnings: String },
}

/// Crate-level orchestration result type.
pub type OrchestrateResult<T> = Result<T, OrchestrateError>;

// ---------------------------------------------------------------------------
// Orchestration steps — tracked for rollback
// ---------------------------------------------------------------------------

/// A completed orchestration step that may need to be rolled back.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CompletedStep {
    /// Sandbox was created with the given name.
    SandboxCreated { name: String },
    /// Policy was applied to the sandbox.
    PolicyApplied { sandbox: String, policy: String },
    /// Provider was attached to the sandbox.
    ProviderAttached { sandbox: String, provider: String },
    /// MCP bridge was started (host-side daemon).
    McpBridgeStarted { sandbox: String, server: String },
    /// In-sandbox MCP server was configured.
    McpInSandboxConfigured { sandbox: String, server: String },
    /// Port forward was established.
    PortForwardEstablished { sandbox: String, spec: String },
    /// Resource limits were applied.
    ResourceLimitsApplied { sandbox: String },
    /// Files were uploaded.
    FilesUploaded { sandbox: String, spec: String },
    /// Streamable-HTTP MCP server was acknowledged (no host-side orchestration needed).
    StreamableHttpAcknowledged { sandbox: String, server: String, url: String },
}

impl fmt::Display for CompletedStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SandboxCreated { name } => write!(f, "sandbox '{name}' created"),
            Self::PolicyApplied { policy, .. } => write!(f, "policy '{policy}' applied"),
            Self::ProviderAttached { provider, .. } => {
                write!(f, "provider '{provider}' attached")
            }
            Self::McpBridgeStarted { server, .. } => {
                write!(f, "MCP bridge '{server}' started")
            }
            Self::McpInSandboxConfigured { server, .. } => {
                write!(f, "in-sandbox MCP server '{server}' configured")
            }
            Self::PortForwardEstablished { spec, .. } => {
                write!(f, "port forward '{spec}' established")
            }
            Self::ResourceLimitsApplied { .. } => write!(f, "resource limits applied"),
            Self::FilesUploaded { spec, .. } => write!(f, "files '{spec}' uploaded"),
            Self::StreamableHttpAcknowledged { server, url, .. } => {
                write!(f, "streamable-http MCP server '{server}' acknowledged at {url}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Orchestration plan — pure computation
// ---------------------------------------------------------------------------

/// An orchestration plan derived from a validated blueprint.
///
/// This is a pure-core structure: it describes WHAT to do without performing
/// any side effects. The orchestrator uses this plan to execute steps.
#[derive(Debug, Clone)]
pub struct OrchestrationPlan {
    /// Sandbox name (from metadata.name).
    pub sandbox_name: String,
    /// Container image reference.
    pub image: String,
    /// Optional policy file path.
    pub policy: Option<String>,
    /// Provider names to attach.
    pub providers: Vec<String>,
    /// MCP bridge servers to start (host-side).
    pub bridge_servers: Vec<McpBridgePlan>,
    /// MCP in-sandbox servers to configure.
    pub in_sandbox_servers: Vec<McpInSandboxPlan>,
    /// MCP streamable-http servers (acknowledged, no host-side orchestration).
    pub streamable_http_servers: Vec<McpStreamableHttpPlan>,
    /// Port forwards to establish.
    pub forwards: Vec<String>,
    /// Resource limits (cpu, memory).
    pub resources: Option<ResourcePlan>,
    /// Upload specs in `local:remote` format.
    pub uploads: Vec<String>,
}

/// Plan for starting an MCP bridge server.
#[derive(Debug, Clone)]
pub struct McpBridgePlan {
    /// Server name.
    pub name: String,
    /// Command to start the MCP server subprocess.
    pub command: String,
    /// Environment variable names for credential injection.
    pub env: Vec<String>,
}

/// Plan for configuring an in-sandbox MCP server.
#[derive(Debug, Clone)]
pub struct McpInSandboxPlan {
    /// Server name.
    pub name: String,
    /// Command to run inside the sandbox.
    pub command: String,
}

/// Plan for a streamable-HTTP MCP server (acknowledged, no host-side orchestration).
#[derive(Debug, Clone)]
pub struct McpStreamableHttpPlan {
    /// Server name.
    pub name: String,
    /// HTTP(S) endpoint URL.
    pub url: String,
}

/// Resource limits plan.
#[derive(Debug, Clone)]
pub struct ResourcePlan {
    /// CPU quantity in Kubernetes format.
    pub cpu: Option<String>,
    /// Memory quantity in Kubernetes format.
    pub memory: Option<String>,
}

// ---------------------------------------------------------------------------
// Plan builder (pure)
// ---------------------------------------------------------------------------

/// Build an orchestration plan from a validated blueprint.
///
/// This is a pure function: it extracts and organizes the blueprint fields
/// into a plan structure. The blueprint MUST have passed validation first.
///
/// # Errors
///
/// Returns `OrchestrateError::EmptyImage` if `spec.image` is missing or empty
/// (should not happen after validation, but defense in depth).
pub fn build_plan(blueprint: &Blueprint) -> OrchestrateResult<OrchestrationPlan> {
    let metadata = blueprint
        .metadata
        .as_ref()
        .ok_or_else(|| OrchestrateError::InvalidBlueprint {
            reason: "blueprint is missing required 'metadata' section".to_string(),
        })?;
    let spec = blueprint
        .spec
        .as_ref()
        .ok_or_else(|| OrchestrateError::InvalidBlueprint {
            reason: "blueprint is missing required 'spec' section".to_string(),
        })?;

    let sandbox_name = metadata
        .name
        .clone()
        .ok_or_else(|| OrchestrateError::InvalidBlueprint {
            reason: "metadata.name is required".to_string(),
        })?;

    let image = match &spec.image {
        Some(img) if !img.is_empty() => img.clone(),
        Some(_) | None => return Err(OrchestrateError::EmptyImage),
    };

    let policy = spec.policy.clone();
    let providers = spec.providers.clone().unwrap_or_default();
    let forwards = spec.forwards.clone().unwrap_or_default();
    let uploads = spec.upload.clone().unwrap_or_default();

    let resources = spec.resources.as_ref().map(|r| ResourcePlan {
        cpu: r.cpu.clone(),
        memory: r.memory.clone(),
    });

    let mut bridge_servers = Vec::new();
    let mut in_sandbox_servers = Vec::new();
    let mut streamable_http_servers = Vec::new();

    if let Some(servers) = &spec.mcp_servers {
        for server in servers {
            let name = server
                .name
                .clone()
                .ok_or_else(|| OrchestrateError::InvalidBlueprint {
                    reason: "mcp_servers[].name is required".to_string(),
                })?;
            let transport = server
                .transport
                .as_ref()
                .ok_or_else(|| OrchestrateError::InvalidBlueprint {
                    reason: format!("mcp_servers['{name}'].transport is required"),
                })?;

            match transport {
                McpTransport::Bridge => {
                    bridge_servers.push(McpBridgePlan {
                        name,
                        command: server
                            .command
                            .clone()
                            .ok_or_else(|| OrchestrateError::InvalidBlueprint {
                                reason: "bridge MCP server requires a 'command' field".to_string(),
                            })?,
                        env: server.env.clone().unwrap_or_default(),
                    });
                }
                McpTransport::InSandbox => {
                    in_sandbox_servers.push(McpInSandboxPlan {
                        name,
                        command: server
                            .command
                            .clone()
                            .ok_or_else(|| OrchestrateError::InvalidBlueprint {
                                reason: "in-sandbox MCP server requires a 'command' field".to_string(),
                            })?,
                    });
                }
                McpTransport::StreamableHttp => {
                    // BP-M004: track streamable-http servers in plan instead of silently dropping.
                    streamable_http_servers.push(McpStreamableHttpPlan {
                        name,
                        url: server
                            .url
                            .clone()
                            .ok_or_else(|| OrchestrateError::InvalidBlueprint {
                                reason: "streamable-http MCP server requires a 'url' field".to_string(),
                            })?,
                    });
                }
            }
        }
    }

    Ok(OrchestrationPlan {
        sandbox_name,
        image,
        policy,
        providers,
        bridge_servers,
        in_sandbox_servers,
        streamable_http_servers,
        forwards,
        resources,
        uploads,
    })
}

// ---------------------------------------------------------------------------
// Pre-creation validation (effectful — checks external resources)
// ---------------------------------------------------------------------------

/// Trait for external resource checks during pre-creation validation.
///
/// This trait abstracts the side effects (gateway API calls, file system checks)
/// so the orchestrator can be tested with mock implementations.
///
/// **Note:** This trait uses `async_fn_in_trait`, which requires `Sized` receivers.
/// It is not object-safe and cannot be used with `dyn` dispatch. This is intentional:
/// the orchestrator is generic over concrete validator types, and dynamic dispatch
/// is not needed.
#[allow(async_fn_in_trait)]
pub trait ResourceValidator {
    /// Check if an image can be pulled from the registry.
    async fn validate_image(&self, image: &str) -> OrchestrateResult<()>;

    /// Check if a provider exists in the gateway.
    async fn validate_provider(&self, provider: &str) -> OrchestrateResult<()>;

    /// Check if a policy file exists and is valid.
    async fn validate_policy(&self, path: &str) -> OrchestrateResult<()>;
}

/// Trait for sandbox lifecycle operations (effectful).
///
/// Abstracted for testing with mock implementations.
///
/// **Note:** This trait uses `async_fn_in_trait`, which requires `Sized` receivers.
/// It is not object-safe and cannot be used with `dyn` dispatch. This is intentional:
/// the orchestrator is generic over concrete gateway types, and dynamic dispatch
/// is not needed.
#[allow(async_fn_in_trait)]
pub trait SandboxGateway {
    /// Create a sandbox from an image.
    async fn create_sandbox(&self, name: &str, image: &str) -> OrchestrateResult<String>;

    /// Delete a sandbox.
    async fn delete_sandbox(&self, name: &str) -> OrchestrateResult<()>;

    /// Apply a policy to a sandbox.
    async fn apply_policy(&self, sandbox: &str, policy_path: &str) -> OrchestrateResult<()>;

    /// Attach a provider to a sandbox.
    async fn attach_provider(&self, sandbox: &str, provider: &str) -> OrchestrateResult<()>;

    /// Start an MCP bridge daemon for a sandbox.
    async fn start_mcp_bridge(
        &self,
        sandbox: &str,
        server_name: &str,
        command: &str,
        env: &[String],
    ) -> OrchestrateResult<()>;

    /// Stop an MCP bridge daemon.
    async fn stop_mcp_bridge(&self, sandbox: &str, server_name: &str) -> OrchestrateResult<()>;

    /// Configure an in-sandbox MCP server.
    async fn configure_in_sandbox_mcp(
        &self,
        sandbox: &str,
        server_name: &str,
        command: &str,
    ) -> OrchestrateResult<()>;

    /// Establish a port forward to a sandbox.
    async fn establish_port_forward(&self, sandbox: &str, spec: &str) -> OrchestrateResult<()>;

    /// Remove a port forward.
    async fn remove_port_forward(&self, sandbox: &str, spec: &str) -> OrchestrateResult<()>;

    /// Apply resource limits to a sandbox.
    async fn apply_resource_limits(
        &self,
        sandbox: &str,
        cpu: Option<&str>,
        memory: Option<&str>,
    ) -> OrchestrateResult<()>;

    /// Upload files to a sandbox.
    async fn upload_files(&self, sandbox: &str, spec: &str) -> OrchestrateResult<()>;
}

// ---------------------------------------------------------------------------
// Blueprint Orchestrator
// ---------------------------------------------------------------------------

/// Orchestrates the full sandbox creation lifecycle from a blueprint.
///
/// The orchestrator follows a strict sequence:
/// 1. Schema validation (pure)
/// 2. Pre-creation resource validation (effectful)
/// 3. Sandbox creation
/// 4. Policy application
/// 5. Provider attachment
/// 6. MCP bridge startup
/// 7. In-sandbox MCP configuration
/// 8. Port forward establishment
/// 9. Resource limit application
/// 10. File uploads
///
/// On failure at any step after sandbox creation, all completed steps
/// are rolled back in reverse order.
pub struct BlueprintOrchestrator<V: ResourceValidator, G: SandboxGateway> {
    validator: V,
    gateway: G,
}

impl<V: ResourceValidator + Sync, G: SandboxGateway + Sync> BlueprintOrchestrator<V, G> {
    /// Create a new orchestrator with the given validator and gateway.
    pub fn new(validator: V, gateway: G) -> Self {
        Self {
            validator,
            gateway,
        }
    }

    /// Execute the full blueprint orchestration.
    ///
    /// Returns the list of completed steps on success, or an error with
    /// rollback details on failure.
    pub async fn execute(&self, blueprint: &Blueprint) -> OrchestrateResult<Vec<CompletedStep>> {
        // Step 1: Schema validation (pure).
        tracing::info!("validating blueprint schema");
        let validation = crate::validate(blueprint);
        if !validation.errors.is_empty() {
            let details = validation
                .errors
                .iter()
                .map(|e| format!("  - {e}"))
                .collect::<Vec<_>>()
                .join("\n");
            return Err(OrchestrateError::ValidationFailed {
                count: validation.errors.len(),
                details,
            });
        }

        for warning in &validation.warnings {
            tracing::warn!(field = %warning.field, "{}", warning.message);
        }

        // Step 2: Build plan (pure).
        tracing::info!("building orchestration plan");
        let plan = build_plan(blueprint)?;

        // Step 3: Pre-creation resource validation (effectful).
        tracing::info!("validating external resources");
        self.validate_resources(&plan).await?;

        // Step 4: Execute plan with rollback on failure.
        tracing::info!(sandbox = %plan.sandbox_name, "executing orchestration plan");
        self.execute_plan(&plan).await
    }

    /// Validate all external resources referenced by the plan.
    async fn validate_resources(&self, plan: &OrchestrationPlan) -> OrchestrateResult<()> {
        // Validate image.
        tracing::info!(image = %plan.image, "validating image");
        self.validator.validate_image(&plan.image).await?;

        // Validate providers.
        for provider in &plan.providers {
            tracing::info!(provider = %provider, "validating provider");
            self.validator.validate_provider(provider).await?;
        }

        // Validate policy file.
        if let Some(ref policy) = plan.policy {
            tracing::info!(policy = %policy, "validating policy file");
            self.validator.validate_policy(policy).await?;
        }

        Ok(())
    }

    /// Execute the orchestration plan, rolling back on failure.
    async fn execute_plan(
        &self,
        plan: &OrchestrationPlan,
    ) -> OrchestrateResult<Vec<CompletedStep>> {
        let mut completed: Vec<CompletedStep> = Vec::new();

        // Helper macro to attempt a step and rollback on failure.
        macro_rules! step {
            ($expr:expr, $step:expr) => {
                match $expr.await {
                    Ok(()) => {
                        tracing::info!(step = %$step, "step completed");
                        completed.push($step);
                    }
                    Err(err) => {
                        tracing::error!(step = stringify!($expr), error = %err, "step failed, rolling back");
                        self.rollback(&completed).await;
                        return Err(err);
                    }
                }
            };
        }

        // Create sandbox.
        match self
            .gateway
            .create_sandbox(&plan.sandbox_name, &plan.image)
            .await
        {
            Ok(name) => {
                let s = CompletedStep::SandboxCreated { name };
                tracing::info!(step = %s, "step completed");
                completed.push(s);
            }
            Err(err) => {
                tracing::error!(error = %err, "sandbox creation failed");
                return Err(err);
            }
        }

        let sandbox = &plan.sandbox_name;

        // Apply policy.
        if let Some(ref policy) = plan.policy {
            step!(
                self.gateway.apply_policy(sandbox, policy),
                CompletedStep::PolicyApplied {
                    sandbox: sandbox.clone(),
                    policy: policy.clone(),
                }
            );
        }

        // Attach providers.
        for provider in &plan.providers {
            step!(
                self.gateway.attach_provider(sandbox, provider),
                CompletedStep::ProviderAttached {
                    sandbox: sandbox.clone(),
                    provider: provider.clone(),
                }
            );
        }

        // Start MCP bridges.
        for bridge in &plan.bridge_servers {
            step!(
                self.gateway
                    .start_mcp_bridge(sandbox, &bridge.name, &bridge.command, &bridge.env),
                CompletedStep::McpBridgeStarted {
                    sandbox: sandbox.clone(),
                    server: bridge.name.clone(),
                }
            );
        }

        // Configure in-sandbox MCP servers.
        for server in &plan.in_sandbox_servers {
            step!(
                self.gateway
                    .configure_in_sandbox_mcp(sandbox, &server.name, &server.command),
                CompletedStep::McpInSandboxConfigured {
                    sandbox: sandbox.clone(),
                    server: server.name.clone(),
                }
            );
        }

        // BP-M004: Acknowledge streamable-HTTP MCP servers (no host-side orchestration needed).
        for server in &plan.streamable_http_servers {
            tracing::info!(
                sandbox = %sandbox,
                server = %server.name,
                url = %server.url,
                "streamable-http MCP server acknowledged (no host-side orchestration needed)"
            );
            completed.push(CompletedStep::StreamableHttpAcknowledged {
                sandbox: sandbox.clone(),
                server: server.name.clone(),
                url: server.url.clone(),
            });
        }

        // Establish port forwards.
        for forward in &plan.forwards {
            step!(
                self.gateway.establish_port_forward(sandbox, forward),
                CompletedStep::PortForwardEstablished {
                    sandbox: sandbox.clone(),
                    spec: forward.clone(),
                }
            );
        }

        // Apply resource limits.
        if let Some(ref resources) = plan.resources {
            step!(
                self.gateway.apply_resource_limits(
                    sandbox,
                    resources.cpu.as_deref(),
                    resources.memory.as_deref(),
                ),
                CompletedStep::ResourceLimitsApplied {
                    sandbox: sandbox.clone(),
                }
            );
        }

        // Upload files.
        for upload in &plan.uploads {
            step!(
                self.gateway.upload_files(sandbox, upload),
                CompletedStep::FilesUploaded {
                    sandbox: sandbox.clone(),
                    spec: upload.clone(),
                }
            );
        }

        tracing::info!(
            sandbox = %sandbox,
            steps = completed.len(),
            "blueprint orchestration completed successfully"
        );

        Ok(completed)
    }

    /// Roll back completed steps in reverse order.
    ///
    /// Rollback is best-effort: failures are logged but do not prevent
    /// subsequent rollback steps from executing.
    async fn rollback(&self, completed: &[CompletedStep]) {
        if completed.is_empty() {
            return;
        }

        tracing::warn!(
            steps = completed.len(),
            "rolling back {} completed step(s)",
            completed.len()
        );

        for step in completed.iter().rev() {
            let result = match step {
                CompletedStep::SandboxCreated { name } => {
                    tracing::info!(sandbox = %name, "rollback: deleting sandbox");
                    self.gateway.delete_sandbox(name).await
                }
                CompletedStep::McpBridgeStarted { sandbox, server } => {
                    tracing::info!(sandbox = %sandbox, server = %server, "rollback: stopping MCP bridge");
                    self.gateway.stop_mcp_bridge(sandbox, server).await
                }
                CompletedStep::PortForwardEstablished { sandbox, spec } => {
                    tracing::info!(sandbox = %sandbox, spec = %spec, "rollback: removing port forward");
                    self.gateway.remove_port_forward(sandbox, spec).await
                }
                // Policy, providers, resource limits, uploads, in-sandbox MCP,
                // streamable-http: these are cleaned up when the sandbox is deleted.
                CompletedStep::PolicyApplied { .. }
                | CompletedStep::ProviderAttached { .. }
                | CompletedStep::McpInSandboxConfigured { .. }
                | CompletedStep::ResourceLimitsApplied { .. }
                | CompletedStep::FilesUploaded { .. }
                | CompletedStep::StreamableHttpAcknowledged { .. } => {
                    tracing::info!(step = %step, "rollback: cleaned up with sandbox deletion");
                    Ok(())
                }
            };

            if let Err(err) = result {
                tracing::error!(step = %step, error = %err, "rollback step failed (continuing)");
            }
        }

        tracing::info!("rollback completed");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::needless_raw_string_hashes)]
mod tests {
    use super::*;
    use crate::parse_blueprint;
    use std::sync::{Arc, Mutex};

    // -- Mock implementations --

    /// Records all calls for verification.
    #[derive(Debug, Default, Clone)]
    struct CallLog {
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl CallLog {
        fn log(&self, call: &str) {
            self.calls
                .lock()
                .expect("lock poisoned")
                .push(call.to_string());
        }

        fn calls(&self) -> Vec<String> {
            self.calls.lock().expect("lock poisoned").clone()
        }
    }

    /// Mock resource validator that always succeeds unless configured to fail.
    struct MockValidator {
        log: CallLog,
        /// If set, `validate_image` fails for this image name.
        fail_image: Option<String>,
        /// If set, `validate_provider` fails for this provider name.
        fail_provider: Option<String>,
        /// If set, `validate_policy` fails for this policy path.
        fail_policy: Option<String>,
    }

    impl MockValidator {
        fn new(log: CallLog) -> Self {
            Self {
                log,
                fail_image: None,
                fail_provider: None,
                fail_policy: None,
            }
        }
    }

    impl ResourceValidator for MockValidator {
        async fn validate_image(&self, image: &str) -> OrchestrateResult<()> {
            self.log.log(&format!("validate_image:{image}"));
            if self.fail_image.as_deref() == Some(image) {
                return Err(OrchestrateError::ImageNotFound {
                    image: image.to_string(),
                });
            }
            Ok(())
        }

        async fn validate_provider(&self, provider: &str) -> OrchestrateResult<()> {
            self.log.log(&format!("validate_provider:{provider}"));
            if self.fail_provider.as_deref() == Some(provider) {
                return Err(OrchestrateError::ProviderNotFound {
                    provider: provider.to_string(),
                });
            }
            Ok(())
        }

        async fn validate_policy(&self, path: &str) -> OrchestrateResult<()> {
            self.log.log(&format!("validate_policy:{path}"));
            if self.fail_policy.as_deref() == Some(path) {
                return Err(OrchestrateError::PolicyFileNotFound {
                    path: path.to_string(),
                });
            }
            Ok(())
        }
    }

    /// Mock sandbox gateway that records calls and optionally fails at specific steps.
    struct MockGateway {
        log: CallLog,
        /// If set, the named step will fail.
        fail_at: Option<String>,
    }

    impl MockGateway {
        fn new(log: CallLog) -> Self {
            Self {
                log,
                fail_at: None,
            }
        }

        fn check_fail(&self, step: &str) -> OrchestrateResult<()> {
            if self.fail_at.as_deref() == Some(step) {
                Err(OrchestrateError::McpBridgeFailed {
                    server: step.to_string(),
                    reason: "injected test failure".to_string(),
                })
            } else {
                Ok(())
            }
        }
    }

    impl SandboxGateway for MockGateway {
        async fn create_sandbox(&self, name: &str, image: &str) -> OrchestrateResult<String> {
            self.log.log(&format!("create_sandbox:{name}:{image}"));
            self.check_fail("create_sandbox")?;
            Ok(name.to_string())
        }

        async fn delete_sandbox(&self, name: &str) -> OrchestrateResult<()> {
            self.log.log(&format!("delete_sandbox:{name}"));
            Ok(())
        }

        async fn apply_policy(&self, sandbox: &str, policy_path: &str) -> OrchestrateResult<()> {
            self.log
                .log(&format!("apply_policy:{sandbox}:{policy_path}"));
            self.check_fail("apply_policy")?;
            Ok(())
        }

        async fn attach_provider(&self, sandbox: &str, provider: &str) -> OrchestrateResult<()> {
            self.log
                .log(&format!("attach_provider:{sandbox}:{provider}"));
            self.check_fail(&format!("attach_provider:{provider}"))?;
            Ok(())
        }

        async fn start_mcp_bridge(
            &self,
            sandbox: &str,
            server_name: &str,
            command: &str,
            env: &[String],
        ) -> OrchestrateResult<()> {
            self.log.log(&format!(
                "start_mcp_bridge:{sandbox}:{server_name}:{command}:{}",
                env.join(",")
            ));
            self.check_fail(&format!("start_mcp_bridge:{server_name}"))?;
            Ok(())
        }

        async fn stop_mcp_bridge(
            &self,
            sandbox: &str,
            server_name: &str,
        ) -> OrchestrateResult<()> {
            self.log
                .log(&format!("stop_mcp_bridge:{sandbox}:{server_name}"));
            Ok(())
        }

        async fn configure_in_sandbox_mcp(
            &self,
            sandbox: &str,
            server_name: &str,
            command: &str,
        ) -> OrchestrateResult<()> {
            self.log.log(&format!(
                "configure_in_sandbox_mcp:{sandbox}:{server_name}:{command}"
            ));
            self.check_fail(&format!("configure_in_sandbox_mcp:{server_name}"))?;
            Ok(())
        }

        async fn establish_port_forward(
            &self,
            sandbox: &str,
            spec: &str,
        ) -> OrchestrateResult<()> {
            self.log
                .log(&format!("establish_port_forward:{sandbox}:{spec}"));
            self.check_fail(&format!("establish_port_forward:{spec}"))?;
            Ok(())
        }

        async fn remove_port_forward(
            &self,
            sandbox: &str,
            spec: &str,
        ) -> OrchestrateResult<()> {
            self.log
                .log(&format!("remove_port_forward:{sandbox}:{spec}"));
            Ok(())
        }

        async fn apply_resource_limits(
            &self,
            sandbox: &str,
            cpu: Option<&str>,
            memory: Option<&str>,
        ) -> OrchestrateResult<()> {
            self.log.log(&format!(
                "apply_resource_limits:{sandbox}:{}:{}",
                cpu.unwrap_or("none"),
                memory.unwrap_or("none")
            ));
            self.check_fail("apply_resource_limits")?;
            Ok(())
        }

        async fn upload_files(&self, sandbox: &str, spec: &str) -> OrchestrateResult<()> {
            self.log.log(&format!("upload_files:{sandbox}:{spec}"));
            self.check_fail(&format!("upload_files:{spec}"))?;
            Ok(())
        }
    }

    // -- Helper YAML blueprints --

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
    // AC-001: Blueprint orchestrates full sandbox creation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_blueprint_creates_sandbox_with_all_sections() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_ok(), "orchestration should succeed: {result:?}");

        let steps = result.expect("should succeed");
        assert!(
            steps
                .iter()
                .any(|s| matches!(s, CompletedStep::SandboxCreated { name } if name == "my-dev-sandbox")),
            "should have created sandbox"
        );
        assert!(
            steps
                .iter()
                .any(|s| matches!(s, CompletedStep::PolicyApplied { policy, .. } if policy == "policies/dev.yaml")),
            "should have applied policy"
        );
        assert!(
            steps
                .iter()
                .any(|s| matches!(s, CompletedStep::ProviderAttached { provider, .. } if provider == "github")),
            "should have attached github provider"
        );
        assert!(
            steps
                .iter()
                .any(|s| matches!(s, CompletedStep::ProviderAttached { provider, .. } if provider == "openai")),
            "should have attached openai provider"
        );
        assert!(
            steps
                .iter()
                .any(|s| matches!(s, CompletedStep::McpBridgeStarted { server, .. } if server == "code-assist")),
            "should have started MCP bridge"
        );
        assert!(
            steps
                .iter()
                .any(|s| matches!(s, CompletedStep::McpInSandboxConfigured { server, .. } if server == "local-tools")),
            "should have configured in-sandbox MCP"
        );
        assert!(
            steps
                .iter()
                .any(|s| matches!(s, CompletedStep::ResourceLimitsApplied { .. })),
            "should have applied resource limits"
        );

        let calls = log.calls();
        // Verify orchestration order: validate -> create -> policy -> providers -> bridges -> ...
        let create_idx = calls
            .iter()
            .position(|c| c.starts_with("create_sandbox"))
            .expect("create_sandbox call");
        let policy_idx = calls
            .iter()
            .position(|c| c.starts_with("apply_policy"))
            .expect("apply_policy call");
        let provider_idx = calls
            .iter()
            .position(|c| c.starts_with("attach_provider"))
            .expect("attach_provider call");
        let bridge_idx = calls
            .iter()
            .position(|c| c.starts_with("start_mcp_bridge"))
            .expect("start_mcp_bridge call");

        assert!(
            create_idx < policy_idx,
            "sandbox created before policy applied"
        );
        assert!(
            policy_idx < provider_idx,
            "policy applied before providers attached"
        );
        assert!(
            provider_idx < bridge_idx,
            "providers attached before bridges started"
        );
    }

    // -----------------------------------------------------------------------
    // AC-002: MCP bridge servers started from blueprint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_blueprint_starts_mcp_bridge_servers() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;
        assert!(result.is_ok());

        let calls = log.calls();
        let bridge_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.starts_with("start_mcp_bridge"))
            .collect();
        assert_eq!(
            bridge_calls.len(),
            1,
            "should start exactly one bridge server"
        );
        assert!(
            bridge_calls[0].contains("code-assist"),
            "bridge should be for code-assist server"
        );
        assert!(
            bridge_calls[0].contains("npx @modelcontextprotocol/server-code"),
            "bridge should use correct command"
        );
        assert!(
            bridge_calls[0].contains("GITHUB_TOKEN"),
            "bridge should pass env vars"
        );
    }

    // -----------------------------------------------------------------------
    // AC-003: In-sandbox MCP servers configured from blueprint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_blueprint_configures_in_sandbox_mcp() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;
        assert!(result.is_ok());

        let calls = log.calls();
        let in_sandbox_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.starts_with("configure_in_sandbox_mcp"))
            .collect();
        assert_eq!(
            in_sandbox_calls.len(),
            1,
            "should configure exactly one in-sandbox server"
        );
        assert!(
            in_sandbox_calls[0].contains("local-tools"),
            "should configure local-tools"
        );
        assert!(
            in_sandbox_calls[0].contains("/usr/local/bin/mcp-tools"),
            "should use correct command"
        );
    }

    // -----------------------------------------------------------------------
    // AC-004: Resource limits applied from blueprint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_blueprint_applies_resource_limits() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;
        assert!(result.is_ok());

        let calls = log.calls();
        let resource_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.starts_with("apply_resource_limits"))
            .collect();
        assert_eq!(resource_calls.len(), 1, "should apply resource limits once");
        assert!(resource_calls[0].contains(":2:"), "should set cpu to 2");
        assert!(
            resource_calls[0].contains("4Gi"),
            "should set memory to 4Gi"
        );
    }

    // -----------------------------------------------------------------------
    // AC-005: Files uploaded from blueprint
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_blueprint_uploads_files() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;
        assert!(result.is_ok());

        let calls = log.calls();
        let upload_calls: Vec<_> = calls
            .iter()
            .filter(|c| c.starts_with("upload_files"))
            .collect();
        assert_eq!(upload_calls.len(), 2, "should upload two file specs");
        assert!(
            upload_calls[0].contains("./src:~/project/src"),
            "should upload src"
        );
        assert!(
            upload_calls[1].contains("./config:~/project/config"),
            "should upload config"
        );
    }

    // -----------------------------------------------------------------------
    // AC-006: All resources validated before creation
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_blueprint_validates_all_resources_before_creation() {
        let log = CallLog::default();
        let mut validator = MockValidator::new(log.clone());
        validator.fail_image = Some("ubuntu:22.04".to_string());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(minimal_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err(), "should fail when image validation fails");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("not found"),
            "error should mention image not found: {err}"
        );

        // Verify no sandbox was created.
        let calls = log.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("create_sandbox")),
            "should not create sandbox when pre-validation fails"
        );
    }

    #[tokio::test]
    async fn test_blueprint_validates_provider_before_creation() {
        let log = CallLog::default();
        let mut validator = MockValidator::new(log.clone());
        validator.fail_provider = Some("github".to_string());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err(), "should fail when provider validation fails");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Provider 'github' not found"),
            "error should mention missing provider: {err}"
        );

        // Verify no sandbox was created.
        let calls = log.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("create_sandbox")),
            "should not create sandbox when pre-validation fails"
        );
    }

    #[tokio::test]
    async fn test_blueprint_validates_policy_before_creation() {
        let log = CallLog::default();
        let mut validator = MockValidator::new(log.clone());
        validator.fail_policy = Some("policies/dev.yaml".to_string());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err(), "should fail when policy validation fails");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Policy file"),
            "error should mention policy file: {err}"
        );

        let calls = log.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("create_sandbox")),
            "should not create sandbox when pre-validation fails"
        );
    }

    // -----------------------------------------------------------------------
    // AC-007: Partial creation is rolled back on failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_blueprint_rolls_back_on_partial_failure() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let mut gateway = MockGateway::new(log.clone());
        // Fail when starting the MCP bridge.
        gateway.fail_at = Some("start_mcp_bridge:code-assist".to_string());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err(), "should fail when MCP bridge fails");

        let calls = log.calls();
        // Verify sandbox was created (before the failure).
        assert!(
            calls.iter().any(|c| c.starts_with("create_sandbox")),
            "sandbox should have been created before failure"
        );
        // Verify rollback: sandbox deleted.
        assert!(
            calls.iter().any(|c| c.starts_with("delete_sandbox")),
            "sandbox should be deleted during rollback"
        );
    }

    #[tokio::test]
    async fn test_blueprint_rollback_cleans_up_bridges_and_sandbox() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());

        // Use a blueprint with two bridges, fail on the second one.
        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: rollback-test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: server-a
      transport: bridge
      command: npx server-a
    - name: server-b
      transport: bridge
      command: npx server-b
"#;

        let mut gateway = MockGateway::new(log.clone());
        gateway.fail_at = Some("start_mcp_bridge:server-b".to_string());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(yaml).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err());

        let calls = log.calls();
        // server-a bridge was started and should be stopped during rollback.
        assert!(
            calls
                .iter()
                .any(|c| c == "stop_mcp_bridge:rollback-test:server-a"),
            "should stop server-a bridge during rollback: {calls:?}"
        );
        // sandbox should be deleted.
        assert!(
            calls
                .iter()
                .any(|c| c == "delete_sandbox:rollback-test"),
            "should delete sandbox during rollback: {calls:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Minimal blueprint (only image) creates sandbox equivalently (VP-003)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_minimal_blueprint_creates_sandbox() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(minimal_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(
            result.is_ok(),
            "minimal blueprint should succeed: {result:?}"
        );

        let steps = result.expect("should succeed");
        assert_eq!(
            steps.len(),
            1,
            "minimal blueprint should only create sandbox"
        );
        assert!(
            matches!(&steps[0], CompletedStep::SandboxCreated { name } if name == "minimal"),
            "should create sandbox named 'minimal'"
        );

        let calls = log.calls();
        // Should validate image and create sandbox, nothing else.
        assert!(calls.iter().any(|c| c.starts_with("validate_image")));
        assert!(calls.iter().any(|c| c.starts_with("create_sandbox")));
        assert!(
            !calls.iter().any(|c| c.starts_with("apply_policy")),
            "should not apply policy for minimal blueprint"
        );
        assert!(
            !calls.iter().any(|c| c.starts_with("attach_provider")),
            "should not attach providers for minimal blueprint"
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases: EC-009 (image not found)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ec009_image_not_found_actionable_error() {
        let log = CallLog::default();
        let mut validator = MockValidator::new(log.clone());
        validator.fail_image = Some("ghcr.io/x/y:z".to_string());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: bad-image
spec:
  image: ghcr.io/x/y:z
"#;
        let blueprint = parse_blueprint(yaml).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("ghcr.io/x/y:z"),
            "error should include image ref: {msg}"
        );
        assert!(
            msg.contains("not found"),
            "error should say not found: {msg}"
        );
        assert!(
            msg.contains("Check registry access"),
            "error should include fix suggestion: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases: EC-010 (provider not found)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_ec010_provider_not_found_actionable_error() {
        let log = CallLog::default();
        let mut validator = MockValidator::new(log.clone());
        validator.fail_provider = Some("github".to_string());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: bad-provider
spec:
  image: ubuntu:22.04
  providers:
    - github
"#;
        let blueprint = parse_blueprint(yaml).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Provider 'github' not found"),
            "error should name missing provider: {msg}"
        );
        assert!(
            msg.contains("darkshell provider create"),
            "error should include fix command: {msg}"
        );
    }

    // -----------------------------------------------------------------------
    // Schema validation failure prevents any side effects
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_schema_validation_failure_prevents_side_effects() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        // Missing apiVersion, kind, spec.image — multiple errors.
        let yaml = r#"
metadata:
  name: broken
spec:
  providers:
    - github
"#;
        let blueprint = parse_blueprint(yaml).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("validation failed"),
            "should report validation failure: {err}"
        );

        // No external calls should have been made.
        let calls = log.calls();
        assert!(
            calls.is_empty(),
            "no external calls when schema validation fails: {calls:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Plan building tests (pure)
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_plan_full_blueprint() {
        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let plan = build_plan(&blueprint).expect("build plan");

        assert_eq!(plan.sandbox_name, "my-dev-sandbox");
        assert_eq!(plan.image, "ubuntu:22.04");
        assert_eq!(plan.policy, Some("policies/dev.yaml".to_string()));
        assert_eq!(plan.providers, vec!["github", "openai"]);
        assert_eq!(plan.bridge_servers.len(), 1);
        assert_eq!(plan.bridge_servers[0].name, "code-assist");
        assert_eq!(plan.in_sandbox_servers.len(), 1);
        assert_eq!(plan.in_sandbox_servers[0].name, "local-tools");
        assert_eq!(plan.forwards, vec!["8080", "127.0.0.1:3000"]);
        assert!(plan.resources.is_some());
        let resources = plan.resources.as_ref().expect("resources");
        assert_eq!(resources.cpu, Some("2".to_string()));
        assert_eq!(resources.memory, Some("4Gi".to_string()));
        assert_eq!(
            plan.uploads,
            vec!["./src:~/project/src", "./config:~/project/config"]
        );
    }

    #[test]
    fn test_build_plan_minimal_blueprint() {
        let blueprint = parse_blueprint(minimal_blueprint_yaml()).expect("parse");
        let plan = build_plan(&blueprint).expect("build plan");

        assert_eq!(plan.sandbox_name, "minimal");
        assert_eq!(plan.image, "ubuntu:22.04");
        assert!(plan.policy.is_none());
        assert!(plan.providers.is_empty());
        assert!(plan.bridge_servers.is_empty());
        assert!(plan.in_sandbox_servers.is_empty());
        assert!(plan.forwards.is_empty());
        assert!(plan.resources.is_none());
        assert!(plan.uploads.is_empty());
    }

    // -----------------------------------------------------------------------
    // Orchestration order is deterministic
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_orchestration_order_is_deterministic() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let gateway = MockGateway::new(log.clone());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let _ = orchestrator.execute(&blueprint).await;

        let calls = log.calls();
        let step_prefixes: Vec<&str> = calls
            .iter()
            .filter_map(|c| {
                if c.starts_with("validate_") {
                    Some("validate")
                } else if c.starts_with("create_sandbox") {
                    Some("create_sandbox")
                } else if c.starts_with("apply_policy") {
                    Some("apply_policy")
                } else if c.starts_with("attach_provider") {
                    Some("attach_provider")
                } else if c.starts_with("start_mcp_bridge") {
                    Some("start_mcp_bridge")
                } else if c.starts_with("configure_in_sandbox_mcp") {
                    Some("configure_in_sandbox_mcp")
                } else if c.starts_with("establish_port_forward") {
                    Some("establish_port_forward")
                } else if c.starts_with("apply_resource_limits") {
                    Some("apply_resource_limits")
                } else if c.starts_with("upload_files") {
                    Some("upload_files")
                } else {
                    None
                }
            })
            .collect();

        // Expected order: validate* -> create -> policy -> providers -> bridges ->
        //                 in_sandbox -> forwards -> resources -> uploads
        let expected_order = [
            "validate",    // validate_image
            "validate",    // validate_provider (github)
            "validate",    // validate_provider (openai)
            "validate",    // validate_policy
            "create_sandbox",
            "apply_policy",
            "attach_provider",
            "attach_provider",
            "start_mcp_bridge",
            "configure_in_sandbox_mcp",
            "establish_port_forward",
            "establish_port_forward",
            "apply_resource_limits",
            "upload_files",
            "upload_files",
        ];

        assert_eq!(
            step_prefixes, expected_order,
            "orchestration order must match expected sequence"
        );
    }

    // -----------------------------------------------------------------------
    // Rollback does not run when sandbox creation itself fails
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_no_rollback_when_sandbox_creation_fails() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let mut gateway = MockGateway::new(log.clone());
        gateway.fail_at = Some("create_sandbox".to_string());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(minimal_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err());

        let calls = log.calls();
        assert!(
            !calls.iter().any(|c| c.starts_with("delete_sandbox")),
            "should not try to delete sandbox that was never created"
        );
    }

    // -----------------------------------------------------------------------
    // Rollback on port forward failure
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rollback_on_port_forward_failure() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let mut gateway = MockGateway::new(log.clone());
        gateway.fail_at = Some("establish_port_forward:127.0.0.1:3000".to_string());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err());

        let calls = log.calls();
        // First port forward (8080) should succeed and be rolled back.
        assert!(
            calls
                .iter()
                .any(|c| c == "remove_port_forward:my-dev-sandbox:8080"),
            "should remove first port forward during rollback: {calls:?}"
        );
        // MCP bridge should be stopped.
        assert!(
            calls
                .iter()
                .any(|c| c == "stop_mcp_bridge:my-dev-sandbox:code-assist"),
            "should stop bridge during rollback: {calls:?}"
        );
        // Sandbox should be deleted.
        assert!(
            calls
                .iter()
                .any(|c| c == "delete_sandbox:my-dev-sandbox"),
            "should delete sandbox during rollback: {calls:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Upload failure triggers rollback
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_rollback_on_upload_failure() {
        let log = CallLog::default();
        let validator = MockValidator::new(log.clone());
        let mut gateway = MockGateway::new(log.clone());
        gateway.fail_at = Some("upload_files:./config:~/project/config".to_string());
        let orchestrator = BlueprintOrchestrator::new(validator, gateway);

        let blueprint = parse_blueprint(full_blueprint_yaml()).expect("parse");
        let result = orchestrator.execute(&blueprint).await;

        assert!(result.is_err());

        let calls = log.calls();
        assert!(
            calls.iter().any(|c| c.starts_with("delete_sandbox")),
            "should delete sandbox on upload failure"
        );
    }
}
