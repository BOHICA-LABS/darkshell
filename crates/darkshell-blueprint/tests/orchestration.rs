//! WF-4 integration tests: blueprint orchestration with mock implementations.

use darkshell_blueprint::orchestrator::{
    BlueprintOrchestrator, CompletedStep, OrchestrateError, OrchestrateResult, ResourceValidator,
    SandboxGateway,
};
use darkshell_blueprint::parse_blueprint;
use std::sync::{Arc, Mutex};

// ---------------------------------------------------------------------------
// Mock implementations
// ---------------------------------------------------------------------------

/// Records all calls for step-order verification.
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

    fn entries(&self) -> Vec<String> {
        self.calls.lock().expect("lock poisoned").clone()
    }
}

/// Mock validator that always succeeds.
#[derive(Clone)]
struct MockValidator {
    log: CallLog,
}

impl MockValidator {
    fn new(log: CallLog) -> Self {
        Self { log }
    }
}

impl ResourceValidator for MockValidator {
    async fn validate_image(&self, image: &str) -> OrchestrateResult<()> {
        self.log.log(&format!("validate_image:{image}"));
        Ok(())
    }

    async fn validate_provider(&self, provider: &str) -> OrchestrateResult<()> {
        self.log.log(&format!("validate_provider:{provider}"));
        Ok(())
    }

    async fn validate_policy(&self, path: &str) -> OrchestrateResult<()> {
        self.log.log(&format!("validate_policy:{path}"));
        Ok(())
    }
}

/// Mock gateway that tracks steps and optionally fails at a named step.
#[derive(Clone)]
struct MockGateway {
    log: CallLog,
    fail_at_step: Option<String>,
}

impl MockGateway {
    fn new(log: CallLog) -> Self {
        Self {
            log,
            fail_at_step: None,
        }
    }

    fn failing_at(log: CallLog, step: &str) -> Self {
        Self {
            log,
            fail_at_step: Some(step.to_string()),
        }
    }

    fn should_fail(&self, step: &str) -> OrchestrateResult<()> {
        if self.fail_at_step.as_deref() == Some(step) {
            Err(OrchestrateError::SandboxCreateFailed {
                reason: format!("mock failure at {step}"),
            })
        } else {
            Ok(())
        }
    }
}

impl SandboxGateway for MockGateway {
    async fn create_sandbox(&self, name: &str, image: &str) -> OrchestrateResult<String> {
        self.log.log(&format!("create_sandbox:{name}:{image}"));
        self.should_fail("create_sandbox")?;
        Ok(name.to_string())
    }

    async fn delete_sandbox(&self, name: &str) -> OrchestrateResult<()> {
        self.log.log(&format!("delete_sandbox:{name}"));
        Ok(())
    }

    async fn apply_policy(&self, sandbox: &str, policy_path: &str) -> OrchestrateResult<()> {
        self.log
            .log(&format!("apply_policy:{sandbox}:{policy_path}"));
        self.should_fail("apply_policy")?;
        Ok(())
    }

    async fn attach_provider(&self, sandbox: &str, provider: &str) -> OrchestrateResult<()> {
        self.log
            .log(&format!("attach_provider:{sandbox}:{provider}"));
        self.should_fail("attach_provider")?;
        Ok(())
    }

    async fn start_mcp_bridge(
        &self,
        sandbox: &str,
        server_name: &str,
        command: &str,
        _env: &[String],
    ) -> OrchestrateResult<()> {
        self.log.log(&format!(
            "start_mcp_bridge:{sandbox}:{server_name}:{command}"
        ));
        self.should_fail("start_mcp_bridge")?;
        Ok(())
    }

    async fn stop_mcp_bridge(&self, sandbox: &str, server_name: &str) -> OrchestrateResult<()> {
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
        self.should_fail("configure_in_sandbox_mcp")?;
        Ok(())
    }

    async fn establish_port_forward(&self, sandbox: &str, spec: &str) -> OrchestrateResult<()> {
        self.log
            .log(&format!("establish_port_forward:{sandbox}:{spec}"));
        self.should_fail("establish_port_forward")?;
        Ok(())
    }

    async fn remove_port_forward(&self, sandbox: &str, spec: &str) -> OrchestrateResult<()> {
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
            "apply_resource_limits:{sandbox}:cpu={cpu:?}:memory={memory:?}"
        ));
        self.should_fail("apply_resource_limits")?;
        Ok(())
    }

    async fn upload_files(&self, sandbox: &str, spec: &str) -> OrchestrateResult<()> {
        self.log.log(&format!("upload_files:{sandbox}:{spec}"));
        self.should_fail("upload_files")?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helper: full factory blueprint YAML
// ---------------------------------------------------------------------------

fn full_factory_yaml() -> &'static str {
    r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: factory-sandbox
spec:
  image: ghcr.io/org/factory:latest
  policy: policies/default.yaml
  providers:
    - github
  mcp_servers:
    - name: tally
      transport: bridge
      command: mcp-tally
      env:
        - GITHUB_TOKEN
    - name: local-tools
      transport: in-sandbox
      command: /usr/local/bin/mcp-tools
  forwards:
    - "8080"
  resources:
    cpu: "2"
    memory: 4Gi
  upload:
    - src:/workspace/src
"#
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_full_orchestration_happy_path() {
    let log = CallLog::default();
    let validator = MockValidator::new(log.clone());
    let gateway = MockGateway::new(log.clone());
    let orchestrator = BlueprintOrchestrator::new(validator, gateway);

    let blueprint = parse_blueprint(full_factory_yaml()).expect("valid YAML");
    let steps = orchestrator
        .execute(&blueprint)
        .await
        .expect("orchestration should succeed");

    // All expected step types should be present.
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, CompletedStep::SandboxCreated { .. })),
        "should have created sandbox"
    );
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, CompletedStep::PolicyApplied { .. })),
        "should have applied policy"
    );
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, CompletedStep::ProviderAttached { .. })),
        "should have attached provider"
    );
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, CompletedStep::McpBridgeStarted { .. })),
        "should have started MCP bridge"
    );
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, CompletedStep::McpInSandboxConfigured { .. })),
        "should have configured in-sandbox MCP"
    );
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, CompletedStep::PortForwardEstablished { .. })),
        "should have established port forward"
    );
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, CompletedStep::ResourceLimitsApplied { .. })),
        "should have applied resource limits"
    );
    assert!(
        steps
            .iter()
            .any(|s| matches!(s, CompletedStep::FilesUploaded { .. })),
        "should have uploaded files"
    );

    // Verify gateway calls were made (validate + execute).
    let entries = log.entries();
    assert!(
        entries.iter().any(|e| e.starts_with("validate_image:")),
        "should validate image"
    );
    assert!(
        entries.iter().any(|e| e.starts_with("create_sandbox:")),
        "should create sandbox"
    );
}

#[tokio::test]
async fn test_orchestration_validates_before_executing() {
    let log = CallLog::default();
    let validator = MockValidator::new(log.clone());
    let gateway = MockGateway::new(log.clone());
    let orchestrator = BlueprintOrchestrator::new(validator, gateway);

    // Blueprint missing image (spec exists but image is absent).
    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: bad-sandbox
spec:
  providers:
    - github
"#;
    let blueprint = parse_blueprint(yaml).expect("valid YAML syntax");
    let err = orchestrator.execute(&blueprint).await.unwrap_err();

    assert!(
        matches!(err, OrchestrateError::ValidationFailed { .. }),
        "expected ValidationFailed, got: {err}"
    );

    // No gateway calls should have been made.
    let entries = log.entries();
    assert!(
        !entries.iter().any(|e| e.starts_with("create_sandbox:")),
        "should not have created sandbox on validation failure"
    );
}

#[tokio::test]
async fn test_orchestration_rollback_on_mcp_failure() {
    let log = CallLog::default();
    let validator = MockValidator::new(log.clone());
    let gateway = MockGateway::failing_at(log.clone(), "start_mcp_bridge");
    let orchestrator = BlueprintOrchestrator::new(validator, gateway);

    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: rollback-test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: failing-bridge
      transport: bridge
      command: mcp-server
"#;
    let blueprint = parse_blueprint(yaml).expect("valid YAML");
    let err = orchestrator.execute(&blueprint).await.unwrap_err();

    assert!(
        matches!(err, OrchestrateError::SandboxCreateFailed { .. }),
        "expected failure from mock, got: {err}"
    );

    // Sandbox should have been cleaned up via rollback.
    let entries = log.entries();
    assert!(
        entries.iter().any(|e| e.starts_with("create_sandbox:")),
        "sandbox should have been created before failure"
    );
    assert!(
        entries.iter().any(|e| e.starts_with("delete_sandbox:")),
        "sandbox should have been deleted during rollback"
    );
}

#[tokio::test]
async fn test_orchestration_rollback_on_upload_failure() {
    let log = CallLog::default();
    let validator = MockValidator::new(log.clone());
    let gateway = MockGateway::failing_at(log.clone(), "upload_files");
    let orchestrator = BlueprintOrchestrator::new(validator, gateway);

    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: upload-fail-test
spec:
  image: ubuntu:22.04
  mcp_servers:
    - name: bridge-server
      transport: bridge
      command: mcp-server
  upload:
    - src:/workspace/src
"#;
    let blueprint = parse_blueprint(yaml).expect("valid YAML");
    let err = orchestrator.execute(&blueprint).await.unwrap_err();

    assert!(
        matches!(err, OrchestrateError::SandboxCreateFailed { .. }),
        "expected failure from mock, got: {err}"
    );

    let entries = log.entries();
    // MCP bridge was started and should be stopped during rollback.
    assert!(
        entries.iter().any(|e| e.starts_with("start_mcp_bridge:")),
        "MCP bridge should have been started before upload failure"
    );
    assert!(
        entries.iter().any(|e| e.starts_with("stop_mcp_bridge:")),
        "MCP bridge should have been stopped during rollback"
    );
    // Sandbox should be deleted.
    assert!(
        entries.iter().any(|e| e.starts_with("delete_sandbox:")),
        "sandbox should be deleted during rollback"
    );
}

#[tokio::test]
async fn test_minimal_blueprint_only_creates_sandbox() {
    let log = CallLog::default();
    let validator = MockValidator::new(log.clone());
    let gateway = MockGateway::new(log.clone());
    let orchestrator = BlueprintOrchestrator::new(validator, gateway);

    let yaml = r#"
apiVersion: darkshell/v1
kind: Blueprint
metadata:
  name: minimal
spec:
  image: ubuntu:22.04
"#;
    let blueprint = parse_blueprint(yaml).expect("valid YAML");
    let steps = orchestrator
        .execute(&blueprint)
        .await
        .expect("orchestration should succeed");

    // Only sandbox creation should have completed.
    assert_eq!(
        steps.len(),
        1,
        "minimal blueprint should produce exactly 1 step"
    );
    assert!(
        matches!(&steps[0], CompletedStep::SandboxCreated { name } if name == "minimal"),
        "the single step should be SandboxCreated"
    );

    // No policy, provider, MCP, forward, resource, or upload calls.
    let entries = log.entries();
    assert!(
        !entries.iter().any(|e| e.starts_with("apply_policy:")),
        "no policy should be applied"
    );
    assert!(
        !entries.iter().any(|e| e.starts_with("attach_provider:")),
        "no provider should be attached"
    );
    assert!(
        !entries.iter().any(|e| e.starts_with("start_mcp_bridge:")),
        "no MCP bridge should be started"
    );
    assert!(
        !entries.iter().any(|e| e.starts_with("upload_files:")),
        "no files should be uploaded"
    );
}

#[tokio::test]
async fn test_orchestration_step_order() {
    let log = CallLog::default();
    let validator = MockValidator::new(log.clone());
    let gateway = MockGateway::new(log.clone());
    let orchestrator = BlueprintOrchestrator::new(validator, gateway);

    let blueprint = parse_blueprint(full_factory_yaml()).expect("valid YAML");
    orchestrator
        .execute(&blueprint)
        .await
        .expect("orchestration should succeed");

    let entries = log.entries();

    // Find indices of key steps to verify ordering.
    let find_idx = |prefix: &str| -> usize {
        entries
            .iter()
            .position(|e| e.starts_with(prefix))
            .unwrap_or_else(|| panic!("expected entry starting with '{prefix}'"))
    };

    let validate_image_idx = find_idx("validate_image:");
    let validate_provider_idx = find_idx("validate_provider:");
    let validate_policy_idx = find_idx("validate_policy:");
    let create_sandbox_idx = find_idx("create_sandbox:");
    let apply_policy_idx = find_idx("apply_policy:");
    let attach_provider_idx = find_idx("attach_provider:");
    let start_mcp_bridge_idx = find_idx("start_mcp_bridge:");
    let configure_in_sandbox_mcp_idx = find_idx("configure_in_sandbox_mcp:");
    let establish_port_forward_idx = find_idx("establish_port_forward:");
    let apply_resource_limits_idx = find_idx("apply_resource_limits:");
    let upload_files_idx = find_idx("upload_files:");

    // Validation before creation.
    assert!(
        validate_image_idx < create_sandbox_idx,
        "validate_image must precede create_sandbox"
    );
    assert!(
        validate_provider_idx < create_sandbox_idx,
        "validate_provider must precede create_sandbox"
    );
    assert!(
        validate_policy_idx < create_sandbox_idx,
        "validate_policy must precede create_sandbox"
    );

    // Creation before everything else.
    assert!(
        create_sandbox_idx < apply_policy_idx,
        "create_sandbox must precede apply_policy"
    );
    assert!(
        create_sandbox_idx < attach_provider_idx,
        "create_sandbox must precede attach_provider"
    );

    // Policy and providers before MCP bridges.
    assert!(
        apply_policy_idx < start_mcp_bridge_idx,
        "apply_policy must precede start_mcp_bridge"
    );
    assert!(
        attach_provider_idx < start_mcp_bridge_idx,
        "attach_provider must precede start_mcp_bridge"
    );

    // MCP bridges before in-sandbox MCP.
    assert!(
        start_mcp_bridge_idx < configure_in_sandbox_mcp_idx,
        "start_mcp_bridge must precede configure_in_sandbox_mcp"
    );

    // In-sandbox MCP before port forwards.
    assert!(
        configure_in_sandbox_mcp_idx < establish_port_forward_idx,
        "configure_in_sandbox_mcp must precede establish_port_forward"
    );

    // Port forwards before resource limits.
    assert!(
        establish_port_forward_idx < apply_resource_limits_idx,
        "establish_port_forward must precede apply_resource_limits"
    );

    // Resource limits before uploads.
    assert!(
        apply_resource_limits_idx < upload_files_idx,
        "apply_resource_limits must precede upload_files"
    );
}
