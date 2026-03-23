// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Credential retrieval and injection for MCP server subprocesses.
//!
//! Credentials are resolved from a provider system (or host environment as
//! fallback) and injected as environment variables into the MCP server
//! subprocess. **Credential values are never logged.**

use crate::error::{BridgeError, Result};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Credential provider trait (allows mocking in tests)
// ---------------------------------------------------------------------------

/// Trait for resolving credential values by provider name and key.
///
/// The default implementation reads from host environment variables.
/// Production code will use the gateway provider API.
pub trait CredentialProvider: Send + Sync {
    /// Resolve a credential value for the given provider and key.
    ///
    /// Returns `Ok(value)` on success, or an error if the credential
    /// cannot be found or the provider is unavailable.
    fn resolve(&self, provider: &str, key: &str) -> Result<String>;
}

/// Resolves credentials from host environment variables.
///
/// This is the fallback provider when the gateway API is not available.
/// It looks up the key directly as an environment variable name.
pub struct EnvCredentialProvider;

impl CredentialProvider for EnvCredentialProvider {
    fn resolve(&self, provider: &str, key: &str) -> Result<String> {
        std::env::var(key).map_err(|_| BridgeError::CredentialNotFound {
            provider: provider.to_string(),
            key: key.to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Credential injection
// ---------------------------------------------------------------------------

/// A credential request: which provider and which env var key to resolve.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CredentialSpec {
    /// Provider name (e.g., "perplexity", "tavily", "github").
    pub provider: String,
    /// Environment variable name to inject (e.g., `PERPLEXITY_API_KEY`).
    pub env_key: String,
}

/// Resolve all requested credentials and return them as a map of
/// environment variable name to value.
///
/// **SECURITY:** The returned values must only be passed to the subprocess
/// environment. They must never be logged, written to disk, or sent over
/// the network.
pub fn inject_credentials(
    specs: &[CredentialSpec],
    provider: &dyn CredentialProvider,
) -> Result<HashMap<String, String>> {
    let mut env_vars = HashMap::with_capacity(specs.len());

    for spec in specs {
        tracing::info!(
            provider = %spec.provider,
            env_key = %spec.env_key,
            "resolving credential (value not logged)"
        );

        let value = provider.resolve(&spec.provider, &spec.env_key)?;
        env_vars.insert(spec.env_key.clone(), value);
    }

    tracing::info!(
        count = env_vars.len(),
        "all credentials resolved successfully"
    );

    Ok(env_vars)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Mock provider that returns predefined values.
    struct MockProvider {
        credentials: HashMap<(String, String), String>,
    }

    impl MockProvider {
        fn new(entries: Vec<(&str, &str, &str)>) -> Self {
            let mut credentials = HashMap::new();
            for (provider, key, value) in entries {
                credentials.insert((provider.to_string(), key.to_string()), value.to_string());
            }
            Self { credentials }
        }
    }

    impl CredentialProvider for MockProvider {
        fn resolve(&self, provider: &str, key: &str) -> Result<String> {
            self.credentials
                .get(&(provider.to_string(), key.to_string()))
                .cloned()
                .ok_or_else(|| BridgeError::CredentialNotFound {
                    provider: provider.to_string(),
                    key: key.to_string(),
                })
        }
    }

    /// Provider that always returns unavailable.
    struct UnavailableProvider;

    impl CredentialProvider for UnavailableProvider {
        fn resolve(&self, _provider: &str, _key: &str) -> Result<String> {
            Err(BridgeError::ProviderUnavailable)
        }
    }

    #[test]
    fn inject_credentials_resolves_all_from_provider() {
        let provider = MockProvider::new(vec![
            ("perplexity", "PERPLEXITY_API_KEY", "secret-pplx-123"),
            ("tavily", "TAVILY_API_KEY", "secret-tvly-456"),
        ]);

        let specs = vec![
            CredentialSpec {
                provider: "perplexity".to_string(),
                env_key: "PERPLEXITY_API_KEY".to_string(),
            },
            CredentialSpec {
                provider: "tavily".to_string(),
                env_key: "TAVILY_API_KEY".to_string(),
            },
        ];

        let result = inject_credentials(&specs, &provider).expect("should resolve");
        assert_eq!(result.len(), 2);
        assert_eq!(result["PERPLEXITY_API_KEY"], "secret-pplx-123");
        assert_eq!(result["TAVILY_API_KEY"], "secret-tvly-456");
    }

    #[test]
    fn inject_credentials_returns_error_when_key_missing() {
        let provider = MockProvider::new(vec![("perplexity", "PERPLEXITY_API_KEY", "secret-123")]);

        let specs = vec![CredentialSpec {
            provider: "perplexity".to_string(),
            env_key: "MISSING_KEY".to_string(),
        }];

        let err = inject_credentials(&specs, &provider).unwrap_err();
        match &err {
            BridgeError::CredentialNotFound { provider, key } => {
                assert_eq!(provider, "perplexity");
                assert_eq!(key, "MISSING_KEY");
            }
            other => panic!("expected CredentialNotFound, got: {other}"),
        }
        // Verify error message is actionable
        let msg = err.to_string();
        assert!(
            msg.contains("darkshell provider create"),
            "error should suggest fix: {msg}"
        );
    }

    #[test]
    fn inject_credentials_returns_error_when_provider_unavailable() {
        let provider = UnavailableProvider;

        let specs = vec![CredentialSpec {
            provider: "perplexity".to_string(),
            env_key: "PERPLEXITY_API_KEY".to_string(),
        }];

        let err = inject_credentials(&specs, &provider).unwrap_err();
        match &err {
            BridgeError::ProviderUnavailable => {}
            other => panic!("expected ProviderUnavailable, got: {other}"),
        }
        let msg = err.to_string();
        assert!(
            msg.contains("darkshell status"),
            "error should suggest fix: {msg}"
        );
    }

    #[test]
    fn inject_credentials_empty_specs_returns_empty_map() {
        let provider = MockProvider::new(vec![]);
        let result = inject_credentials(&[], &provider).expect("should succeed");
        assert!(result.is_empty());
    }

    #[test]
    fn env_credential_provider_reads_host_env() {
        // Use HOME which is reliably set in test environments.
        let provider = EnvCredentialProvider;
        let value = provider
            .resolve("test-provider", "HOME")
            .expect("should resolve");
        assert!(!value.is_empty(), "HOME should be non-empty");
    }

    #[test]
    fn env_credential_provider_returns_error_for_missing_var() {
        let provider = EnvCredentialProvider;
        let err = provider
            .resolve("test-provider", "DARKSHELL_NONEXISTENT_VAR_99999")
            .unwrap_err();
        assert!(matches!(err, BridgeError::CredentialNotFound { .. }));
    }
}
