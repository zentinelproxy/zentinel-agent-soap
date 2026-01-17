//! Configuration types for the SOAP Security agent.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Main configuration for the SOAP Security agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SoapSecurityConfig {
    /// Config version
    pub version: String,

    /// General settings
    pub settings: SettingsConfig,

    /// Envelope validation configuration
    pub envelope: EnvelopeConfig,

    /// WS-Security configuration
    pub ws_security: WsSecurityConfig,

    /// SOAP action/operation control configuration
    pub operations: OperationsConfig,

    /// XXE prevention configuration
    pub xxe_prevention: XxePreventionConfig,

    /// Body content validation
    pub body_validation: BodyValidationConfig,
}

impl Default for SoapSecurityConfig {
    fn default() -> Self {
        Self {
            version: "1".to_string(),
            settings: SettingsConfig::default(),
            envelope: EnvelopeConfig::default(),
            ws_security: WsSecurityConfig::default(),
            operations: OperationsConfig::default(),
            xxe_prevention: XxePreventionConfig::default(),
            body_validation: BodyValidationConfig::default(),
        }
    }
}

/// General settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SettingsConfig {
    /// Maximum body size to process (bytes)
    pub max_body_size: usize,

    /// Add debug headers (X-SOAP-*) to responses
    pub debug_headers: bool,

    /// Action on failure: "block" or "allow"
    pub fail_action: FailAction,

    /// Allowed Content-Type headers for SOAP requests
    pub allowed_content_types: Vec<String>,
}

impl Default for SettingsConfig {
    fn default() -> Self {
        Self {
            max_body_size: 1_048_576, // 1MB
            debug_headers: false,
            fail_action: FailAction::Block,
            allowed_content_types: vec![
                "text/xml".to_string(),
                "application/soap+xml".to_string(),
                "application/xml".to_string(),
            ],
        }
    }
}

/// Failure action when violations are detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FailAction {
    /// Block the request
    #[default]
    Block,
    /// Allow the request (log only)
    Allow,
}

/// SOAP envelope validation configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EnvelopeConfig {
    /// Enable envelope validation
    pub enabled: bool,

    /// Require valid SOAP envelope structure
    pub require_valid_envelope: bool,

    /// Allowed SOAP versions
    pub allowed_versions: Vec<SoapVersion>,

    /// Require SOAP Header element
    pub require_header: bool,

    /// Maximum nesting depth in SOAP Body
    pub max_body_depth: u32,
}

impl Default for EnvelopeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_valid_envelope: true,
            allowed_versions: vec![SoapVersion::Soap11, SoapVersion::Soap12],
            require_header: false,
            max_body_depth: 20,
        }
    }
}

/// SOAP versions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SoapVersion {
    /// SOAP 1.1 (namespace: http://schemas.xmlsoap.org/soap/envelope/)
    #[serde(rename = "1.1")]
    Soap11,
    /// SOAP 1.2 (namespace: http://www.w3.org/2003/05/soap-envelope)
    #[serde(rename = "1.2")]
    Soap12,
}

/// WS-Security configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WsSecurityConfig {
    /// Enable WS-Security validation
    pub enabled: bool,

    /// Require WS-Security header
    pub require_security_header: bool,

    /// Require timestamp in Security header
    pub require_timestamp: bool,

    /// Maximum timestamp age in seconds (for replay prevention)
    pub max_timestamp_age_secs: u64,

    /// Require username token
    pub require_username_token: bool,

    /// Allowed username token password types
    pub allowed_password_types: Vec<PasswordType>,

    /// Require SAML assertion
    pub require_saml: bool,

    /// Header name for extracting validated identity
    pub identity_header: Option<String>,
}

impl Default for WsSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            require_security_header: false,
            require_timestamp: false,
            max_timestamp_age_secs: 300, // 5 minutes
            require_username_token: false,
            allowed_password_types: vec![PasswordType::PasswordDigest],
            require_saml: false,
            identity_header: None,
        }
    }
}

/// WS-Security UsernameToken password types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PasswordType {
    /// Plain text password (not recommended)
    #[serde(rename = "PasswordText")]
    PasswordText,
    /// Digested password (SHA-1 with nonce and timestamp)
    #[serde(rename = "PasswordDigest")]
    PasswordDigest,
}

/// SOAP operation/action control configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OperationsConfig {
    /// Enable operation control
    pub enabled: bool,

    /// Mode: allowlist or denylist
    pub mode: OperationMode,

    /// List of allowed/denied SOAP actions (supports glob patterns)
    pub actions: Vec<String>,

    /// Per-operation rate limits (action -> requests per minute)
    pub rate_limits: HashMap<String, u32>,

    /// Require SOAPAction header
    pub require_soap_action_header: bool,

    /// Validate SOAPAction matches body operation
    pub validate_action_match: bool,
}

impl Default for OperationsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: OperationMode::Allowlist,
            actions: Vec::new(),
            rate_limits: HashMap::new(),
            require_soap_action_header: false,
            validate_action_match: false,
        }
    }
}

/// Operation control mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OperationMode {
    /// Only allow listed operations
    #[default]
    Allowlist,
    /// Block listed operations
    Denylist,
}

/// XXE (XML External Entity) prevention configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct XxePreventionConfig {
    /// Enable XXE prevention (should always be true)
    pub enabled: bool,

    /// Block DOCTYPE declarations
    pub block_doctype: bool,

    /// Block external entity references
    pub block_external_entities: bool,

    /// Block processing instructions
    pub block_processing_instructions: bool,

    /// Maximum entity expansion count
    pub max_entity_expansions: u32,
}

impl Default for XxePreventionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            block_doctype: true,
            block_external_entities: true,
            block_processing_instructions: true,
            max_entity_expansions: 100,
        }
    }
}

/// SOAP body content validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BodyValidationConfig {
    /// Enable body validation
    pub enabled: bool,

    /// Maximum number of elements in body
    pub max_elements: u32,

    /// Maximum text content length per element
    pub max_text_length: usize,

    /// Block CDATA sections
    pub block_cdata: bool,

    /// Block comments in SOAP body
    pub block_comments: bool,

    /// Required namespaces (element must have one of these)
    pub required_namespaces: Vec<String>,
}

impl Default for BodyValidationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_elements: 1000,
            max_text_length: 65536, // 64KB
            block_cdata: false,
            block_comments: false,
            required_namespaces: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SoapSecurityConfig::default();
        assert!(config.envelope.enabled);
        assert!(config.xxe_prevention.enabled);
        assert!(config.xxe_prevention.block_doctype);
        assert!(!config.ws_security.enabled);
    }

    #[test]
    fn test_config_serialization() {
        let config = SoapSecurityConfig::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: SoapSecurityConfig = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.envelope.max_body_depth, config.envelope.max_body_depth);
    }

    #[test]
    fn test_config_from_yaml() {
        let yaml = r#"
version: "1"
settings:
  debug_headers: true
  max_body_size: 2097152
envelope:
  max_body_depth: 15
  allowed_versions:
    - "1.1"
ws_security:
  enabled: true
  require_timestamp: true
operations:
  enabled: true
  mode: allowlist
  actions:
    - "GetUser"
    - "ListUsers"
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.settings.debug_headers);
        assert_eq!(config.settings.max_body_size, 2_097_152);
        assert_eq!(config.envelope.max_body_depth, 15);
        assert!(config.ws_security.enabled);
        assert!(config.ws_security.require_timestamp);
        assert!(config.operations.enabled);
        assert_eq!(config.operations.actions.len(), 2);
    }
}
