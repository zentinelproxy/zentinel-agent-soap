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

    // --- Default value coverage ---

    #[test]
    fn test_default_settings_config() {
        let settings = SettingsConfig::default();
        assert_eq!(settings.max_body_size, 1_048_576);
        assert!(!settings.debug_headers);
        assert_eq!(settings.fail_action, FailAction::Block);
        assert_eq!(settings.allowed_content_types.len(), 3);
        assert!(settings.allowed_content_types.contains(&"text/xml".to_string()));
        assert!(settings.allowed_content_types.contains(&"application/soap+xml".to_string()));
        assert!(settings.allowed_content_types.contains(&"application/xml".to_string()));
    }

    #[test]
    fn test_default_envelope_config() {
        let envelope = EnvelopeConfig::default();
        assert!(envelope.enabled);
        assert!(envelope.require_valid_envelope);
        assert!(!envelope.require_header);
        assert_eq!(envelope.max_body_depth, 20);
        assert_eq!(envelope.allowed_versions.len(), 2);
        assert!(envelope.allowed_versions.contains(&SoapVersion::Soap11));
        assert!(envelope.allowed_versions.contains(&SoapVersion::Soap12));
    }

    #[test]
    fn test_default_ws_security_config() {
        let ws = WsSecurityConfig::default();
        assert!(!ws.enabled);
        assert!(!ws.require_security_header);
        assert!(!ws.require_timestamp);
        assert_eq!(ws.max_timestamp_age_secs, 300);
        assert!(!ws.require_username_token);
        assert_eq!(ws.allowed_password_types.len(), 1);
        assert_eq!(ws.allowed_password_types[0], PasswordType::PasswordDigest);
        assert!(!ws.require_saml);
        assert!(ws.identity_header.is_none());
    }

    #[test]
    fn test_default_operations_config() {
        let ops = OperationsConfig::default();
        assert!(!ops.enabled);
        assert_eq!(ops.mode, OperationMode::Allowlist);
        assert!(ops.actions.is_empty());
        assert!(ops.rate_limits.is_empty());
        assert!(!ops.require_soap_action_header);
        assert!(!ops.validate_action_match);
    }

    #[test]
    fn test_default_xxe_prevention_config() {
        let xxe = XxePreventionConfig::default();
        assert!(xxe.enabled);
        assert!(xxe.block_doctype);
        assert!(xxe.block_external_entities);
        assert!(xxe.block_processing_instructions);
        assert_eq!(xxe.max_entity_expansions, 100);
    }

    #[test]
    fn test_default_body_validation_config() {
        let body = BodyValidationConfig::default();
        assert!(body.enabled);
        assert_eq!(body.max_elements, 1000);
        assert_eq!(body.max_text_length, 65536);
        assert!(!body.block_cdata);
        assert!(!body.block_comments);
        assert!(body.required_namespaces.is_empty());
    }

    // --- YAML parsing edge cases ---

    #[test]
    fn test_empty_yaml_uses_defaults() {
        let yaml = "{}";
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.version, "1");
        assert!(config.envelope.enabled);
        assert!(config.xxe_prevention.enabled);
    }

    #[test]
    fn test_partial_yaml_fills_defaults() {
        let yaml = r#"
envelope:
  max_body_depth: 5
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        // Explicitly set value
        assert_eq!(config.envelope.max_body_depth, 5);
        // Defaulted values remain
        assert!(config.envelope.enabled);
        assert!(config.envelope.require_valid_envelope);
        assert!(!config.ws_security.enabled);
        assert!(config.xxe_prevention.block_doctype);
    }

    #[test]
    fn test_fail_action_allow_yaml() {
        let yaml = r#"
settings:
  fail_action: allow
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.settings.fail_action, FailAction::Allow);
    }

    #[test]
    fn test_fail_action_block_yaml() {
        let yaml = r#"
settings:
  fail_action: block
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.settings.fail_action, FailAction::Block);
    }

    #[test]
    fn test_operation_mode_denylist_yaml() {
        let yaml = r#"
operations:
  enabled: true
  mode: denylist
  actions:
    - "DeleteUser"
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.operations.mode, OperationMode::Denylist);
        assert_eq!(config.operations.actions, vec!["DeleteUser".to_string()]);
    }

    #[test]
    fn test_soap_version_only_11() {
        let yaml = r#"
envelope:
  allowed_versions:
    - "1.1"
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.envelope.allowed_versions.len(), 1);
        assert_eq!(config.envelope.allowed_versions[0], SoapVersion::Soap11);
    }

    #[test]
    fn test_soap_version_only_12() {
        let yaml = r#"
envelope:
  allowed_versions:
    - "1.2"
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.envelope.allowed_versions.len(), 1);
        assert_eq!(config.envelope.allowed_versions[0], SoapVersion::Soap12);
    }

    #[test]
    fn test_ws_security_full_config() {
        let yaml = r#"
ws_security:
  enabled: true
  require_security_header: true
  require_timestamp: true
  max_timestamp_age_secs: 600
  require_username_token: true
  allowed_password_types:
    - PasswordText
    - PasswordDigest
  require_saml: true
  identity_header: "X-Authenticated-User"
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.ws_security.enabled);
        assert!(config.ws_security.require_security_header);
        assert!(config.ws_security.require_timestamp);
        assert_eq!(config.ws_security.max_timestamp_age_secs, 600);
        assert!(config.ws_security.require_username_token);
        assert_eq!(config.ws_security.allowed_password_types.len(), 2);
        assert!(config.ws_security.allowed_password_types.contains(&PasswordType::PasswordText));
        assert!(config.ws_security.allowed_password_types.contains(&PasswordType::PasswordDigest));
        assert!(config.ws_security.require_saml);
        assert_eq!(
            config.ws_security.identity_header,
            Some("X-Authenticated-User".to_string())
        );
    }

    #[test]
    fn test_body_validation_full_config() {
        let yaml = r#"
body_validation:
  enabled: true
  max_elements: 500
  max_text_length: 32768
  block_cdata: true
  block_comments: true
  required_namespaces:
    - "http://example.org/api"
    - "http://example.org/types"
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.body_validation.enabled);
        assert_eq!(config.body_validation.max_elements, 500);
        assert_eq!(config.body_validation.max_text_length, 32768);
        assert!(config.body_validation.block_cdata);
        assert!(config.body_validation.block_comments);
        assert_eq!(config.body_validation.required_namespaces.len(), 2);
    }

    #[test]
    fn test_operations_with_rate_limits() {
        let yaml = r#"
operations:
  enabled: true
  mode: allowlist
  actions:
    - "GetUser"
    - "ListUsers"
  rate_limits:
    GetUser: 100
    ListUsers: 50
  require_soap_action_header: true
  validate_action_match: true
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(config.operations.require_soap_action_header);
        assert!(config.operations.validate_action_match);
        assert_eq!(config.operations.rate_limits.get("GetUser"), Some(&100));
        assert_eq!(config.operations.rate_limits.get("ListUsers"), Some(&50));
    }

    #[test]
    fn test_xxe_prevention_disabled() {
        let yaml = r#"
xxe_prevention:
  enabled: false
  block_doctype: false
  block_external_entities: false
  block_processing_instructions: false
  max_entity_expansions: 0
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert!(!config.xxe_prevention.enabled);
        assert!(!config.xxe_prevention.block_doctype);
        assert!(!config.xxe_prevention.block_external_entities);
        assert!(!config.xxe_prevention.block_processing_instructions);
        assert_eq!(config.xxe_prevention.max_entity_expansions, 0);
    }

    #[test]
    fn test_roundtrip_serialization_full() {
        let config = SoapSecurityConfig {
            version: "2".to_string(),
            settings: SettingsConfig {
                max_body_size: 2_097_152,
                debug_headers: true,
                fail_action: FailAction::Allow,
                allowed_content_types: vec!["text/xml".to_string()],
            },
            envelope: EnvelopeConfig {
                enabled: true,
                require_valid_envelope: true,
                allowed_versions: vec![SoapVersion::Soap11],
                require_header: true,
                max_body_depth: 10,
            },
            ws_security: WsSecurityConfig {
                enabled: true,
                require_security_header: true,
                require_timestamp: true,
                max_timestamp_age_secs: 600,
                require_username_token: true,
                allowed_password_types: vec![PasswordType::PasswordDigest],
                require_saml: false,
                identity_header: Some("X-User".to_string()),
            },
            operations: OperationsConfig {
                enabled: true,
                mode: OperationMode::Denylist,
                actions: vec!["Delete*".to_string()],
                rate_limits: HashMap::new(),
                require_soap_action_header: true,
                validate_action_match: true,
            },
            xxe_prevention: XxePreventionConfig::default(),
            body_validation: BodyValidationConfig::default(),
        };

        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: SoapSecurityConfig = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(parsed.version, "2");
        assert_eq!(parsed.settings.max_body_size, 2_097_152);
        assert!(parsed.settings.debug_headers);
        assert_eq!(parsed.settings.fail_action, FailAction::Allow);
        assert_eq!(parsed.envelope.max_body_depth, 10);
        assert!(parsed.envelope.require_header);
        assert!(parsed.ws_security.enabled);
        assert_eq!(parsed.ws_security.max_timestamp_age_secs, 600);
        assert_eq!(parsed.ws_security.identity_header, Some("X-User".to_string()));
        assert_eq!(parsed.operations.mode, OperationMode::Denylist);
        assert!(parsed.operations.validate_action_match);
    }

    #[test]
    fn test_invalid_yaml_returns_error() {
        let yaml = "{{{{invalid yaml}}}}";
        let result: Result<SoapSecurityConfig, _> = serde_yaml::from_str(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_unknown_fields_ignored_by_default() {
        // serde(default) on the struct should allow extra/missing fields
        let yaml = r#"
version: "1"
some_unknown_field: "value"
"#;
        // This may or may not fail depending on serde config; the struct uses #[serde(default)]
        // but does NOT use deny_unknown_fields, so unknown fields should be ignored.
        let result: Result<SoapSecurityConfig, _> = serde_yaml::from_str(yaml);
        // With serde(default) and no deny_unknown_fields, this should succeed
        assert!(result.is_ok());
    }

    #[test]
    fn test_fail_action_default_is_block() {
        let action = FailAction::default();
        assert_eq!(action, FailAction::Block);
    }

    #[test]
    fn test_operation_mode_default_is_allowlist() {
        let mode = OperationMode::default();
        assert_eq!(mode, OperationMode::Allowlist);
    }

    #[test]
    fn test_custom_content_types() {
        let yaml = r#"
settings:
  allowed_content_types:
    - "text/xml"
    - "application/soap+xml"
    - "application/custom+soap"
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.settings.allowed_content_types.len(), 3);
        assert!(config.settings.allowed_content_types.contains(&"application/custom+soap".to_string()));
    }

    #[test]
    fn test_zero_max_body_size() {
        let yaml = r#"
settings:
  max_body_size: 0
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.settings.max_body_size, 0);
    }

    #[test]
    fn test_large_max_body_depth() {
        let yaml = r#"
envelope:
  max_body_depth: 999999
"#;
        let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.envelope.max_body_depth, 999999);
    }

    #[test]
    fn test_json_serialization() {
        // Config should also work with JSON via serde
        let config = SoapSecurityConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: SoapSecurityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.envelope.max_body_depth, config.envelope.max_body_depth);
        assert_eq!(parsed.settings.max_body_size, config.settings.max_body_size);
    }
}
