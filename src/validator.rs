//! SOAP validation logic.

use crate::config::{OperationMode, SoapSecurityConfig, SoapVersion};
use crate::error::{Violation, ViolationCode};
use crate::parser::{SoapEnvelope, SoapHeader};
use chrono::{DateTime, Utc};
use glob::Pattern;
use tracing::warn;

/// Result of SOAP validation.
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// Violations found
    pub violations: Vec<Violation>,
    /// Detected SOAP version
    pub soap_version: Option<SoapVersion>,
    /// Detected operation name
    pub operation: Option<String>,
    /// Extracted identity (from WS-Security)
    pub identity: Option<String>,
    /// Validation metrics
    pub metrics: ValidationMetrics,
}

impl ValidationResult {
    /// Check if any violations were found.
    pub fn has_violations(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Add a violation.
    pub fn add_violation(&mut self, violation: Violation) {
        self.violations.push(violation);
    }
}

/// Validation metrics for observability.
#[derive(Debug, Clone, Default)]
pub struct ValidationMetrics {
    /// Body depth
    pub body_depth: u32,
    /// Element count
    pub element_count: u32,
    /// Max text length
    pub max_text_length: usize,
}

/// Main SOAP validator.
pub struct SoapValidator {
    config: SoapSecurityConfig,
    /// Compiled operation patterns (for allowlist/denylist)
    operation_patterns: Vec<Pattern>,
}

impl SoapValidator {
    /// Create a new validator with configuration.
    pub fn new(config: SoapSecurityConfig) -> Self {
        let operation_patterns = config
            .operations
            .actions
            .iter()
            .filter_map(|pattern| Pattern::new(pattern).ok())
            .collect();

        Self {
            config,
            operation_patterns,
        }
    }

    /// Validate a parsed SOAP envelope.
    pub fn validate(&self, envelope: &SoapEnvelope, soap_action: Option<&str>) -> ValidationResult {
        let mut result = ValidationResult {
            soap_version: Some(envelope.version),
            operation: envelope.body.operation.clone(),
            ..Default::default()
        };

        // Envelope validation
        if self.config.envelope.enabled {
            self.validate_envelope(envelope, &mut result);
        }

        // WS-Security validation
        if self.config.ws_security.enabled {
            self.validate_ws_security(envelope.header.as_ref(), &mut result);
        }

        // Operation control
        if self.config.operations.enabled {
            self.validate_operations(envelope, soap_action, &mut result);
        }

        // Body validation
        if self.config.body_validation.enabled {
            self.validate_body(envelope, &mut result);
        }

        // Fill metrics
        result.metrics = ValidationMetrics {
            body_depth: envelope.body.analysis.max_depth,
            element_count: envelope.body.analysis.element_count,
            max_text_length: envelope.body.analysis.max_text_length,
        };

        result
    }

    /// Validate SOAP envelope structure.
    fn validate_envelope(&self, envelope: &SoapEnvelope, result: &mut ValidationResult) {
        let config = &self.config.envelope;

        // Check SOAP version
        if !config.allowed_versions.contains(&envelope.version) {
            result.add_violation(Violation::new(
                ViolationCode::UnsupportedVersion,
                format!(
                    "SOAP version {:?} not allowed, allowed versions: {:?}",
                    envelope.version, config.allowed_versions
                ),
            ));
        }

        // Check header requirement
        if config.require_header && envelope.header.is_none() {
            result.add_violation(Violation::new(
                ViolationCode::MissingHeader,
                "SOAP Header is required but not present",
            ));
        }

        // Check body depth
        if envelope.body.analysis.max_depth > config.max_body_depth {
            result.add_violation(Violation::new(
                ViolationCode::BodyDepthExceeded,
                format!(
                    "SOAP Body nesting depth {} exceeds maximum {}",
                    envelope.body.analysis.max_depth, config.max_body_depth
                ),
            ));
        }
    }

    /// Validate WS-Security header.
    fn validate_ws_security(&self, header: Option<&SoapHeader>, result: &mut ValidationResult) {
        let config = &self.config.ws_security;

        let security = match header.and_then(|h| h.security.as_ref()) {
            Some(s) => s,
            None => {
                if config.require_security_header {
                    result.add_violation(Violation::new(
                        ViolationCode::MissingSecurityHeader,
                        "WS-Security header is required but not present",
                    ));
                }
                return;
            }
        };

        // Validate timestamp
        if config.require_timestamp {
            match &security.timestamp {
                Some(ts) => {
                    if let Some(ref created) = ts.created {
                        if let Err(e) = self.validate_timestamp(created) {
                            result.add_violation(e);
                        }
                    }
                    if let Some(ref expires) = ts.expires {
                        if let Err(e) = self.check_timestamp_expiry(expires) {
                            result.add_violation(e);
                        }
                    }
                }
                None => {
                    result.add_violation(Violation::new(
                        ViolationCode::InvalidTimestamp,
                        "Timestamp is required in WS-Security header but not present",
                    ));
                }
            }
        }

        // Validate username token
        if config.require_username_token {
            match &security.username_token {
                Some(token) => {
                    // Check password type
                    if let Some(ref pw_type) = token.password_type {
                        let allowed = config
                            .allowed_password_types
                            .iter()
                            .any(|t| match t {
                                crate::config::PasswordType::PasswordText => {
                                    pw_type.contains("PasswordText")
                                }
                                crate::config::PasswordType::PasswordDigest => {
                                    pw_type.contains("PasswordDigest")
                                }
                            });

                        if !allowed {
                            result.add_violation(Violation::new(
                                ViolationCode::InvalidPasswordType,
                                format!("Password type '{}' is not allowed", pw_type),
                            ));
                        }
                    }

                    // Extract identity
                    if !token.username.is_empty() {
                        result.identity = Some(token.username.clone());
                    }
                }
                None => {
                    result.add_violation(Violation::new(
                        ViolationCode::MissingUsernameToken,
                        "UsernameToken is required but not present",
                    ));
                }
            }
        }

        // Validate SAML
        if config.require_saml && !security.has_saml_assertion {
            result.add_violation(Violation::new(
                ViolationCode::MissingSamlAssertion,
                "SAML assertion is required but not present",
            ));
        }
    }

    /// Validate timestamp is not too old.
    fn validate_timestamp(&self, created: &str) -> Result<(), Violation> {
        let created_time = DateTime::parse_from_rfc3339(created)
            .map_err(|_| {
                Violation::new(
                    ViolationCode::InvalidTimestamp,
                    format!("Invalid timestamp format: {}", created),
                )
            })?
            .with_timezone(&Utc);

        let now = Utc::now();
        let age = now.signed_duration_since(created_time);
        let max_age = chrono::Duration::seconds(self.config.ws_security.max_timestamp_age_secs as i64);

        if age > max_age {
            return Err(Violation::new(
                ViolationCode::TimestampExpired,
                format!(
                    "Timestamp is too old: {} seconds (max: {})",
                    age.num_seconds(),
                    self.config.ws_security.max_timestamp_age_secs
                ),
            ));
        }

        // Also check for future timestamps (clock skew tolerance of 5 minutes)
        let future_tolerance = chrono::Duration::minutes(5);
        if age < -future_tolerance {
            return Err(Violation::new(
                ViolationCode::InvalidTimestamp,
                "Timestamp is in the future",
            ));
        }

        Ok(())
    }

    /// Check if timestamp has expired.
    fn check_timestamp_expiry(&self, expires: &str) -> Result<(), Violation> {
        let expires_time = DateTime::parse_from_rfc3339(expires)
            .map_err(|_| {
                Violation::new(
                    ViolationCode::InvalidTimestamp,
                    format!("Invalid expires timestamp format: {}", expires),
                )
            })?
            .with_timezone(&Utc);

        let now = Utc::now();
        if now > expires_time {
            return Err(Violation::new(
                ViolationCode::TimestampExpired,
                "Security timestamp has expired",
            ));
        }

        Ok(())
    }

    /// Validate SOAP operations.
    fn validate_operations(
        &self,
        envelope: &SoapEnvelope,
        soap_action: Option<&str>,
        result: &mut ValidationResult,
    ) {
        let config = &self.config.operations;

        // Check SOAPAction header requirement
        if config.require_soap_action_header && soap_action.is_none() {
            result.add_violation(Violation::new(
                ViolationCode::MissingSoapAction,
                "SOAPAction header is required but not present",
            ));
            return;
        }

        // Validate operation is allowed
        let operation = envelope
            .body
            .operation
            .as_deref()
            .or(soap_action)
            .unwrap_or("");

        if operation.is_empty() {
            return;
        }

        let matches_pattern = self.operation_patterns.iter().any(|p| p.matches(operation));

        let allowed = match config.mode {
            OperationMode::Allowlist => {
                // In allowlist mode, operation must match a pattern
                if self.operation_patterns.is_empty() {
                    true // No patterns = allow all
                } else {
                    matches_pattern
                }
            }
            OperationMode::Denylist => {
                // In denylist mode, operation must NOT match a pattern
                !matches_pattern
            }
        };

        if !allowed {
            result.add_violation(Violation::new(
                ViolationCode::OperationNotAllowed,
                format!("Operation '{}' is not allowed", operation),
            ));
        }

        // Validate SOAPAction matches body operation
        if config.validate_action_match {
            if let (Some(action), Some(body_op)) = (soap_action, envelope.body.operation.as_deref())
            {
                // SOAPAction might contain namespace, extract operation name
                let action_op = action.rsplit('/').next().unwrap_or(action);
                let action_op = action_op.rsplit('#').next().unwrap_or(action_op);

                if action_op != body_op {
                    warn!(
                        soap_action = action,
                        body_operation = body_op,
                        "SOAPAction mismatch with body operation"
                    );
                    result.add_violation(Violation::new(
                        ViolationCode::SoapActionMismatch,
                        format!(
                            "SOAPAction '{}' does not match body operation '{}'",
                            action, body_op
                        ),
                    ));
                }
            }
        }
    }

    /// Validate SOAP body content.
    fn validate_body(&self, envelope: &SoapEnvelope, result: &mut ValidationResult) {
        let config = &self.config.body_validation;
        let analysis = &envelope.body.analysis;

        // Check element count
        if analysis.element_count > config.max_elements {
            result.add_violation(Violation::new(
                ViolationCode::TooManyElements,
                format!(
                    "SOAP Body contains {} elements, maximum is {}",
                    analysis.element_count, config.max_elements
                ),
            ));
        }

        // Check text length
        if analysis.max_text_length > config.max_text_length {
            result.add_violation(Violation::new(
                ViolationCode::TextTooLong,
                format!(
                    "Text content length {} exceeds maximum {}",
                    analysis.max_text_length, config.max_text_length
                ),
            ));
        }

        // Check CDATA
        if config.block_cdata && analysis.has_cdata {
            result.add_violation(Violation::new(
                ViolationCode::CdataNotAllowed,
                "CDATA sections are not allowed",
            ));
        }

        // Check comments
        if config.block_comments && analysis.has_comments {
            result.add_violation(Violation::new(
                ViolationCode::CommentNotAllowed,
                "XML comments are not allowed in SOAP Body",
            ));
        }

        // Check required namespaces
        if !config.required_namespaces.is_empty() {
            let has_required = config
                .required_namespaces
                .iter()
                .any(|ns| analysis.namespaces.contains(ns));

            if !has_required {
                result.add_violation(Violation::new(
                    ViolationCode::MissingNamespace,
                    format!(
                        "Body must contain one of these namespaces: {:?}",
                        config.required_namespaces
                    ),
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        BodyValidationConfig, EnvelopeConfig, OperationsConfig, PasswordType,
        WsSecurityConfig, XxePreventionConfig,
    };
    use crate::parser::parse_soap_envelope;

    fn test_config() -> SoapSecurityConfig {
        SoapSecurityConfig {
            envelope: EnvelopeConfig {
                enabled: true,
                max_body_depth: 10,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn parse_xml(xml: &str) -> crate::parser::SoapEnvelope {
        parse_soap_envelope(xml.as_bytes()).unwrap()
    }

    // --- Basic envelope validation ---

    #[test]
    fn test_valid_soap_11() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.org/users">
      <m:UserId>123</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let validator = SoapValidator::new(test_config());
        let result = validator.validate(&envelope, None);

        assert!(!result.has_violations());
        assert_eq!(result.soap_version, Some(SoapVersion::Soap11));
        assert_eq!(result.operation, Some("GetUser".to_string()));
    }

    #[test]
    fn test_valid_soap_12() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.org/users">
      <m:UserId>456</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(test_config());
        let result = validator.validate(&envelope, None);

        assert!(!result.has_violations());
        assert_eq!(result.soap_version, Some(SoapVersion::Soap12));
    }

    #[test]
    fn test_depth_exceeded() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <a><b><c><d><e><f><g><h><i><j><k><l></l></k></j></i></h></g></f></e></d></c></b></a>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.envelope.max_body_depth = 5;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, ViolationCode::BodyDepthExceeded);
    }

    #[test]
    fn test_depth_exactly_at_limit() {
        // Depth of exactly max_body_depth should pass
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <a><b><c></c></b></a>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.envelope.max_body_depth = 20; // generous

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.has_violations());
    }

    // --- SOAP version restriction ---

    #[test]
    fn test_unsupported_soap_version_only_11_allowed() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.envelope.allowed_versions = vec![SoapVersion::Soap11];

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, ViolationCode::UnsupportedVersion);
    }

    #[test]
    fn test_unsupported_soap_version_only_12_allowed() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.envelope.allowed_versions = vec![SoapVersion::Soap12];

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, ViolationCode::UnsupportedVersion);
    }

    // --- Header requirement ---

    #[test]
    fn test_missing_header_when_required() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.envelope.require_header = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, ViolationCode::MissingHeader);
    }

    #[test]
    fn test_header_present_when_required() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <m:Token xmlns:m="http://example.org/auth">abc123</m:Token>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.envelope.require_header = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.has_violations());
    }

    // --- Envelope validation disabled ---

    #[test]
    fn test_envelope_validation_disabled() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <a><b><c><d><e><f><g><h><i><j><k></k></j></i></h></g></f></e></d></c></b></a>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.envelope.enabled = false;
        config.envelope.max_body_depth = 2; // would normally fail

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        // No envelope violations because validation is disabled
        assert!(!result.violations.iter().any(|v| v.code == ViolationCode::BodyDepthExceeded));
    }

    // --- Operation control ---

    #[test]
    fn test_operation_allowlist() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DeleteUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.mode = OperationMode::Allowlist;
        config.operations.actions = vec!["GetUser".to_string(), "ListUsers".to_string()];

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, ViolationCode::OperationNotAllowed);
    }

    #[test]
    fn test_operation_allowlist_allowed() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.mode = OperationMode::Allowlist;
        config.operations.actions = vec!["GetUser".to_string(), "ListUsers".to_string()];

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.has_violations());
    }

    #[test]
    fn test_operation_allowlist_glob_pattern() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUserProfile xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.mode = OperationMode::Allowlist;
        config.operations.actions = vec!["Get*".to_string()];

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.has_violations());
    }

    #[test]
    fn test_operation_denylist() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DeleteAllUsers xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.mode = OperationMode::Denylist;
        config.operations.actions = vec!["Delete*".to_string()];

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, ViolationCode::OperationNotAllowed);
    }

    #[test]
    fn test_operation_denylist_allowed() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.mode = OperationMode::Denylist;
        config.operations.actions = vec!["Delete*".to_string()];

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.has_violations());
    }

    #[test]
    fn test_operation_allowlist_empty_allows_all() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <AnythingGoes xmlns="http://example.org/anything"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.mode = OperationMode::Allowlist;
        config.operations.actions = vec![]; // Empty allowlist = allow all

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.has_violations());
    }

    #[test]
    fn test_require_soap_action_header_missing() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.require_soap_action_header = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None); // No SOAPAction provided

        assert!(result.has_violations());
        assert_eq!(result.violations[0].code, ViolationCode::MissingSoapAction);
    }

    #[test]
    fn test_require_soap_action_header_present() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.require_soap_action_header = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, Some("GetUser"));

        assert!(!result.has_violations());
    }

    #[test]
    fn test_soap_action_mismatch() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.validate_action_match = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, Some("DeleteUser"));

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::SoapActionMismatch));
    }

    #[test]
    fn test_soap_action_match_with_namespace() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.validate_action_match = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        // SOAPAction with namespace prefix, operation extracted via rsplit('/')
        let result = validator.validate(&envelope, Some("http://example.org/users/GetUser"));

        assert!(!result.has_violations());
    }

    #[test]
    fn test_soap_action_match_with_hash_separator() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.validate_action_match = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, Some("http://example.org/users#GetUser"));

        assert!(!result.has_violations());
    }

    #[test]
    fn test_operations_disabled_skips_check() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DeleteEverything xmlns="http://example.org/danger"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.operations.enabled = false; // Disabled
        config.operations.mode = OperationMode::Allowlist;
        config.operations.actions = vec!["SafeOperation".to_string()];

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        // Should pass since operations control is disabled
        assert!(!result.violations.iter().any(|v| v.code == ViolationCode::OperationNotAllowed));
    }

    // --- WS-Security validation ---

    #[test]
    fn test_ws_security_missing_header_when_required() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.ws_security.enabled = true;
        config.ws_security.require_security_header = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::MissingSecurityHeader));
    }

    #[test]
    fn test_ws_security_not_required_when_absent() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.ws_security.enabled = true;
        config.ws_security.require_security_header = false;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.violations.iter().any(|v| v.code == ViolationCode::MissingSecurityHeader));
    }

    #[test]
    fn test_ws_security_timestamp_required_but_missing() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>user</wsse:Username>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.ws_security.enabled = true;
        config.ws_security.require_timestamp = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::InvalidTimestamp));
    }

    #[test]
    fn test_ws_security_username_token_required_but_missing() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
        <wsu:Created>2025-01-01T00:00:00Z</wsu:Created>
      </wsu:Timestamp>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.ws_security.enabled = true;
        config.ws_security.require_username_token = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::MissingUsernameToken));
    }

    #[test]
    fn test_ws_security_saml_required_but_missing() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <wsse:UsernameToken>
        <wsse:Username>admin</wsse:Username>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.ws_security.enabled = true;
        config.ws_security.require_saml = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::MissingSamlAssertion));
    }

    #[test]
    fn test_ws_security_disabled_skips_all() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.ws_security.enabled = false;
        config.ws_security.require_security_header = true;
        config.ws_security.require_timestamp = true;
        config.ws_security.require_username_token = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        // No WS-Security violations because the feature is disabled
        assert!(!result.violations.iter().any(|v| matches!(
            v.code,
            ViolationCode::MissingSecurityHeader
                | ViolationCode::InvalidTimestamp
                | ViolationCode::MissingUsernameToken
        )));
    }

    // --- Timestamp validation ---

    #[test]
    fn test_validate_timestamp_invalid_format() {
        let config = test_config();
        let validator = SoapValidator::new(config);

        let result = validator.validate_timestamp("not-a-date");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ViolationCode::InvalidTimestamp);
    }

    #[test]
    fn test_validate_timestamp_old_message() {
        let mut config = test_config();
        config.ws_security.max_timestamp_age_secs = 60; // 1 minute max

        let validator = SoapValidator::new(config);
        // A timestamp from 2020 should be way too old
        let result = validator.validate_timestamp("2020-01-01T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ViolationCode::TimestampExpired);
    }

    #[test]
    fn test_validate_timestamp_far_future() {
        let config = test_config();
        let validator = SoapValidator::new(config);
        // A timestamp far in the future should fail (> 5 minute tolerance)
        let result = validator.validate_timestamp("2099-12-31T23:59:59Z");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ViolationCode::InvalidTimestamp);
    }

    #[test]
    fn test_validate_timestamp_recent() {
        let mut config = test_config();
        config.ws_security.max_timestamp_age_secs = 300;

        let validator = SoapValidator::new(config);
        // Use current time
        let now = chrono::Utc::now().to_rfc3339();
        let result = validator.validate_timestamp(&now);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_timestamp_expiry_expired() {
        let config = test_config();
        let validator = SoapValidator::new(config);
        // Already expired
        let result = validator.check_timestamp_expiry("2020-01-01T00:00:00Z");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ViolationCode::TimestampExpired);
    }

    #[test]
    fn test_check_timestamp_expiry_valid() {
        let config = test_config();
        let validator = SoapValidator::new(config);
        // Far future, not expired
        let result = validator.check_timestamp_expiry("2099-12-31T23:59:59Z");
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_timestamp_expiry_invalid_format() {
        let config = test_config();
        let validator = SoapValidator::new(config);
        let result = validator.check_timestamp_expiry("garbage");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ViolationCode::InvalidTimestamp);
    }

    // --- Body validation ---

    #[test]
    fn test_body_too_many_elements() {
        // Generate XML with lots of elements
        let mut elements = String::new();
        for i in 0..50 {
            elements.push_str(&format!("<item{i}>val</item{i}>"));
        }
        let xml = format!(
            r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:BulkOp xmlns:m="http://example.org/bulk">{}</m:BulkOp>
  </soap:Body>
</soap:Envelope>"#,
            elements
        );

        let mut config = test_config();
        config.body_validation.enabled = true;
        config.body_validation.max_elements = 10;

        let envelope = parse_xml(&xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::TooManyElements));
    }

    #[test]
    fn test_body_text_too_long() {
        let long_text = "X".repeat(1000);
        let xml = format!(
            r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:Save xmlns:m="http://example.org/data">
      <m:Content>{}</m:Content>
    </m:Save>
  </soap:Body>
</soap:Envelope>"#,
            long_text
        );

        let mut config = test_config();
        config.body_validation.enabled = true;
        config.body_validation.max_text_length = 100;

        let envelope = parse_xml(&xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::TextTooLong));
    }

    #[test]
    fn test_body_cdata_blocked() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:Save xmlns:m="http://example.org/data">
      <m:Content><![CDATA[some data]]></m:Content>
    </m:Save>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.body_validation.enabled = true;
        config.body_validation.block_cdata = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::CdataNotAllowed));
    }

    #[test]
    fn test_body_cdata_allowed_by_default() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:Save xmlns:m="http://example.org/data">
      <m:Content><![CDATA[some data]]></m:Content>
    </m:Save>
  </soap:Body>
</soap:Envelope>"#;

        let config = test_config(); // block_cdata defaults to false

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.violations.iter().any(|v| v.code == ViolationCode::CdataNotAllowed));
    }

    #[test]
    fn test_body_comments_blocked() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!-- this comment should be blocked -->
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.body_validation.enabled = true;
        config.body_validation.block_comments = true;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::CommentNotAllowed));
    }

    #[test]
    fn test_body_comments_allowed_by_default() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!-- this comment should be fine -->
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let config = test_config(); // block_comments defaults to false

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.violations.iter().any(|v| v.code == ViolationCode::CommentNotAllowed));
    }

    #[test]
    fn test_body_required_namespace_present() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.org/users">
      <m:UserId>123</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.body_validation.enabled = true;
        config.body_validation.required_namespaces = vec!["http://example.org/users".to_string()];

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.violations.iter().any(|v| v.code == ViolationCode::MissingNamespace));
    }

    #[test]
    fn test_body_required_namespace_missing() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.org/users">
      <m:UserId>123</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.body_validation.enabled = true;
        config.body_validation.required_namespaces =
            vec!["http://example.org/REQUIRED_NS".to_string()];

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(result.has_violations());
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::MissingNamespace));
    }

    #[test]
    fn test_body_validation_disabled() {
        let long_text = "X".repeat(1000);
        let xml = format!(
            r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:Save xmlns:m="http://example.org/data">
      <m:Content>{}</m:Content>
    </m:Save>
  </soap:Body>
</soap:Envelope>"#,
            long_text
        );

        let mut config = test_config();
        config.body_validation.enabled = false;
        config.body_validation.max_text_length = 10; // Would normally fail

        let envelope = parse_xml(&xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        assert!(!result.violations.iter().any(|v| v.code == ViolationCode::TextTooLong));
    }

    // --- Metrics tracking ---

    #[test]
    fn test_metrics_populated() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.org/users">
      <m:UserId>123</m:UserId>
      <m:Extra>data</m:Extra>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(test_config());
        let result = validator.validate(&envelope, None);

        assert_eq!(result.metrics.element_count, envelope.body.analysis.element_count);
        assert_eq!(result.metrics.body_depth, envelope.body.analysis.max_depth);
        assert_eq!(result.metrics.max_text_length, envelope.body.analysis.max_text_length);
    }

    // --- Multiple violations in one request ---

    #[test]
    fn test_multiple_violations_accumulated() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <a><b><c><d><e><f><g><h><i><j><k></k></j></i></h></g></f></e></d></c></b></a>
  </soap:Body>
</soap:Envelope>"#;

        let mut config = test_config();
        config.envelope.allowed_versions = vec![SoapVersion::Soap11]; // Will fail: SOAP 1.2 not allowed
        config.envelope.require_header = true; // Will fail: no header
        config.envelope.max_body_depth = 3; // Will fail: deep nesting

        let envelope = parse_xml(xml);
        let validator = SoapValidator::new(config);
        let result = validator.validate(&envelope, None);

        // Should have at least 3 violations
        assert!(result.violations.len() >= 3);
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::UnsupportedVersion));
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::MissingHeader));
        assert!(result.violations.iter().any(|v| v.code == ViolationCode::BodyDepthExceeded));
    }

    // --- ValidationResult API ---

    #[test]
    fn test_validation_result_has_violations() {
        let mut result = ValidationResult::default();
        assert!(!result.has_violations());

        result.add_violation(Violation::new(ViolationCode::InvalidXml, "test"));
        assert!(result.has_violations());
    }

    #[test]
    fn test_validation_result_defaults() {
        let result = ValidationResult::default();
        assert!(result.violations.is_empty());
        assert!(result.soap_version.is_none());
        assert!(result.operation.is_none());
        assert!(result.identity.is_none());
        assert_eq!(result.metrics.body_depth, 0);
        assert_eq!(result.metrics.element_count, 0);
        assert_eq!(result.metrics.max_text_length, 0);
    }
}
