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
    use crate::config::EnvelopeConfig;
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
}
