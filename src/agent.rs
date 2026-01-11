//! Main SOAP Security Agent implementation.
//!
//! Coordinates all validators and integrates with the Sentinel Agent SDK.

use crate::config::{FailAction, SoapSecurityConfig};
use crate::error::{soap_fault_response, SoapFaultVersion, Violation, ViolationCode};
use crate::parser::{parse_soap_action, parse_soap_envelope};
use crate::validator::{SoapValidator, ValidationMetrics};
use async_trait::async_trait;
use sentinel_agent_sdk::{Agent, Decision, Request};
use tracing::{debug, info, warn};

/// SOAP Security Agent for Sentinel.
///
/// Validates SOAP messages for security concerns including envelope structure,
/// WS-Security, operation control, and XXE prevention.
pub struct SoapSecurityAgent {
    config: SoapSecurityConfig,
    validator: SoapValidator,
}

impl SoapSecurityAgent {
    /// Create a new SOAP security agent with the given configuration.
    pub fn new(config: SoapSecurityConfig) -> Self {
        let validator = SoapValidator::new(config.clone());
        Self { config, validator }
    }

    /// Check if Content-Type is valid for SOAP.
    fn is_valid_content_type(&self, content_type: Option<&str>) -> bool {
        match content_type {
            Some(ct) => {
                let ct_lower = ct.to_lowercase();
                self.config
                    .settings
                    .allowed_content_types
                    .iter()
                    .any(|allowed| ct_lower.contains(&allowed.to_lowercase()))
            }
            None => false,
        }
    }

    /// Build a block decision with SOAP Fault response.
    fn build_block_decision(
        &self,
        violations: &[Violation],
        metrics: &ValidationMetrics,
        soap_version: Option<crate::config::SoapVersion>,
    ) -> Decision {
        let fault_version = soap_version.map(|v| match v {
            crate::config::SoapVersion::Soap11 => SoapFaultVersion::Soap11,
            crate::config::SoapVersion::Soap12 => SoapFaultVersion::Soap12,
        });

        let fault_body = soap_fault_response(violations, fault_version);

        let content_type = match soap_version {
            Some(crate::config::SoapVersion::Soap12) => "application/soap+xml; charset=utf-8",
            _ => "text/xml; charset=utf-8",
        };

        let mut decision = Decision::block(500)
            .with_body(&fault_body)
            .add_response_header("Content-Type", content_type);

        // Add debug headers if enabled
        if self.config.settings.debug_headers {
            decision = self.add_debug_headers(decision, metrics);
        }

        decision
    }

    /// Add debug headers to a decision.
    fn add_debug_headers(&self, mut decision: Decision, metrics: &ValidationMetrics) -> Decision {
        decision = decision
            .add_response_header("X-SOAP-Body-Depth", &metrics.body_depth.to_string())
            .add_response_header("X-SOAP-Element-Count", &metrics.element_count.to_string())
            .add_response_header(
                "X-SOAP-Max-Text-Length",
                &metrics.max_text_length.to_string(),
            );
        decision
    }

    /// Add metrics headers for allow decisions.
    fn add_allow_headers(&self, mut decision: Decision, metrics: &ValidationMetrics) -> Decision {
        if self.config.settings.debug_headers {
            decision = self.add_debug_headers(decision, metrics);
        }
        decision
    }
}

#[async_trait]
impl Agent for SoapSecurityAgent {
    fn name(&self) -> &str {
        "soap"
    }

    async fn on_request(&self, request: &Request) -> Decision {
        let correlation_id = request
            .header("x-correlation-id")
            .or_else(|| request.header("x-request-id"))
            .unwrap_or("unknown")
            .to_string();

        let client_ip = request.client_ip().to_string();

        debug!(
            correlation_id = %correlation_id,
            client_ip = %client_ip,
            method = %request.method(),
            path = %request.path(),
            "Processing SOAP request"
        );

        // Check Content-Type
        let content_type = request.header("content-type");
        if !self.is_valid_content_type(content_type) {
            debug!(
                correlation_id = %correlation_id,
                content_type = ?content_type,
                "Non-SOAP content type, passing through"
            );
            return Decision::allow();
        }

        // Get body
        let body = match request.body() {
            Some(b) => b,
            None => {
                debug!(
                    correlation_id = %correlation_id,
                    "No body available, passing through"
                );
                return Decision::allow();
            }
        };

        // Check body size
        if body.len() > self.config.settings.max_body_size {
            warn!(
                correlation_id = %correlation_id,
                body_size = body.len(),
                max_size = self.config.settings.max_body_size,
                "SOAP body too large"
            );

            let violation = Violation::new(
                ViolationCode::BodyTooLarge,
                format!(
                    "Request body size {} exceeds maximum {}",
                    body.len(),
                    self.config.settings.max_body_size
                ),
            );

            return match self.config.settings.fail_action {
                FailAction::Block => self.build_block_decision(
                    &[violation],
                    &ValidationMetrics::default(),
                    None,
                ),
                FailAction::Allow => {
                    info!(
                        correlation_id = %correlation_id,
                        "Body too large but allowing request (fail_action=allow)"
                    );
                    Decision::allow()
                }
            };
        }

        // Parse SOAP envelope
        let envelope = match parse_soap_envelope(body) {
            Ok(env) => env,
            Err(violation) => {
                warn!(
                    correlation_id = %correlation_id,
                    code = %violation.code.as_str(),
                    message = %violation.message,
                    "SOAP parsing error"
                );

                return match self.config.settings.fail_action {
                    FailAction::Block => self.build_block_decision(
                        &[violation],
                        &ValidationMetrics::default(),
                        None,
                    ),
                    FailAction::Allow => {
                        info!(
                            correlation_id = %correlation_id,
                            "Parsing error but allowing request (fail_action=allow)"
                        );
                        Decision::allow()
                    }
                };
            }
        };

        // Get SOAPAction header
        let soap_action = request
            .header("soapaction")
            .or_else(|| request.header("SOAPAction"))
            .map(parse_soap_action);

        // Validate
        let result = self.validator.validate(&envelope, soap_action.as_deref());

        if result.has_violations() {
            warn!(
                correlation_id = %correlation_id,
                violation_count = result.violations.len(),
                operation = ?result.operation,
                "SOAP security violations detected"
            );

            for v in &result.violations {
                debug!(
                    correlation_id = %correlation_id,
                    code = %v.code.as_str(),
                    message = %v.message,
                    "Violation"
                );
            }

            match self.config.settings.fail_action {
                FailAction::Block => {
                    self.build_block_decision(&result.violations, &result.metrics, result.soap_version)
                }
                FailAction::Allow => {
                    info!(
                        correlation_id = %correlation_id,
                        "Violations detected but allowing request (fail_action=allow)"
                    );
                    self.add_allow_headers(Decision::allow(), &result.metrics)
                }
            }
        } else {
            debug!(
                correlation_id = %correlation_id,
                operation = ?result.operation,
                "SOAP request passed security checks"
            );

            let mut decision = Decision::allow();

            // Add identity header if configured and available
            if let (Some(ref header_name), Some(ref identity)) =
                (&self.config.ws_security.identity_header, &result.identity)
            {
                decision = decision.add_request_header(header_name, identity);
            }

            // Add processed header
            decision = decision.add_request_header("X-SOAP-Validated", "true");

            if let Some(ref op) = result.operation {
                decision = decision.add_request_header("X-SOAP-Operation", op);
            }

            self.add_allow_headers(decision, &result.metrics)
        }
    }

    async fn on_request_body(&self, request: &Request) -> Decision {
        // Process in on_request_body since we need the body
        self.on_request(request).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> SoapSecurityConfig {
        SoapSecurityConfig {
            settings: crate::config::SettingsConfig {
                max_body_size: 1_048_576,
                debug_headers: true,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_agent_creation() {
        let agent = SoapSecurityAgent::new(test_config());
        assert_eq!(agent.name(), "soap");
    }

    #[test]
    fn test_valid_content_type() {
        let agent = SoapSecurityAgent::new(test_config());
        assert!(agent.is_valid_content_type(Some("text/xml")));
        assert!(agent.is_valid_content_type(Some("application/soap+xml; charset=utf-8")));
        assert!(agent.is_valid_content_type(Some("TEXT/XML")));
        assert!(!agent.is_valid_content_type(Some("application/json")));
        assert!(!agent.is_valid_content_type(None));
    }
}
