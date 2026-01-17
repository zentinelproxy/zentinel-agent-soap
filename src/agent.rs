//! Main SOAP Security Agent implementation.
//!
//! Coordinates all validators and integrates with Sentinel Agent Protocol v2.

use crate::config::{FailAction, SoapSecurityConfig};
use crate::error::{soap_fault_response, SoapFaultVersion, Violation, ViolationCode};
use crate::parser::{parse_soap_action, parse_soap_envelope};
use crate::validator::{SoapValidator, ValidationMetrics};
use async_trait::async_trait;
use sentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason, HealthConfig,
    HealthStatus, MetricsReport, ShutdownReason,
};
use sentinel_agent_protocol::{
    AgentResponse, Decision, EventType, HeaderOp, RequestHeadersEvent,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

/// SOAP Security Agent for Sentinel.
///
/// Validates SOAP messages for security concerns including envelope structure,
/// WS-Security, operation control, and XXE prevention.
pub struct SoapSecurityAgent {
    config: SoapSecurityConfig,
    validator: SoapValidator,
    /// Metrics tracking
    requests_processed: AtomicU64,
    requests_blocked: AtomicU64,
}

impl SoapSecurityAgent {
    /// Create a new SOAP security agent with the given configuration.
    pub fn new(config: SoapSecurityConfig) -> Self {
        let validator = SoapValidator::new(config.clone());
        Self {
            config,
            validator,
            requests_processed: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
        }
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

    /// Build a block response with SOAP Fault body.
    fn build_block_response(
        &self,
        violations: &[Violation],
        metrics: &ValidationMetrics,
        soap_version: Option<crate::config::SoapVersion>,
    ) -> AgentResponse {
        let fault_version = soap_version.map(|v| match v {
            crate::config::SoapVersion::Soap11 => SoapFaultVersion::Soap11,
            crate::config::SoapVersion::Soap12 => SoapFaultVersion::Soap12,
        });

        let fault_body = soap_fault_response(violations, fault_version);

        let content_type = match soap_version {
            Some(crate::config::SoapVersion::Soap12) => "application/soap+xml; charset=utf-8",
            _ => "text/xml; charset=utf-8",
        };

        let mut headers_map = std::collections::HashMap::new();
        headers_map.insert("Content-Type".to_string(), content_type.to_string());

        let mut response = AgentResponse::block(500, Some(fault_body.clone()));
        response.decision = Decision::Block {
            status: 500,
            body: Some(fault_body),
            headers: Some(headers_map),
        };

        // Add debug headers if enabled
        if self.config.settings.debug_headers {
            response = self.add_debug_headers_to_response(response, metrics);
        }

        response
    }

    /// Add debug headers to a response.
    fn add_debug_headers_to_response(
        &self,
        mut response: AgentResponse,
        metrics: &ValidationMetrics,
    ) -> AgentResponse {
        response.response_headers.push(HeaderOp::Set {
            name: "X-SOAP-Body-Depth".to_string(),
            value: metrics.body_depth.to_string(),
        });
        response.response_headers.push(HeaderOp::Set {
            name: "X-SOAP-Element-Count".to_string(),
            value: metrics.element_count.to_string(),
        });
        response.response_headers.push(HeaderOp::Set {
            name: "X-SOAP-Max-Text-Length".to_string(),
            value: metrics.max_text_length.to_string(),
        });
        response
    }

    /// Add metrics headers for allow responses.
    fn add_allow_headers_to_response(
        &self,
        mut response: AgentResponse,
        metrics: &ValidationMetrics,
    ) -> AgentResponse {
        if self.config.settings.debug_headers {
            response = self.add_debug_headers_to_response(response, metrics);
        }
        response
    }

    /// Process a SOAP request and return the appropriate response.
    fn process_soap_request(
        &self,
        event: &RequestHeadersEvent,
        body: Option<&[u8]>,
    ) -> AgentResponse {
        let correlation_id = event
            .metadata
            .correlation_id
            .clone();

        let client_ip = event.metadata.client_ip.clone();

        debug!(
            correlation_id = %correlation_id,
            client_ip = %client_ip,
            method = %event.method,
            path = %event.uri,
            "Processing SOAP request"
        );

        // Check Content-Type
        let content_type = event.headers.get("content-type").and_then(|v| v.first()).map(|s| s.as_str());
        if !self.is_valid_content_type(content_type) {
            debug!(
                correlation_id = %correlation_id,
                content_type = ?content_type,
                "Non-SOAP content type, passing through"
            );
            return AgentResponse::default_allow();
        }

        // Get body
        let body = match body {
            Some(b) => b,
            None => {
                debug!(
                    correlation_id = %correlation_id,
                    "No body available, passing through"
                );
                return AgentResponse::default_allow();
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
                FailAction::Block => self.build_block_response(
                    &[violation],
                    &ValidationMetrics::default(),
                    None,
                ),
                FailAction::Allow => {
                    info!(
                        correlation_id = %correlation_id,
                        "Body too large but allowing request (fail_action=allow)"
                    );
                    AgentResponse::default_allow()
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
                    FailAction::Block => self.build_block_response(
                        &[violation],
                        &ValidationMetrics::default(),
                        None,
                    ),
                    FailAction::Allow => {
                        info!(
                            correlation_id = %correlation_id,
                            "Parsing error but allowing request (fail_action=allow)"
                        );
                        AgentResponse::default_allow()
                    }
                };
            }
        };

        // Get SOAPAction header
        let soap_action = event
            .headers
            .get("soapaction")
            .or_else(|| event.headers.get("SOAPAction"))
            .and_then(|v| v.first())
            .map(|s| parse_soap_action(s));

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
                    self.build_block_response(&result.violations, &result.metrics, result.soap_version)
                }
                FailAction::Allow => {
                    info!(
                        correlation_id = %correlation_id,
                        "Violations detected but allowing request (fail_action=allow)"
                    );
                    self.add_allow_headers_to_response(AgentResponse::default_allow(), &result.metrics)
                }
            }
        } else {
            debug!(
                correlation_id = %correlation_id,
                operation = ?result.operation,
                "SOAP request passed security checks"
            );

            let mut response = AgentResponse::default_allow();

            // Add identity header if configured and available
            if let (Some(ref header_name), Some(ref identity)) =
                (&self.config.ws_security.identity_header, &result.identity)
            {
                response.request_headers.push(HeaderOp::Set {
                    name: header_name.clone(),
                    value: identity.clone(),
                });
            }

            // Add processed header
            response.request_headers.push(HeaderOp::Set {
                name: "X-SOAP-Validated".to_string(),
                value: "true".to_string(),
            });

            if let Some(ref op) = result.operation {
                response.request_headers.push(HeaderOp::Set {
                    name: "X-SOAP-Operation".to_string(),
                    value: op.clone(),
                });
            }

            self.add_allow_headers_to_response(response, &result.metrics)
        }
    }
}

/// Agent Protocol v2 implementation.
#[async_trait]
impl AgentHandlerV2 for SoapSecurityAgent {
    /// Return agent capabilities for v2 protocol negotiation.
    fn capabilities(&self) -> AgentCapabilities {
        AgentCapabilities {
            protocol_version: 2,
            agent_id: "soap-security".to_string(),
            name: "SOAP Security Agent".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            supported_events: vec![
                EventType::RequestHeaders,
                EventType::RequestBodyChunk,
                EventType::Configure,
            ],
            features: AgentFeatures {
                streaming_body: true,
                websocket: false,
                guardrails: false,
                config_push: true,
                metrics_export: true,
                concurrent_requests: 100,
                cancellation: true,
                flow_control: false,
                health_reporting: true,
            },
            limits: AgentLimits {
                max_body_size: self.config.settings.max_body_size,
                max_concurrency: 100,
                preferred_chunk_size: 64 * 1024,
                max_memory: None,
                max_processing_time_ms: Some(5000),
            },
            health: HealthConfig {
                report_interval_ms: 10_000,
                include_load_metrics: true,
                include_resource_metrics: false,
            },
        }
    }

    /// Handle request headers event.
    async fn on_request_headers(&self, event: RequestHeadersEvent) -> AgentResponse {
        self.requests_processed.fetch_add(1, Ordering::Relaxed);

        // For v2, we may need to request the body if content-type is SOAP
        let content_type = event.headers.get("content-type").and_then(|v| v.first()).map(|s| s.as_str());

        if self.is_valid_content_type(content_type) {
            // Need body to validate SOAP - signal we need more data
            AgentResponse::needs_more_data()
        } else {
            // Not a SOAP request, allow through
            AgentResponse::default_allow()
        }
    }

    /// Handle request body chunk event.
    async fn on_request_body_chunk(
        &self,
        event: sentinel_agent_protocol::RequestBodyChunkEvent,
    ) -> AgentResponse {
        // Decode body from base64 if needed
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let body_data = STANDARD.decode(&event.data).unwrap_or_default();

        // Create a minimal RequestHeadersEvent for processing
        // In a real implementation, we'd cache headers from the initial request
        let headers_event = RequestHeadersEvent {
            metadata: sentinel_agent_protocol::RequestMetadata {
                correlation_id: event.correlation_id.clone(),
                request_id: String::new(),
                client_ip: String::new(),
                client_port: 0,
                server_name: None,
                protocol: String::new(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: String::new(),
                traceparent: None,
            },
            method: "POST".to_string(),
            uri: String::new(),
            headers: std::collections::HashMap::from([
                ("content-type".to_string(), vec!["text/xml".to_string()]),
            ]),
        };

        let response = self.process_soap_request(&headers_event, Some(&body_data));

        // Track blocked requests
        if matches!(response.decision, Decision::Block { .. }) {
            self.requests_blocked.fetch_add(1, Ordering::Relaxed);
        }

        response
    }

    /// Handle configuration updates from the proxy.
    async fn on_configure(&self, config: serde_json::Value, version: Option<String>) -> bool {
        info!(
            config_version = ?version,
            "Received configuration update"
        );

        // In a production implementation, we would:
        // 1. Parse the new configuration
        // 2. Validate it
        // 3. Hot-reload the validator with new settings
        // For now, accept but log that we don't support hot reload
        debug!(config = %config, "Configuration update received (hot reload not implemented)");

        true
    }

    /// Return current health status.
    fn health_status(&self) -> HealthStatus {
        HealthStatus::healthy("soap-security")
    }

    /// Return metrics report for the agent.
    fn metrics_report(&self) -> Option<MetricsReport> {
        use sentinel_agent_protocol::v2::CounterMetric;

        let mut report = MetricsReport::new("soap-security", 10_000);

        report.counters.push(CounterMetric::new(
            "soap_requests_processed_total",
            self.requests_processed.load(Ordering::Relaxed),
        ));

        report.counters.push(CounterMetric::new(
            "soap_requests_blocked_total",
            self.requests_blocked.load(Ordering::Relaxed),
        ));

        Some(report)
    }

    /// Handle shutdown request.
    async fn on_shutdown(&self, reason: ShutdownReason, grace_period_ms: u64) {
        info!(
            reason = ?reason,
            grace_period_ms = grace_period_ms,
            "Received shutdown request"
        );
        // Perform any cleanup needed
    }

    /// Handle drain request.
    async fn on_drain(&self, duration_ms: u64, reason: DrainReason) {
        info!(
            reason = ?reason,
            duration_ms = duration_ms,
            "Received drain request"
        );
        // Stop accepting new requests gracefully
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
                fail_action: FailAction::Block,
                allowed_content_types: vec![
                    "text/xml".to_string(),
                    "application/soap+xml".to_string(),
                    "application/xml".to_string(),
                ],
            },
            envelope: crate::config::EnvelopeConfig::default(),
            ws_security: crate::config::WsSecurityConfig::default(),
            operations: crate::config::OperationsConfig::default(),
            xxe_prevention: crate::config::XxePreventionConfig::default(),
            body_validation: crate::config::BodyValidationConfig::default(),
            version: "1".to_string(),
        }
    }

    #[test]
    fn test_agent_creation() {
        let agent = SoapSecurityAgent::new(test_config());
        let caps = agent.capabilities();
        assert_eq!(caps.agent_id, "soap-security");
        assert_eq!(caps.name, "SOAP Security Agent");
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

    #[test]
    fn test_capabilities() {
        let agent = SoapSecurityAgent::new(test_config());
        let caps = agent.capabilities();

        assert_eq!(caps.protocol_version, 2);
        assert!(caps.supported_events.contains(&EventType::RequestHeaders));
        assert!(caps.supported_events.contains(&EventType::RequestBodyChunk));
        assert!(caps.features.streaming_body);
        assert!(caps.features.metrics_export);
        assert!(caps.features.health_reporting);
    }

    #[test]
    fn test_health_status() {
        let agent = SoapSecurityAgent::new(test_config());
        let health = agent.health_status();
        assert!(health.is_healthy());
    }

    #[test]
    fn test_metrics_report() {
        let agent = SoapSecurityAgent::new(test_config());
        let report = agent.metrics_report();
        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.agent_id, "soap-security");
        assert_eq!(report.counters.len(), 2);
    }
}
