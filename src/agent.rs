//! Main SOAP Security Agent implementation.
//!
//! Coordinates all validators and integrates with Zentinel Agent Protocol v2.

use crate::config::{FailAction, SoapSecurityConfig};
use crate::error::{soap_fault_response, SoapFaultVersion, Violation, ViolationCode};
use crate::parser::{parse_soap_action, parse_soap_envelope};
use crate::validator::{SoapValidator, ValidationMetrics};
use async_trait::async_trait;
use zentinel_agent_protocol::v2::{
    AgentCapabilities, AgentFeatures, AgentHandlerV2, AgentLimits, DrainReason, HealthConfig,
    HealthStatus, MetricsReport, ShutdownReason,
};
use zentinel_agent_protocol::{
    AgentResponse, Decision, EventType, HeaderOp, RequestHeadersEvent,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

/// SOAP Security Agent for Zentinel.
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
        event: zentinel_agent_protocol::RequestBodyChunkEvent,
    ) -> AgentResponse {
        // Decode body from base64 if needed
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let body_data = STANDARD.decode(&event.data).unwrap_or_default();

        // Create a minimal RequestHeadersEvent for processing
        // In a real implementation, we'd cache headers from the initial request
        let headers_event = RequestHeadersEvent {
            metadata: zentinel_agent_protocol::RequestMetadata {
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
        use zentinel_agent_protocol::v2::CounterMetric;

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
    use crate::config::{
        BodyValidationConfig, EnvelopeConfig, OperationMode, OperationsConfig,
        SettingsConfig, WsSecurityConfig, XxePreventionConfig,
    };
    use std::collections::HashMap;
    use zentinel_agent_protocol::RequestMetadata;

    fn test_config() -> SoapSecurityConfig {
        SoapSecurityConfig {
            settings: SettingsConfig {
                max_body_size: 1_048_576,
                debug_headers: true,
                fail_action: FailAction::Block,
                allowed_content_types: vec![
                    "text/xml".to_string(),
                    "application/soap+xml".to_string(),
                    "application/xml".to_string(),
                ],
            },
            envelope: EnvelopeConfig::default(),
            ws_security: WsSecurityConfig::default(),
            operations: OperationsConfig::default(),
            xxe_prevention: XxePreventionConfig::default(),
            body_validation: BodyValidationConfig::default(),
            version: "1".to_string(),
        }
    }

    fn make_request_event(
        content_type: Option<&str>,
        soap_action: Option<&str>,
    ) -> RequestHeadersEvent {
        let mut headers = HashMap::new();
        if let Some(ct) = content_type {
            headers.insert("content-type".to_string(), vec![ct.to_string()]);
        }
        if let Some(sa) = soap_action {
            headers.insert("soapaction".to_string(), vec![sa.to_string()]);
        }

        RequestHeadersEvent {
            metadata: RequestMetadata {
                correlation_id: "test-corr-123".to_string(),
                request_id: "test-req-456".to_string(),
                client_ip: "127.0.0.1".to_string(),
                client_port: 12345,
                server_name: None,
                protocol: "HTTP/1.1".to_string(),
                tls_version: None,
                tls_cipher: None,
                route_id: None,
                upstream_id: None,
                timestamp: "2025-01-01T00:00:00Z".to_string(),
                traceparent: None,
            },
            method: "POST".to_string(),
            uri: "/soap/service".to_string(),
            headers,
        }
    }

    // --- Agent creation ---

    #[test]
    fn test_agent_creation() {
        let agent = SoapSecurityAgent::new(test_config());
        let caps = agent.capabilities();
        assert_eq!(caps.agent_id, "soap-security");
        assert_eq!(caps.name, "SOAP Security Agent");
    }

    // --- Content type validation ---

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
    fn test_content_type_application_xml() {
        let agent = SoapSecurityAgent::new(test_config());
        assert!(agent.is_valid_content_type(Some("application/xml")));
        assert!(agent.is_valid_content_type(Some("Application/XML; charset=utf-8")));
    }

    #[test]
    fn test_content_type_not_soap() {
        let agent = SoapSecurityAgent::new(test_config());
        assert!(!agent.is_valid_content_type(Some("text/html")));
        assert!(!agent.is_valid_content_type(Some("text/plain")));
        assert!(!agent.is_valid_content_type(Some("multipart/form-data")));
        assert!(!agent.is_valid_content_type(Some("")));
    }

    // --- Capabilities ---

    #[test]
    fn test_capabilities() {
        let agent = SoapSecurityAgent::new(test_config());
        let caps = agent.capabilities();

        assert_eq!(caps.protocol_version, 2);
        assert!(caps.supported_events.contains(&EventType::RequestHeaders));
        assert!(caps.supported_events.contains(&EventType::RequestBodyChunk));
        assert!(caps.supported_events.contains(&EventType::Configure));
        assert_eq!(caps.supported_events.len(), 3);
        assert!(caps.features.streaming_body);
        assert!(caps.features.metrics_export);
        assert!(caps.features.health_reporting);
        assert!(caps.features.config_push);
        assert!(caps.features.cancellation);
        assert!(!caps.features.websocket);
        assert!(!caps.features.guardrails);
        assert!(!caps.features.flow_control);
        assert_eq!(caps.features.concurrent_requests, 100);
    }

    #[test]
    fn test_capabilities_limits() {
        let agent = SoapSecurityAgent::new(test_config());
        let caps = agent.capabilities();

        assert_eq!(caps.limits.max_body_size, 1_048_576);
        assert_eq!(caps.limits.max_concurrency, 100);
        assert_eq!(caps.limits.preferred_chunk_size, 64 * 1024);
        assert!(caps.limits.max_memory.is_none());
        assert_eq!(caps.limits.max_processing_time_ms, Some(5000));
    }

    #[test]
    fn test_capabilities_health_config() {
        let agent = SoapSecurityAgent::new(test_config());
        let caps = agent.capabilities();

        assert_eq!(caps.health.report_interval_ms, 10_000);
        assert!(caps.health.include_load_metrics);
        assert!(!caps.health.include_resource_metrics);
    }

    #[test]
    fn test_capabilities_max_body_size_reflects_config() {
        let mut config = test_config();
        config.settings.max_body_size = 5_000_000;
        let agent = SoapSecurityAgent::new(config);
        let caps = agent.capabilities();
        assert_eq!(caps.limits.max_body_size, 5_000_000);
    }

    // --- Health status ---

    #[test]
    fn test_health_status() {
        let agent = SoapSecurityAgent::new(test_config());
        let health = agent.health_status();
        assert!(health.is_healthy());
    }

    // --- Metrics ---

    #[test]
    fn test_metrics_report() {
        let agent = SoapSecurityAgent::new(test_config());
        let report = agent.metrics_report();
        assert!(report.is_some());
        let report = report.unwrap();
        assert_eq!(report.agent_id, "soap-security");
        assert_eq!(report.counters.len(), 2);
    }

    #[test]
    fn test_metrics_initial_values() {
        let agent = SoapSecurityAgent::new(test_config());
        let report = agent.metrics_report().unwrap();

        // Initially, all counters should be 0
        for counter in &report.counters {
            assert_eq!(counter.value, 0);
        }
    }

    #[test]
    fn test_metrics_counter_names() {
        let agent = SoapSecurityAgent::new(test_config());
        let report = agent.metrics_report().unwrap();

        let names: Vec<&str> = report.counters.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"soap_requests_processed_total"));
        assert!(names.contains(&"soap_requests_blocked_total"));
    }

    // --- process_soap_request: non-SOAP pass-through ---

    #[test]
    fn test_non_soap_content_type_passes_through() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("application/json"), None);
        let body = b"not soap";

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Allow));
    }

    #[test]
    fn test_no_content_type_passes_through() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(None, None);
        let body = b"some body";

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Allow));
    }

    #[test]
    fn test_no_body_passes_through() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("text/xml"), None);

        let response = agent.process_soap_request(&event, None);
        assert!(matches!(response.decision, Decision::Allow));
    }

    // --- process_soap_request: body too large ---

    #[test]
    fn test_body_too_large_blocked() {
        let mut config = test_config();
        config.settings.max_body_size = 100;
        config.settings.fail_action = FailAction::Block;

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), None);
        let body = vec![b'x'; 200];

        let response = agent.process_soap_request(&event, Some(&body));
        assert!(matches!(response.decision, Decision::Block { .. }));
    }

    #[test]
    fn test_body_too_large_allowed_when_fail_action_allow() {
        let mut config = test_config();
        config.settings.max_body_size = 100;
        config.settings.fail_action = FailAction::Allow;

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), None);
        let body = vec![b'x'; 200];

        let response = agent.process_soap_request(&event, Some(&body));
        assert!(matches!(response.decision, Decision::Allow));
    }

    // --- process_soap_request: valid SOAP ---

    #[test]
    fn test_valid_soap_request_allowed() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.org/users">
      <m:UserId>123</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Allow));

        // Should have X-SOAP-Validated header
        assert!(response.request_headers.iter().any(|h| matches!(
            h,
            HeaderOp::Set { name, value } if name == "X-SOAP-Validated" && value == "true"
        )));

        // Should have X-SOAP-Operation header
        assert!(response.request_headers.iter().any(|h| matches!(
            h,
            HeaderOp::Set { name, value } if name == "X-SOAP-Operation" && value == "GetUser"
        )));
    }

    #[test]
    fn test_valid_soap_12_request_allowed() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("application/soap+xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <m:ListUsers xmlns:m="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Allow));
    }

    // --- process_soap_request: debug headers ---

    #[test]
    fn test_debug_headers_on_allow_response() {
        let mut config = test_config();
        config.settings.debug_headers = true;

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Allow));

        // Debug headers should be present
        assert!(response.response_headers.iter().any(|h| matches!(
            h,
            HeaderOp::Set { name, .. } if name == "X-SOAP-Body-Depth"
        )));
        assert!(response.response_headers.iter().any(|h| matches!(
            h,
            HeaderOp::Set { name, .. } if name == "X-SOAP-Element-Count"
        )));
        assert!(response.response_headers.iter().any(|h| matches!(
            h,
            HeaderOp::Set { name, .. } if name == "X-SOAP-Max-Text-Length"
        )));
    }

    #[test]
    fn test_debug_headers_disabled() {
        let mut config = test_config();
        config.settings.debug_headers = false;

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Allow));

        // Debug headers should NOT be present
        assert!(!response.response_headers.iter().any(|h| matches!(
            h,
            HeaderOp::Set { name, .. } if name == "X-SOAP-Body-Depth"
        )));
    }

    // --- process_soap_request: malformed XML ---

    #[test]
    fn test_malformed_xml_blocked() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("text/xml"), None);
        let body = b"<this is not valid xml>><<";

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Block { .. }));
    }

    #[test]
    fn test_malformed_xml_allowed_with_fail_action_allow() {
        let mut config = test_config();
        config.settings.fail_action = FailAction::Allow;

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), None);
        let body = b"<this is not valid xml>><<";

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Allow));
    }

    // --- process_soap_request: XXE attack ---

    #[test]
    fn test_xxe_attack_blocked() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>&xxe;</soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Block { .. }));
    }

    // --- process_soap_request: operation control ---

    #[test]
    fn test_blocked_operation_returns_fault() {
        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.mode = OperationMode::Allowlist;
        config.operations.actions = vec!["GetUser".to_string()];

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DeleteUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Block { .. }));

        if let Decision::Block { status, body, headers } = &response.decision {
            assert_eq!(*status, 500);
            assert!(body.as_ref().unwrap().contains("OPERATION_NOT_ALLOWED"));
            // Content-Type should be text/xml for SOAP 1.1
            let ct = headers.as_ref().unwrap().get("Content-Type").unwrap();
            assert!(ct.contains("text/xml"));
        }
    }

    #[test]
    fn test_allowed_operation_passes() {
        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.mode = OperationMode::Allowlist;
        config.operations.actions = vec!["GetUser".to_string()];

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Allow));
    }

    // --- process_soap_request: violations with fail_action=allow ---

    #[test]
    fn test_violations_with_allow_mode_pass_through() {
        let mut config = test_config();
        config.settings.fail_action = FailAction::Allow;
        config.operations.enabled = true;
        config.operations.mode = OperationMode::Allowlist;
        config.operations.actions = vec!["SafeOnly".to_string()];

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DangerousOp xmlns="http://example.org/danger"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        // Should be allowed even though operation is not in the allowlist
        assert!(matches!(response.decision, Decision::Allow));
    }

    // --- process_soap_request: SOAP 1.2 block response content type ---

    #[test]
    fn test_soap_12_block_response_content_type() {
        let mut config = test_config();
        config.envelope.allowed_versions = vec![crate::config::SoapVersion::Soap11]; // Reject 1.2

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("application/soap+xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Block { .. }));

        if let Decision::Block { headers, .. } = &response.decision {
            let ct = headers.as_ref().unwrap().get("Content-Type").unwrap();
            // SOAP 1.2 block response should use application/soap+xml
            assert!(ct.contains("application/soap+xml"));
        }
    }

    // --- process_soap_request: SOAPAction header ---

    #[test]
    fn test_soap_action_header_used_in_validation() {
        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.validate_action_match = true;

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), Some("\"GetUser\""));
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        // SOAPAction matches body, should pass
        assert!(matches!(response.decision, Decision::Allow));
    }

    #[test]
    fn test_soap_action_mismatch_blocked() {
        let mut config = test_config();
        config.operations.enabled = true;
        config.operations.validate_action_match = true;

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), Some("\"DeleteUser\""));
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Block { .. }));
    }

    // --- process_soap_request: identity header ---

    #[test]
    fn test_identity_header_not_set_when_ws_security_disabled() {
        let mut config = test_config();
        config.ws_security.enabled = false;
        config.ws_security.identity_header = Some("X-Authenticated-User".to_string());

        let agent = SoapSecurityAgent::new(config);
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        assert!(matches!(response.decision, Decision::Allow));

        // Identity header should NOT be present (WS-Security is disabled)
        assert!(!response.request_headers.iter().any(|h| matches!(
            h,
            HeaderOp::Set { name, .. } if name == "X-Authenticated-User"
        )));
    }

    // --- process_soap_request: empty body ---

    #[test]
    fn test_empty_soap_body() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
  </soap:Body>
</soap:Envelope>"#;

        let response = agent.process_soap_request(&event, Some(body));
        // Valid envelope, just empty body - should be allowed
        assert!(matches!(response.decision, Decision::Allow));
    }

    // --- Async handler tests ---

    #[tokio::test]
    async fn test_on_request_headers_soap_needs_body() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("text/xml"), None);

        let response = agent.on_request_headers(event).await;
        // SOAP requests should signal they need more data (the body).
        // needs_more_data() returns Decision::Allow with needs_more=true.
        assert!(matches!(response.decision, Decision::Allow));
        assert!(response.needs_more);
    }

    #[tokio::test]
    async fn test_on_request_headers_non_soap_allows() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("application/json"), None);

        let response = agent.on_request_headers(event).await;
        assert!(matches!(response.decision, Decision::Allow));
    }

    #[tokio::test]
    async fn test_on_request_headers_no_content_type_allows() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(None, None);

        let response = agent.on_request_headers(event).await;
        assert!(matches!(response.decision, Decision::Allow));
    }

    #[tokio::test]
    async fn test_on_configure_returns_true() {
        let agent = SoapSecurityAgent::new(test_config());
        let config_json = serde_json::json!({"envelope": {"max_body_depth": 5}});

        let accepted = agent.on_configure(config_json, Some("v2".to_string())).await;
        assert!(accepted);
    }

    #[tokio::test]
    async fn test_on_configure_no_version() {
        let agent = SoapSecurityAgent::new(test_config());
        let config_json = serde_json::json!({});

        let accepted = agent.on_configure(config_json, None).await;
        assert!(accepted);
    }

    #[tokio::test]
    async fn test_on_shutdown() {
        let agent = SoapSecurityAgent::new(test_config());
        // Should not panic -- test that the method completes without error
        agent.on_shutdown(ShutdownReason::Graceful, 5000).await;
    }

    #[tokio::test]
    async fn test_on_drain() {
        let agent = SoapSecurityAgent::new(test_config());
        // Should not panic -- test that the method completes without error
        agent.on_drain(10000, DrainReason::Maintenance).await;
    }

    // --- Atomic counter tracking ---

    #[test]
    fn test_request_counter_increments() {
        let agent = SoapSecurityAgent::new(test_config());
        let event = make_request_event(Some("text/xml"), None);
        let body = br#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        // Process a request via process_soap_request (doesn't touch counters directly)
        let _response = agent.process_soap_request(&event, Some(body));

        // The process_soap_request doesn't increment counters, only the async handlers do
        // So counters should still be 0
        assert_eq!(agent.requests_processed.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}
