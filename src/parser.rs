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
pub const WSSE_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
pub const WSU_NS: &str = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
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
    let xml_str = std::str::from_utf8(data).map_err(|e| {
        Violation::new(ViolationCode::InvalidXml, format!("Invalid UTF-8: {}", e))
    })?;

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
                    } else if in_security {
                        if local_name == "Timestamp" {
                            in_timestamp = true;
                        } else if local_name == "UsernameToken" {
                            in_username_token = true;
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
                if in_timestamp && current_depth < body_start_depth {
                    in_timestamp = false;
                    current_security.timestamp = Some(current_timestamp.clone());
                }
                if in_username_token && current_depth < body_start_depth {
                    in_username_token = false;
                    current_security.username_token = Some(current_username_token.clone());
                }
                if in_security && current_depth < body_start_depth {
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
    std::str::from_utf8(name.as_ref())
        .unwrap_or("")
        .to_string()
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
}
