//! Error types for the SOAP Security agent.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// SOAP security agent errors.
#[derive(Error, Debug)]
pub enum SoapError {
    #[error("XML parsing error: {0}")]
    XmlParse(String),

    #[error("Invalid SOAP envelope: {0}")]
    InvalidEnvelope(String),

    #[error("WS-Security error: {0}")]
    WsSecurity(String),

    #[error("Operation not allowed: {0}")]
    OperationNotAllowed(String),

    #[error("XXE attack detected: {0}")]
    XxeDetected(String),

    #[error("Body validation error: {0}")]
    BodyValidation(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Violation codes for SOAP security violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ViolationCode {
    /// Invalid XML syntax
    InvalidXml,
    /// Missing SOAP envelope
    MissingEnvelope,
    /// Invalid SOAP envelope structure
    InvalidEnvelopeStructure,
    /// Unsupported SOAP version
    UnsupportedVersion,
    /// Missing SOAP header
    MissingHeader,
    /// Body depth exceeded
    BodyDepthExceeded,
    /// Missing WS-Security header
    MissingSecurityHeader,
    /// Invalid timestamp
    InvalidTimestamp,
    /// Timestamp expired
    TimestampExpired,
    /// Missing username token
    MissingUsernameToken,
    /// Invalid password type
    InvalidPasswordType,
    /// Missing SAML assertion
    MissingSamlAssertion,
    /// Operation not allowed
    OperationNotAllowed,
    /// Missing SOAPAction header
    MissingSoapAction,
    /// SOAPAction mismatch
    SoapActionMismatch,
    /// DOCTYPE detected (XXE)
    DoctypeDetected,
    /// External entity detected (XXE)
    ExternalEntityDetected,
    /// Processing instruction detected
    ProcessingInstructionDetected,
    /// Entity expansion limit exceeded
    EntityExpansionExceeded,
    /// Too many elements
    TooManyElements,
    /// Text content too long
    TextTooLong,
    /// CDATA not allowed
    CdataNotAllowed,
    /// Comment not allowed
    CommentNotAllowed,
    /// Missing required namespace
    MissingNamespace,
    /// Invalid content type
    InvalidContentType,
    /// Body too large
    BodyTooLarge,
}

impl ViolationCode {
    /// Get the string code for this violation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidXml => "INVALID_XML",
            Self::MissingEnvelope => "MISSING_ENVELOPE",
            Self::InvalidEnvelopeStructure => "INVALID_ENVELOPE_STRUCTURE",
            Self::UnsupportedVersion => "UNSUPPORTED_VERSION",
            Self::MissingHeader => "MISSING_HEADER",
            Self::BodyDepthExceeded => "BODY_DEPTH_EXCEEDED",
            Self::MissingSecurityHeader => "MISSING_SECURITY_HEADER",
            Self::InvalidTimestamp => "INVALID_TIMESTAMP",
            Self::TimestampExpired => "TIMESTAMP_EXPIRED",
            Self::MissingUsernameToken => "MISSING_USERNAME_TOKEN",
            Self::InvalidPasswordType => "INVALID_PASSWORD_TYPE",
            Self::MissingSamlAssertion => "MISSING_SAML_ASSERTION",
            Self::OperationNotAllowed => "OPERATION_NOT_ALLOWED",
            Self::MissingSoapAction => "MISSING_SOAP_ACTION",
            Self::SoapActionMismatch => "SOAP_ACTION_MISMATCH",
            Self::DoctypeDetected => "DOCTYPE_DETECTED",
            Self::ExternalEntityDetected => "EXTERNAL_ENTITY_DETECTED",
            Self::ProcessingInstructionDetected => "PROCESSING_INSTRUCTION_DETECTED",
            Self::EntityExpansionExceeded => "ENTITY_EXPANSION_EXCEEDED",
            Self::TooManyElements => "TOO_MANY_ELEMENTS",
            Self::TextTooLong => "TEXT_TOO_LONG",
            Self::CdataNotAllowed => "CDATA_NOT_ALLOWED",
            Self::CommentNotAllowed => "COMMENT_NOT_ALLOWED",
            Self::MissingNamespace => "MISSING_NAMESPACE",
            Self::InvalidContentType => "INVALID_CONTENT_TYPE",
            Self::BodyTooLarge => "BODY_TOO_LARGE",
        }
    }
}

/// A security violation detected during SOAP processing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Violation {
    /// Violation code
    pub code: ViolationCode,
    /// Human-readable message
    pub message: String,
    /// XPath or location hint (if available)
    pub location: Option<String>,
}

impl Violation {
    /// Create a new violation.
    pub fn new(code: ViolationCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            location: None,
        }
    }

    /// Create a violation with location.
    pub fn with_location(code: ViolationCode, message: impl Into<String>, location: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            location: Some(location.into()),
        }
    }
}

/// Generate a SOAP Fault response for violations.
pub fn soap_fault_response(violations: &[Violation], soap_version: Option<SoapFaultVersion>) -> String {
    let version = soap_version.unwrap_or(SoapFaultVersion::Soap11);

    match version {
        SoapFaultVersion::Soap11 => soap_11_fault(violations),
        SoapFaultVersion::Soap12 => soap_12_fault(violations),
    }
}

/// SOAP Fault version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SoapFaultVersion {
    Soap11,
    Soap12,
}

fn soap_11_fault(violations: &[Violation]) -> String {
    let fault_string = violations
        .iter()
        .map(|v| format!("[{}] {}", v.code.as_str(), v.message))
        .collect::<Vec<_>>()
        .join("; ");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <soap:Fault>
      <faultcode>soap:Client</faultcode>
      <faultstring>{}</faultstring>
      <detail>
        <zentinel:violations xmlns:zentinel="urn:zentinel:soap:security">
{}
        </zentinel:violations>
      </detail>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>"#,
        xml_escape(&fault_string),
        violations
            .iter()
            .map(|v| format!(
                "          <zentinel:violation code=\"{}\">{}</zentinel:violation>",
                v.code.as_str(),
                xml_escape(&v.message)
            ))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn soap_12_fault(violations: &[Violation]) -> String {
    let reason = violations
        .iter()
        .map(|v| format!("[{}] {}", v.code.as_str(), v.message))
        .collect::<Vec<_>>()
        .join("; ");

    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope">
  <soap:Body>
    <soap:Fault>
      <soap:Code>
        <soap:Value>soap:Sender</soap:Value>
      </soap:Code>
      <soap:Reason>
        <soap:Text xml:lang="en">{}</soap:Text>
      </soap:Reason>
      <soap:Detail>
        <zentinel:violations xmlns:zentinel="urn:zentinel:soap:security">
{}
        </zentinel:violations>
      </soap:Detail>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>"#,
        xml_escape(&reason),
        violations
            .iter()
            .map(|v| format!(
                "          <zentinel:violation code=\"{}\">{}</zentinel:violation>",
                v.code.as_str(),
                xml_escape(&v.message)
            ))
            .collect::<Vec<_>>()
            .join("\n")
    )
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- ViolationCode::as_str coverage ---

    #[test]
    fn test_violation_code_as_str() {
        assert_eq!(ViolationCode::InvalidXml.as_str(), "INVALID_XML");
        assert_eq!(ViolationCode::DoctypeDetected.as_str(), "DOCTYPE_DETECTED");
    }

    #[test]
    fn test_all_violation_codes_as_str() {
        // Exhaustive check that every variant has a non-empty string code
        let codes = vec![
            (ViolationCode::InvalidXml, "INVALID_XML"),
            (ViolationCode::MissingEnvelope, "MISSING_ENVELOPE"),
            (ViolationCode::InvalidEnvelopeStructure, "INVALID_ENVELOPE_STRUCTURE"),
            (ViolationCode::UnsupportedVersion, "UNSUPPORTED_VERSION"),
            (ViolationCode::MissingHeader, "MISSING_HEADER"),
            (ViolationCode::BodyDepthExceeded, "BODY_DEPTH_EXCEEDED"),
            (ViolationCode::MissingSecurityHeader, "MISSING_SECURITY_HEADER"),
            (ViolationCode::InvalidTimestamp, "INVALID_TIMESTAMP"),
            (ViolationCode::TimestampExpired, "TIMESTAMP_EXPIRED"),
            (ViolationCode::MissingUsernameToken, "MISSING_USERNAME_TOKEN"),
            (ViolationCode::InvalidPasswordType, "INVALID_PASSWORD_TYPE"),
            (ViolationCode::MissingSamlAssertion, "MISSING_SAML_ASSERTION"),
            (ViolationCode::OperationNotAllowed, "OPERATION_NOT_ALLOWED"),
            (ViolationCode::MissingSoapAction, "MISSING_SOAP_ACTION"),
            (ViolationCode::SoapActionMismatch, "SOAP_ACTION_MISMATCH"),
            (ViolationCode::DoctypeDetected, "DOCTYPE_DETECTED"),
            (ViolationCode::ExternalEntityDetected, "EXTERNAL_ENTITY_DETECTED"),
            (ViolationCode::ProcessingInstructionDetected, "PROCESSING_INSTRUCTION_DETECTED"),
            (ViolationCode::EntityExpansionExceeded, "ENTITY_EXPANSION_EXCEEDED"),
            (ViolationCode::TooManyElements, "TOO_MANY_ELEMENTS"),
            (ViolationCode::TextTooLong, "TEXT_TOO_LONG"),
            (ViolationCode::CdataNotAllowed, "CDATA_NOT_ALLOWED"),
            (ViolationCode::CommentNotAllowed, "COMMENT_NOT_ALLOWED"),
            (ViolationCode::MissingNamespace, "MISSING_NAMESPACE"),
            (ViolationCode::InvalidContentType, "INVALID_CONTENT_TYPE"),
            (ViolationCode::BodyTooLarge, "BODY_TOO_LARGE"),
        ];

        for (code, expected) in codes {
            assert_eq!(code.as_str(), expected, "Mismatch for {:?}", code);
        }
    }

    // --- Violation constructors ---

    #[test]
    fn test_violation_new() {
        let v = Violation::new(ViolationCode::InvalidXml, "bad xml");
        assert_eq!(v.code, ViolationCode::InvalidXml);
        assert_eq!(v.message, "bad xml");
        assert!(v.location.is_none());
    }

    #[test]
    fn test_violation_with_location() {
        let v = Violation::with_location(
            ViolationCode::BodyDepthExceeded,
            "Too deep",
            "/Envelope/Body/a/b/c",
        );
        assert_eq!(v.code, ViolationCode::BodyDepthExceeded);
        assert_eq!(v.message, "Too deep");
        assert_eq!(v.location, Some("/Envelope/Body/a/b/c".to_string()));
    }

    #[test]
    fn test_violation_serialization() {
        let v = Violation::new(ViolationCode::DoctypeDetected, "DOCTYPE found");
        let json = serde_json::to_string(&v).unwrap();
        let parsed: Violation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.code, ViolationCode::DoctypeDetected);
        assert_eq!(parsed.message, "DOCTYPE found");
        assert!(parsed.location.is_none());
    }

    #[test]
    fn test_violation_with_location_serialization() {
        let v = Violation::with_location(ViolationCode::InvalidXml, "parse error", "line 5");
        let json = serde_json::to_string(&v).unwrap();
        let parsed: Violation = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.location, Some("line 5".to_string()));
    }

    // --- SOAP Fault generation ---

    #[test]
    fn test_soap_11_fault() {
        let violations = vec![
            Violation::new(ViolationCode::DoctypeDetected, "DOCTYPE declaration not allowed"),
        ];
        let fault = soap_fault_response(&violations, Some(SoapFaultVersion::Soap11));
        assert!(fault.contains("http://schemas.xmlsoap.org/soap/envelope/"));
        assert!(fault.contains("DOCTYPE_DETECTED"));
    }

    #[test]
    fn test_soap_12_fault() {
        let violations = vec![
            Violation::new(ViolationCode::InvalidXml, "Malformed XML"),
        ];
        let fault = soap_fault_response(&violations, Some(SoapFaultVersion::Soap12));
        assert!(fault.contains("http://www.w3.org/2003/05/soap-envelope"));
        assert!(fault.contains("soap:Sender"));
    }

    #[test]
    fn test_soap_fault_default_version_is_11() {
        let violations = vec![
            Violation::new(ViolationCode::InvalidXml, "error"),
        ];
        let fault = soap_fault_response(&violations, None);
        // Default should be SOAP 1.1
        assert!(fault.contains("http://schemas.xmlsoap.org/soap/envelope/"));
        assert!(fault.contains("faultcode"));
        assert!(fault.contains("faultstring"));
    }

    #[test]
    fn test_soap_11_fault_structure() {
        let violations = vec![
            Violation::new(ViolationCode::MissingEnvelope, "No SOAP envelope"),
        ];
        let fault = soap_fault_response(&violations, Some(SoapFaultVersion::Soap11));

        // Verify SOAP 1.1 fault structure
        assert!(fault.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(fault.contains("<soap:Envelope"));
        assert!(fault.contains("<soap:Body>"));
        assert!(fault.contains("<soap:Fault>"));
        assert!(fault.contains("<faultcode>soap:Client</faultcode>"));
        assert!(fault.contains("<faultstring>"));
        assert!(fault.contains("<detail>"));
        assert!(fault.contains("zentinel:violations"));
        assert!(fault.contains("zentinel:violation"));
        assert!(fault.contains("MISSING_ENVELOPE"));
    }

    #[test]
    fn test_soap_12_fault_structure() {
        let violations = vec![
            Violation::new(ViolationCode::OperationNotAllowed, "Not allowed"),
        ];
        let fault = soap_fault_response(&violations, Some(SoapFaultVersion::Soap12));

        // Verify SOAP 1.2 fault structure
        assert!(fault.contains("<?xml version=\"1.0\" encoding=\"UTF-8\"?>"));
        assert!(fault.contains("<soap:Envelope"));
        assert!(fault.contains("http://www.w3.org/2003/05/soap-envelope"));
        assert!(fault.contains("<soap:Code>"));
        assert!(fault.contains("<soap:Value>soap:Sender</soap:Value>"));
        assert!(fault.contains("<soap:Reason>"));
        assert!(fault.contains("<soap:Text xml:lang=\"en\">"));
        assert!(fault.contains("<soap:Detail>"));
        assert!(fault.contains("OPERATION_NOT_ALLOWED"));
    }

    #[test]
    fn test_soap_fault_multiple_violations() {
        let violations = vec![
            Violation::new(ViolationCode::DoctypeDetected, "DOCTYPE found"),
            Violation::new(ViolationCode::ExternalEntityDetected, "Entity found"),
            Violation::new(ViolationCode::BodyDepthExceeded, "Too deep"),
        ];
        let fault = soap_fault_response(&violations, Some(SoapFaultVersion::Soap11));

        // All violations should be present
        assert!(fault.contains("DOCTYPE_DETECTED"));
        assert!(fault.contains("EXTERNAL_ENTITY_DETECTED"));
        assert!(fault.contains("BODY_DEPTH_EXCEEDED"));

        // Faultstring should join them with semicolons
        assert!(fault.contains("; "));
    }

    #[test]
    fn test_soap_fault_empty_violations() {
        let violations: Vec<Violation> = vec![];
        let fault = soap_fault_response(&violations, Some(SoapFaultVersion::Soap11));

        // Should still produce a valid SOAP fault, just with empty faultstring
        assert!(fault.contains("<soap:Fault>"));
        assert!(fault.contains("<faultstring>"));
    }

    #[test]
    fn test_soap_fault_xml_escaping() {
        let violations = vec![
            Violation::new(
                ViolationCode::InvalidXml,
                "Invalid chars: <script>alert('xss')</script> & \"quotes\"",
            ),
        ];
        let fault = soap_fault_response(&violations, Some(SoapFaultVersion::Soap11));

        // Special characters should be escaped
        assert!(fault.contains("&lt;script&gt;"));
        assert!(fault.contains("&amp;"));
        assert!(fault.contains("&quot;quotes&quot;"));
        // Must NOT contain unescaped < > & in violation text
        assert!(!fault.contains("<script>"));
    }

    #[test]
    fn test_xml_escape_function() {
        assert_eq!(xml_escape("hello"), "hello");
        assert_eq!(xml_escape("<"), "&lt;");
        assert_eq!(xml_escape(">"), "&gt;");
        assert_eq!(xml_escape("&"), "&amp;");
        assert_eq!(xml_escape("\""), "&quot;");
        assert_eq!(xml_escape("'"), "&apos;");
        assert_eq!(
            xml_escape("<tag attr=\"val\">&data</tag>"),
            "&lt;tag attr=&quot;val&quot;&gt;&amp;data&lt;/tag&gt;"
        );
    }

    #[test]
    fn test_xml_escape_empty_string() {
        assert_eq!(xml_escape(""), "");
    }

    #[test]
    fn test_xml_escape_no_special_chars() {
        assert_eq!(xml_escape("plain text 123"), "plain text 123");
    }

    // --- SoapError ---

    #[test]
    fn test_soap_error_display() {
        let err = SoapError::XmlParse("unexpected token".to_string());
        assert_eq!(format!("{}", err), "XML parsing error: unexpected token");

        let err = SoapError::InvalidEnvelope("missing body".to_string());
        assert_eq!(format!("{}", err), "Invalid SOAP envelope: missing body");

        let err = SoapError::WsSecurity("no timestamp".to_string());
        assert_eq!(format!("{}", err), "WS-Security error: no timestamp");

        let err = SoapError::OperationNotAllowed("DeleteUser".to_string());
        assert_eq!(format!("{}", err), "Operation not allowed: DeleteUser");

        let err = SoapError::XxeDetected("DOCTYPE found".to_string());
        assert_eq!(format!("{}", err), "XXE attack detected: DOCTYPE found");

        let err = SoapError::BodyValidation("too many elements".to_string());
        assert_eq!(format!("{}", err), "Body validation error: too many elements");

        let err = SoapError::Config("invalid YAML".to_string());
        assert_eq!(format!("{}", err), "Configuration error: invalid YAML");
    }

    #[test]
    fn test_soap_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let soap_err: SoapError = io_err.into();
        assert!(format!("{}", soap_err).contains("file not found"));
    }

    // --- ViolationCode serialization ---

    #[test]
    fn test_violation_code_serde_roundtrip() {
        let codes = vec![
            ViolationCode::InvalidXml,
            ViolationCode::MissingEnvelope,
            ViolationCode::DoctypeDetected,
            ViolationCode::ExternalEntityDetected,
            ViolationCode::BodyTooLarge,
            ViolationCode::TimestampExpired,
        ];

        for code in codes {
            let json = serde_json::to_string(&code).unwrap();
            let parsed: ViolationCode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, code);
        }
    }
}
