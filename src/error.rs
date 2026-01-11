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
        <sentinel:violations xmlns:sentinel="urn:sentinel:soap:security">
{}
        </sentinel:violations>
      </detail>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>"#,
        xml_escape(&fault_string),
        violations
            .iter()
            .map(|v| format!(
                "          <sentinel:violation code=\"{}\">{}</sentinel:violation>",
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
        <sentinel:violations xmlns:sentinel="urn:sentinel:soap:security">
{}
        </sentinel:violations>
      </soap:Detail>
    </soap:Fault>
  </soap:Body>
</soap:Envelope>"#,
        xml_escape(&reason),
        violations
            .iter()
            .map(|v| format!(
                "          <sentinel:violation code=\"{}\">{}</sentinel:violation>",
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

    #[test]
    fn test_violation_code_as_str() {
        assert_eq!(ViolationCode::InvalidXml.as_str(), "INVALID_XML");
        assert_eq!(ViolationCode::DoctypeDetected.as_str(), "DOCTYPE_DETECTED");
    }

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
}
