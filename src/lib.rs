//! SOAP Security Agent for Zentinel
//!
//! Provides SOAP-specific security controls including envelope validation,
//! WS-Security verification, operation control, and XXE prevention.
//!
//! # Features
//!
//! - Envelope validation (structure, version, depth)
//! - WS-Security header validation (timestamp, username token, SAML)
//! - Operation allowlist/denylist control
//! - XXE (XML External Entity) attack prevention
//! - Body content validation (element count, text length)
//! - SOAP Fault response generation
//!
//! # Protocol v2 Support
//!
//! This agent implements the Zentinel Agent Protocol v2, providing:
//! - Capability negotiation
//! - Health reporting
//! - Metrics export
//! - Configuration updates
//! - Lifecycle hooks (shutdown, drain)
//!
//! # Example
//!
//! ```ignore
//! use zentinel_agent_soap::SoapSecurityAgent;
//! use zentinel_agent_protocol::v2::GrpcAgentServerV2;
//!
//! let agent = SoapSecurityAgent::new(config);
//! let server = GrpcAgentServerV2::new("soap", Box::new(agent));
//! server.run("[::1]:50051".parse().unwrap()).await?;
//! ```

pub mod agent;
pub mod config;
pub mod error;
pub mod parser;
pub mod validator;

pub use agent::SoapSecurityAgent;
pub use config::SoapSecurityConfig;
pub use error::{SoapError, ViolationCode};
