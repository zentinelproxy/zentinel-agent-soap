//! SOAP Security Agent for Sentinel
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
//! # Example
//!
//! ```ignore
//! use sentinel_agent_soap::SoapSecurityAgent;
//! use sentinel_agent_sdk::AgentRunner;
//!
//! let agent = SoapSecurityAgent::new(config);
//! AgentRunner::new(agent)
//!     .with_socket("/tmp/soap-security.sock")
//!     .run()
//!     .await?;
//! ```

pub mod agent;
pub mod config;
pub mod error;
pub mod parser;
pub mod validator;

pub use agent::SoapSecurityAgent;
pub use config::SoapSecurityConfig;
pub use error::{SoapError, ViolationCode};
