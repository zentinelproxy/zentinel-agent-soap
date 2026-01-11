//! Sentinel SOAP Security Agent binary.
//!
//! Run with: `sentinel-agent-soap --config config.yaml`

use anyhow::{Context, Result};
use clap::Parser;
use sentinel_agent_sdk::AgentRunner;
use sentinel_agent_soap::{SoapSecurityAgent, SoapSecurityConfig};
use std::path::PathBuf;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// SOAP Security Agent for Sentinel proxy.
///
/// Validates SOAP messages for security concerns including envelope structure,
/// WS-Security headers, operation control, and XXE prevention.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file (YAML)
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Unix socket path for agent communication
    #[arg(short, long, default_value = "/tmp/sentinel-soap.sock")]
    socket: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[arg(short, long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = args.log_level.parse().unwrap_or(Level::INFO);
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(true)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .context("Failed to set tracing subscriber")?;

    info!("Starting Sentinel SOAP Security Agent");
    info!("Config file: {}", args.config.display());
    info!("Socket path: {}", args.socket.display());

    // Load configuration
    let config = if args.config.exists() {
        let content = tokio::fs::read_to_string(&args.config)
            .await
            .context("Failed to read config file")?;
        serde_yaml::from_str(&content).context("Failed to parse config file")?
    } else {
        info!("Config file not found, using defaults");
        SoapSecurityConfig::default()
    };

    info!(
        envelope_validation = config.envelope.enabled,
        ws_security = config.ws_security.enabled,
        operations_control = config.operations.enabled,
        xxe_prevention = config.xxe_prevention.enabled,
        "Configuration loaded"
    );

    // Create the agent
    let agent = SoapSecurityAgent::new(config);

    info!("Agent initialized successfully");

    // Run the agent
    AgentRunner::new(agent)
        .with_name("soap")
        .with_socket(args.socket)
        .run()
        .await
        .context("Agent runtime error")?;

    Ok(())
}
