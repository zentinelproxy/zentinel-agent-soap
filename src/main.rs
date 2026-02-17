//! Zentinel SOAP Security Agent binary.
//!
//! Run with: `zentinel-agent-soap --config config.yaml`
//!
//! Supports both UDS (Unix Domain Socket) and gRPC transports.

use anyhow::{Context, Result};
use clap::Parser;
use zentinel_agent_protocol::v2::GrpcAgentServerV2;
use zentinel_agent_soap::{SoapSecurityAgent, SoapSecurityConfig};
use std::path::PathBuf;
use tokio::signal;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// SOAP Security Agent for Zentinel proxy.
///
/// Validates SOAP messages for security concerns including envelope structure,
/// WS-Security headers, operation control, and XXE prevention.
///
/// Implements Agent Protocol v2 with support for:
/// - Capability negotiation
/// - Health reporting
/// - Metrics export
/// - Configuration push
/// - Lifecycle management (shutdown, drain)
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file (YAML)
    #[arg(short, long, default_value = "config.yaml")]
    config: PathBuf,

    /// Unix socket path for UDS transport (v1 compatibility)
    #[arg(short, long, default_value = "/tmp/zentinel-soap.sock")]
    socket: PathBuf,

    /// gRPC server address for v2 transport (e.g., "[::1]:50051" or "0.0.0.0:50051")
    #[arg(long)]
    grpc_address: Option<String>,

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

    info!("Starting Zentinel SOAP Security Agent v{}", env!("CARGO_PKG_VERSION"));
    info!("Config file: {}", args.config.display());

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

    // Determine transport and run
    if let Some(grpc_addr) = args.grpc_address {
        // Run with gRPC transport (v2 protocol)
        info!("Using gRPC transport at {}", grpc_addr);
        let addr = grpc_addr
            .parse()
            .context("Invalid gRPC address format")?;

        let server = GrpcAgentServerV2::new("soap-security", Box::new(agent));

        // Run server with graceful shutdown
        tokio::select! {
            result = server.run(addr) => {
                result.context("gRPC server error")?;
            }
            _ = shutdown_signal() => {
                info!("Shutdown signal received, stopping server");
            }
        }
    } else {
        // UDS transport - for now, log that v2 prefers gRPC
        info!("Socket path: {}", args.socket.display());
        info!("Note: For full v2 protocol support, use --grpc-address option");

        // TODO: Implement UDS v2 server when available in the SDK
        // For now, we only support gRPC in v2
        anyhow::bail!(
            "UDS transport not yet implemented for v2. Please use --grpc-address option.\n\
             Example: zentinel-agent-soap --grpc-address '[::1]:50051'"
        );
    }

    info!("SOAP Security Agent stopped");
    Ok(())
}

/// Wait for shutdown signal (Ctrl+C or SIGTERM)
async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
