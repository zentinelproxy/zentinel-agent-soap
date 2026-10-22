//! Zentinel SOAP Security Agent binary.
//!
//! Run with: `zentinel-soap-agent --socket /tmp/zentinel-soap.sock`
//! (or `--grpc-address 127.0.0.1:50051`), optionally `--config soap.yaml`.
//!
//! Supports both UDS (Unix Domain Socket) and gRPC transports, agent
//! protocol v2.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tokio::signal;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;
use zentinel_agent_protocol::v2::{GrpcAgentServerV2, UdsAgentServerV2};
use zentinel_agent_soap::{SoapSecurityAgent, SoapSecurityConfig};

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
#[command(name = "zentinel-soap-agent", author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file (YAML). Without it, `config.yaml` in the
    /// working directory is used if it exists, otherwise the defaults.
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Unix socket path (UDS transport, agent protocol v2)
    #[arg(short, long, default_value = "/tmp/zentinel-soap.sock")]
    socket: PathBuf,

    /// gRPC listen address (e.g. "127.0.0.1:50051"); when given, the agent
    /// serves gRPC instead of the Unix socket
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

    info!(
        "Starting Zentinel SOAP Security Agent v{}",
        env!("CARGO_PKG_VERSION")
    );
    // Load configuration: an explicit --config must exist; the implicit
    // config.yaml is optional.
    let config_path = match args.config {
        Some(path) => Some(path),
        None => Some(PathBuf::from("config.yaml")).filter(|p| p.exists()),
    };
    let config: SoapSecurityConfig = match config_path {
        Some(path) => {
            info!("Config file: {}", path.display());
            let content = tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("Failed to read config file {}", path.display()))?;
            serde_yaml::from_str(&content)
                .with_context(|| format!("Failed to parse config file {}", path.display()))?
        }
        None => {
            info!("No config file, using defaults");
            SoapSecurityConfig::default()
        }
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
        let addr = grpc_addr.parse().context("Invalid gRPC address format")?;

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
        // UDS transport (v2 protocol)
        info!("Using UDS transport at {}", args.socket.display());
        let socket = args.socket.clone();
        let server = UdsAgentServerV2::new("soap-security", args.socket, Box::new(agent));

        tokio::select! {
            result = server.run() => {
                result.context("UDS server error")?;
            }
            _ = shutdown_signal() => {
                info!("Shutdown signal received, stopping server");
            }
        }
        let _ = std::fs::remove_file(&socket);
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
