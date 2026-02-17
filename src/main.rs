//! Zentinel ModSecurity Agent CLI
//!
//! Command-line interface for the ModSecurity WAF agent.
//!
//! Supports both Unix Domain Socket and gRPC transports for v2 protocol.

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

use zentinel_agent_modsec::{ModSecAgent, ModSecConfig};
use zentinel_agent_protocol::{AgentServer, v2::GrpcAgentServerV2};

/// Command line arguments
#[derive(Parser, Debug)]
#[command(name = "zentinel-modsec-agent")]
#[command(about = "ModSecurity WAF agent for Zentinel reverse proxy - full OWASP CRS support")]
struct Args {
    /// Path to Unix socket (mutually exclusive with --grpc-address)
    #[arg(
        long,
        default_value = "/tmp/zentinel-modsec.sock",
        env = "AGENT_SOCKET"
    )]
    socket: PathBuf,

    /// gRPC server address (e.g., 0.0.0.0:50051). If set, uses gRPC transport instead of UDS.
    #[arg(long, env = "AGENT_GRPC_ADDRESS")]
    grpc_address: Option<SocketAddr>,

    /// Paths to ModSecurity rule files (can be specified multiple times)
    #[arg(long = "rules", env = "MODSEC_RULES", value_delimiter = ',')]
    rules_paths: Vec<String>,

    /// Block mode (true) or detect-only mode (false)
    #[arg(long, default_value = "true", env = "MODSEC_BLOCK_MODE")]
    block_mode: bool,

    /// Paths to exclude from inspection (comma-separated)
    #[arg(long, env = "MODSEC_EXCLUDE_PATHS")]
    exclude_paths: Option<String>,

    /// Enable request body inspection
    #[arg(long, default_value = "true", env = "MODSEC_BODY_INSPECTION")]
    body_inspection: bool,

    /// Maximum body size to inspect in bytes (default 1MB)
    #[arg(long, default_value = "1048576", env = "MODSEC_MAX_BODY_SIZE")]
    max_body_size: usize,

    /// Enable response body inspection
    #[arg(long, default_value = "false", env = "MODSEC_RESPONSE_INSPECTION")]
    response_inspection: bool,

    /// Enable verbose logging
    #[arg(short, long, env = "MODSEC_VERBOSE")]
    verbose: bool,
}

impl Args {
    fn to_config(&self) -> ModSecConfig {
        let exclude_paths = self
            .exclude_paths
            .as_ref()
            .map(|p| p.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        ModSecConfig {
            rules_paths: self.rules_paths.clone(),
            block_mode: self.block_mode,
            exclude_paths,
            body_inspection_enabled: self.body_inspection,
            max_body_size: self.max_body_size,
            response_inspection_enabled: self.response_inspection,
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let args = Args::parse();

    // Initialize tracing
    let log_level = if args.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!(
            "{}={},zentinel_agent_protocol=info",
            env!("CARGO_CRATE_NAME"),
            log_level
        ))
        .json()
        .init();

    info!("Starting Zentinel ModSecurity Agent");

    // Build configuration
    let config = args.to_config();

    info!(
        rules_count = config.rules_paths.len(),
        block_mode = config.block_mode,
        body_inspection = config.body_inspection_enabled,
        response_inspection = config.response_inspection_enabled,
        max_body_size = config.max_body_size,
        "Configuration loaded"
    );

    if config.rules_paths.is_empty() {
        tracing::warn!("No rules paths configured - ModSecurity will not block any requests");
        tracing::warn!(
            "Use --rules to specify rule files, e.g.: --rules /etc/modsecurity/crs/rules/*.conf"
        );
    }

    // Create agent
    let agent = ModSecAgent::new(config)?;

    // Start agent server based on transport mode
    if let Some(grpc_addr) = args.grpc_address {
        // gRPC transport (v2 protocol)
        info!(address = %grpc_addr, "Starting gRPC v2 agent server");
        let server = GrpcAgentServerV2::new("zentinel-modsec-agent", Box::new(agent));
        server.run(grpc_addr).await.map_err(|e| anyhow::anyhow!("{}", e))?;
    } else {
        // UDS transport (v1 protocol - for backward compatibility)
        info!(socket = ?args.socket, "Starting UDS agent server");
        let server = AgentServer::new("zentinel-modsec-agent", args.socket, Box::new(agent));
        server.run().await.map_err(|e| anyhow::anyhow!("{}", e))?;
    }

    Ok(())
}
