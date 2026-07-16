//! Custos Network Security Appliance Entrypoint.
//!
//! This is the main orchestrator/launcher for Project Custos.

use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "custos")]
#[command(about = "Custos AF_XDP Network Security Appliance", long_about = None)]
struct Args {
    /// Network interface to bind to
    #[arg(short, long)]
    interface: Option<String>,

    /// Pin processing thread to a specific CPU core
    #[arg(short, long)]
    core: Option<usize>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Initializing Project Custos network security appliance...");

    let args = Args::parse();
    if let Some(ref iface) = args.interface {
        info!("Target interface set to: {}", iface);
    }
    if let Some(core) = args.core {
        info!("Target CPU core affinity set to: {}", core);
    }

    info!("Custos initialization complete. Running placeholder main.");
    Ok(())
}
