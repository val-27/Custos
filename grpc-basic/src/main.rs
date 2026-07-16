//! Phase 2: Header Stripping & gRPC Validation.
//!
//! Provides the CLI and thread-pinning scaffold for future Ethernet/IP/TCP,
//! HTTP/2 framing, and basic gRPC validation work.

use clap::Parser;
use std::error::Error;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "custos-grpc-basic")]
#[command(about = "Phase 2: Header Stripping and gRPC Validation", long_about = None)]
struct Args {
    /// Interface name to bind to
    #[arg(short, long)]
    interface: String,

    /// CPU core to pin the loop thread to
    #[arg(short, long, default_value_t = 2)]
    core: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    info!(
        "Initializing custos-grpc-basic on interface: {}",
        args.interface
    );

    // Pin current thread to core
    custos_common::pin_thread_to_core(args.core)?;

    info!("Poller thread pinned. Phase 2 setup ready.");

    // TODO: Implement Ethernet/IP/TCP parsing, HTTP/2 state-machine validation, and gRPC payload parsing.

    Ok(())
}
