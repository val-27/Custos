//! Phase 3: Protobuf Tag Walking, Guards, and Stats.
//!
//! Deep packet inspection of gRPC-over-HTTP/2 payloads. Zero-allocation parsing
//! of protobuf fields (varints, wire types) to enforce security rules and track statistics.

use clap::Parser;
use std::error::Error;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "custos-protobuf")]
#[command(about = "Phase 3: Protobuf Tag Walking and Security Guards", long_about = None)]
struct Args {
    /// Interface name to bind to
    #[arg(short, long)]
    interface: String,

    /// CPU core to pin the loop thread to
    #[arg(short, long, default_value_t = 3)]
    core: usize,
}

fn main() -> Result<(), Box<dyn Error>> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let args = Args::parse();
    info!("Initializing custos-protobuf on interface: {}", args.interface);

    // Pin current thread to core
    custos_common::pin_thread_to_core(args.core)?;

    info!("Poller thread pinned. Phase 3 setup ready.");
    
    // TODO: Implement zero-copy varint parsing, tag walking, security guards, and telemetry.
    
    Ok(())
}
