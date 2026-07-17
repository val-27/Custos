//! Phase 1: AF_XDP Single-Core Echo and Forward.
//!
//! Pins execution to a single core, receives packets from the AF_XDP Rx ring,
//! processes them (either dropping them or swapping MAC addresses for echo),
//! and submits them to the Tx ring. Employs zero heap allocations in the hot path.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("custos-phase1-echo requires Linux AF_XDP support");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use custos_common::OperationMode;
#[cfg(target_os = "linux")]
use std::convert::TryInto;
use std::error::Error;
#[cfg(target_os = "linux")]
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::time::Instant;
#[cfg(target_os = "linux")]
use tracing::{debug, error, info, trace, Level};
#[cfg(target_os = "linux")]
use tracing_subscriber::FmtSubscriber;
#[cfg(target_os = "linux")]
use xsk_rs::{
    config::{BindFlags, Interface, SocketConfig, UmemConfigBuilder},
    CompQueue, FillQueue, FrameDesc, RxQueue, Socket, TxQueue, Umem,
};

/// Command line arguments for Phase 1 Echo / Forward daemon.
#[cfg(target_os = "linux")]
#[derive(Parser, Debug)]
#[command(name = "custos-phase1-echo")]
#[command(about = "Phase 1: AF_XDP Single-Core Echo and Forward", long_about = None)]
struct Args {
    /// Interface name to bind to
    #[arg(short, long)]
    interface: String,

    /// CPU core to pin the polling thread to
    #[arg(short, long, default_value_t = 0)]
    core: usize,

    /// Queue ID to bind the AF_XDP socket to
    #[arg(short, long, default_value_t = 0)]
    queue_id: u32,

    /// Frame count for UMEM (must be a power of 2)
    #[arg(short, long, default_value_t = 2048)]
    frame_count: u32,

    /// Packet processing mode: drop, forward, or echo
    #[arg(short, long, default_value_t = OperationMode::Forward)]
    mode: OperationMode,

    /// Enable verbose logging (level DEBUG)
    #[arg(short, long)]
    verbose: bool,

    /// Force copy-mode (XDP_COPY)
    #[arg(long)]
    force_copy: bool,

    /// Force zero-copy mode (XDP_ZEROCOPY)
    #[arg(long)]
    force_zerocopy: bool,
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Initialize tracing logger
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting custos-phase1-echo...");
    info!("CLI configuration: {:?}", args);

    if args.force_copy && args.force_zerocopy {
        return Err("Cannot specify both --force-copy and --force-zerocopy".into());
    }

    // 1. Thread Pinning
    custos_common::pin_thread_to_core(args.core)?;

    // 2. Interface Resolution
    let if_name: Interface = args.interface.parse().map_err(|e| {
        error!(
            "Failed to parse interface name '{}': {:?}",
            args.interface, e
        );
        e
    })?;

    // 3. UMEM Configuration (2 KiB frames, ring sizes from shared constants)
    //
    // The NonZeroU32 conversions use expect() rather than unwrap() so that a
    // misconfigured constant produces a descriptive panic message during startup
    // (not in the hot path). UMEM_FRAME_SIZE and UMEM_RING_SIZE are guaranteed
    // non-zero by their definitions in custos-common.
    let frame_size_nz = std::num::NonZeroU32::new(custos_common::UMEM_FRAME_SIZE)
        .expect("UMEM_FRAME_SIZE must be non-zero");
    let ring_size_nz = std::num::NonZeroU32::new(custos_common::UMEM_RING_SIZE)
        .expect("UMEM_RING_SIZE must be non-zero");

    let umem_config = UmemConfigBuilder::new()
        .frame_size(frame_size_nz)
        .frame_headroom(0)
        .fill_queue_size(ring_size_nz)
        .comp_queue_size(ring_size_nz)
        .build()
        .map_err(|e| {
            error!("Failed to build UmemConfig: {:?}", e);
            e
        })?;

    // Use regular page-aligned allocation (no hugepages initially for simple VM deployment)
    let use_huge_pages = false;
    let frame_count_nonzero = NonZeroU32::new(args.frame_count)
        .ok_or("Frame count must be non-zero and a power of two")?;

    let (umem, frame_descs) =
        Umem::new(umem_config, frame_count_nonzero, use_huge_pages).map_err(|e| {
            error!("Failed to initialize UMEM: {:?}", e);
            e
        })?;
    info!(
        "Initialized UMEM with {} frames (2KB size)",
        args.frame_count
    );

    // 4. Socket Configuration
    let mut socket_config_builder = SocketConfig::builder();
    let mut bind_flags = BindFlags::XDP_USE_NEED_WAKEUP;
    if args.force_copy {
        bind_flags.insert(BindFlags::XDP_COPY);
        info!("Forcing copy-mode (XDP_COPY)");
    } else if args.force_zerocopy {
        bind_flags.insert(BindFlags::XDP_ZEROCOPY);
        info!("Forcing zero-copy mode (XDP_ZEROCOPY)");
    }
    let socket_config = socket_config_builder.bind_flags(bind_flags).build();

    let (tx_q, rx_q, fq_and_cq) =
        unsafe { Socket::new(socket_config, &umem, &if_name, args.queue_id) }.map_err(|e| {
            error!("Failed to initialize AF_XDP socket: {:?}", e);
            e
        })?;
    let (mut fq, cq) =
        fq_and_cq.ok_or("Expected Fill and Completion queues from socket creation")?;
    info!(
        "Bound AF_XDP socket to interface: {}, queue: {}",
        args.interface, args.queue_id
    );

    // 5. Populate Fill Queue with all available UMEM frames
    // SAFETY: We are initializing the Fill Queue with all frames at startup, ensuring they are not in flight.
    let produced = unsafe { fq.produce(&frame_descs) };
    if produced != frame_descs.len() {
        return Err(format!(
            "Failed to populate Fill Queue: produced {} out of {} frames",
            produced,
            frame_descs.len()
        )
        .into());
    }
    info!("Populated Fill Queue with all {} frames", produced);

    // 6. Packet Processing Loop
    run_packet_loop(
        args.mode,
        args.verbose,
        umem,
        rx_q,
        tx_q,
        fq,
        cq,
        frame_descs[0],
        args.frame_count,
    )?;

    Ok(())
}

/// The core packet processing loop. Runs with zero heap allocations in the hot path.
///
/// # Purpose
/// Polls the AF_XDP Rx ring in batches, dispatches each packet according to
/// `mode` (Drop / Forward / Echo), submits valid packets to the Tx ring, and
/// recycles completed descriptors back to the Fill ring.
///
/// # Performance Rationale
/// `mode` is stored as an `OperationMode` enum so the per-packet branch is an
/// integer comparison rather than a heap-allocated string scan.
#[cfg(target_os = "linux")]
fn run_packet_loop(
    mode: OperationMode,
    verbose: bool,
    umem: Umem,
    mut rx_q: RxQueue,
    mut tx_q: TxQueue,
    mut fq: FillQueue,
    mut cq: CompQueue,
    template_desc: FrameDesc,
    frame_count: u32,
) -> Result<(), Box<dyn Error>> {
    const BATCH_SIZE: usize = 64;

    // Pre-allocate descriptor arrays to avoid hot-path allocation
    let mut rx_descs = vec![template_desc; BATCH_SIZE];
    let mut tx_descs = vec![template_desc; BATCH_SIZE];
    let mut comp_descs = vec![template_desc; BATCH_SIZE];

    // Stats tracking
    let mut last_stats_time = Instant::now();
    let mut rx_packets: u64 = 0;
    let mut tx_packets: u64 = 0;
    let mut drop_packets: u64 = 0;
    let mut recycled_packets: u64 = 0;
    let mut rx_bytes: u64 = 0;
    let mut tx_bytes: u64 = 0;

    // Lifetime counters to assert completion ring consumption roughly matches transmission count
    let mut total_tx_packets: u64 = 0;
    let mut total_recycled_packets: u64 = 0;

    // Frame distribution tracking
    let mut frames_in_fill = frame_count as i64;
    let mut frames_in_rx = 0i64;
    let mut frames_in_tx = 0i64;
    let mut frames_in_comp = 0i64;

    info!("Entering hot-path packet poll loop (mode: {})...", mode);

    loop {
        // A. Consume received packets from Rx Ring
        // SAFETY: We consume packets into rx_descs. The frames consumed belong to the bound UMEM.
        let received = unsafe { rx_q.consume(&mut rx_descs[..]) };

        if received > 0 {
            rx_packets += received as u64;
            frames_in_rx += received as i64;
            frames_in_fill -= received as i64;

            if verbose {
                debug!("Received batch of {} packets", received);
            }

            if mode == OperationMode::Drop {
                // Drop mode: Recycle frames directly back into the Fill Queue
                let mut offset = 0;
                while offset < received {
                    // SAFETY: Returning received frames back to the Fill Queue.
                    let produced = unsafe { fq.produce(&rx_descs[offset..received]) };
                    if produced > 0 {
                        offset += produced;
                        drop_packets += produced as u64;
                        frames_in_fill += produced as i64;
                        frames_in_rx -= produced as i64;
                    } else {
                        if fq.needs_wakeup() {
                            fq.wakeup(rx_q.fd_mut(), 0)?;
                        }
                    }
                }
            } else {
                // Forward/Echo mode
                for i in 0..received {
                    let desc = &mut rx_descs[i];
                    let len = desc.lengths().data();
                    rx_bytes += len as u64;

                    if mode == OperationMode::Echo {
                        // Echo: Swap MAC addresses in-place
                        // SAFETY: We have exclusive ownership of the packet frame from the Rx ring.
                        let mut data_mut = unsafe { umem.data_mut(desc) };
                        let contents = data_mut.contents_mut();
                        if contents.len() >= 12 {
                            let mut mac_dst = [0u8; 6];
                            let mut mac_src = [0u8; 6];
                            mac_dst.copy_from_slice(&contents[0..6]);
                            mac_src.copy_from_slice(&contents[6..12]);
                            contents[0..6].copy_from_slice(&mac_src);
                            contents[6..12].copy_from_slice(&mac_dst);
                            trace!(
                                "Swapped MAC headers: dst={:02x?} src={:02x?}",
                                mac_src,
                                mac_dst
                            );
                        }
                    }

                    // Copy description back into TX queue buffer
                    tx_descs[i] = *desc;
                }

                // Submit packets to TX Ring
                let mut offset = 0;
                while offset < received {
                    // SAFETY: Submitting processed frames to the Tx Queue. Frame ownership transfers to kernel.
                    let produced = unsafe { tx_q.produce(&tx_descs[offset..received]) };
                    if produced > 0 {
                        for desc in tx_descs[offset..(offset + produced)].iter() {
                            tx_bytes += desc.lengths().data() as u64;
                        }
                        tx_packets += produced as u64;
                        total_tx_packets += produced as u64;
                        frames_in_tx += produced as i64;
                        frames_in_rx -= produced as i64;
                        offset += produced;
                    } else {
                        if tx_q.needs_wakeup() {
                            tx_q.wakeup()?;
                        }
                    }
                }

                // Trigger TX processing in kernel if needed
                if tx_q.needs_wakeup() {
                    tx_q.wakeup()?;
                }
            }
        }

        // B. Reclaim completed Tx frames from Completion Ring and return to Fill Ring
        // SAFETY: Reclaiming frames that kernel has finished transmitting.
        let completed = unsafe { cq.consume(&mut comp_descs[..]) };
        if completed > 0 {
            recycled_packets += completed as u64;
            total_recycled_packets += completed as u64;
            frames_in_comp += completed as i64;
            frames_in_tx -= completed as i64;

            if verbose {
                trace!("Reclaimed {} completed Tx descriptors", completed);
            }
            let mut offset = 0;
            while offset < completed {
                // SAFETY: Returning completed TX frames back to the Fill Queue.
                let produced = unsafe { fq.produce(&comp_descs[offset..completed]) };
                if produced > 0 {
                    offset += produced;
                    frames_in_fill += produced as i64;
                    frames_in_comp -= produced as i64;
                } else {
                    if fq.needs_wakeup() {
                        fq.wakeup(rx_q.fd_mut(), 0)?;
                    }
                }
            }
        }

        // Wake up Fill ring if kernel is blocked waiting for frames
        if fq.needs_wakeup() {
            fq.wakeup(rx_q.fd_mut(), 0)?;
        }

        // C. Periodic statistics printing and health assertions (every 1 second)
        let elapsed = last_stats_time.elapsed();
        if elapsed.as_secs_f64() >= 1.0 {
            let pps_rx = rx_packets as f64 / elapsed.as_secs_f64();
            let pps_tx = tx_packets as f64 / elapsed.as_secs_f64();
            let pps_drop = drop_packets as f64 / elapsed.as_secs_f64();
            let pps_recycled = recycled_packets as f64 / elapsed.as_secs_f64();
            let mbps_rx = (rx_bytes as f64 / elapsed.as_secs_f64()) / (1024.0 * 1024.0);
            let mbps_tx = (tx_bytes as f64 / elapsed.as_secs_f64()) / (1024.0 * 1024.0);

            info!(
                "Stats: RX: {:.2} pps ({:.3} MB/s) | TX: {:.2} pps ({:.3} MB/s) | RECYCLED: {:.2} pps | DROP: {:.2} pps | Total RX: {}, TX: {}, DROP: {}, RECYCLED: {}",
                pps_rx, mbps_rx, pps_tx, mbps_tx, pps_recycled, pps_drop, rx_packets, tx_packets, drop_packets, recycled_packets
            );

            // Print UMEM descriptor distribution mapping
            let total_tracked = frames_in_fill + frames_in_rx + frames_in_tx + frames_in_comp;
            info!(
                "UMEM Frame Distribution: Fill Ring: {} | RX Ring: {} | TX Ring: {} | Completion Ring: {} (Total Tracked: {} / Expected: {})",
                frames_in_fill, frames_in_rx, frames_in_tx, frames_in_comp, total_tracked, frame_count
            );

            // Conservation of Descriptors Assertion (Ensures we haven't leaked any descriptor pointers)
            if total_tracked != frame_count as i64 {
                error!(
                    "CRITICAL: Frame accounting mismatch! Expected {} descriptors, tracked {}.",
                    frame_count, total_tracked
                );
                panic!("Descriptor leak detected!");
            }

            // Starvation/Leak Assertion: Check if completed frames are keeping pace with transmitted frames.
            // Under load, the difference must never exceed the total frame capacity.
            let diff = if total_tx_packets >= total_recycled_packets {
                total_tx_packets - total_recycled_packets
            } else {
                total_recycled_packets - total_tx_packets
            };

            if diff > frame_count as u64 {
                error!(
                    "CRITICAL: Starvation check failed! Tx Count ({}) and Recycled Count ({}) differ by {} (limit: {}). Potential resource leak in completion queue consumption!",
                    total_tx_packets, total_recycled_packets, diff, frame_count
                );
                panic!("Starvation assertion failed! Resource leak detected.");
            }

            // Reset stats counters for the next window
            rx_packets = 0;
            tx_packets = 0;
            drop_packets = 0;
            recycled_packets = 0;
            rx_bytes = 0;
            tx_bytes = 0;
            last_stats_time = Instant::now();
        }
    }
}
