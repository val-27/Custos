//! Phase 2: Header Stripping and Basic gRPC Validation.
//!
//! Parses and validates incoming Ethernet, IPv4, TCP, HTTP/2 DATA, and gRPC headers in-place.
//! Pins polling thread to a single core, avoids heap allocations in the hot path,
//! tracks detailed packet types and validation failures, and supports simulated drop rates.

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("custos-phase2-grpc-basic requires Linux AF_XDP support");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use custos_common::OperationMode;
#[cfg(target_os = "linux")]
use custos_grpc_basic::{parse_grpc_packet, ParseError, Xorshift};
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

/// CLI Arguments for Phase 2.
#[cfg(target_os = "linux")]
#[derive(Parser, Debug)]
#[command(name = "custos-phase2-grpc-basic")]
#[command(about = "Phase 2: AF_XDP Zero-Copy gRPC Validation Engine", long_about = None)]
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

    /// Packet processing mode: forward or echo
    #[arg(short, long, default_value_t = OperationMode::Forward)]
    mode: OperationMode,

    /// Target gRPC port to validate packets for
    #[arg(short, long, default_value_t = 50051)]
    target_port: u16,

    /// Simulated drop rate (0.0 to 1.0) to drop valid gRPC packets
    #[arg(short, long, default_value_t = 0.0)]
    drop_rate: f32,

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

    info!("Starting custos-phase2-grpc-basic...");
    info!("CLI configuration: {:?}", args);

    if args.force_copy && args.force_zerocopy {
        return Err("Cannot specify both --force-copy and --force-zerocopy".into());
    }
    if args.drop_rate < 0.0 || args.drop_rate > 1.0 {
        return Err("Simulated drop rate must be between 0.0 and 1.0".into());
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
    run_packet_loop(args, umem, rx_q, tx_q, fq, cq, frame_descs[0])?;

    Ok(())
}

/// The core packet processing loop. Runs with zero heap allocations in the hot path.
///
/// # Purpose
/// Polls the AF_XDP Rx ring in batches, validates each packet with
/// `parse_grpc_packet`, dispatches according to `mode` (Forward / Echo),
/// and recycles invalid or simulated-drop frames immediately.
///
/// # Performance Rationale
/// `mode` is stored as an `OperationMode` enum so the per-packet branch is an
/// integer comparison rather than a heap-allocated string scan.
#[cfg(target_os = "linux")]
fn run_packet_loop(
    args: Args,
    umem: Umem,
    mut rx_q: RxQueue,
    mut tx_q: TxQueue,
    mut fq: FillQueue,
    mut cq: CompQueue,
    template_desc: FrameDesc,
) -> Result<(), Box<dyn Error>> {
    const BATCH_SIZE: usize = 64;

    // Pre-allocate descriptor arrays to avoid hot-path allocation
    let mut rx_descs = vec![template_desc; BATCH_SIZE];
    let mut tx_descs = vec![template_desc; BATCH_SIZE];
    let mut comp_descs = vec![template_desc; BATCH_SIZE];

    // Initialize PRNG for drop simulation
    let mut prng = Xorshift::new(12345);

    // Stats tracking
    let mut last_stats_time = Instant::now();
    let mut rx_packets: u64 = 0;
    let mut tx_packets: u64 = 0;
    let mut recycled_packets: u64 = 0;
    let mut rx_bytes: u64 = 0;
    let mut tx_bytes: u64 = 0;

    // Lifetime counters to assert completion ring consumption roughly matches transmission count
    let mut total_tx_packets: u64 = 0;
    let mut total_recycled_packets: u64 = 0;

    // Frame distribution tracking
    let mut frames_in_fill = args.frame_count as i64;
    let mut frames_in_rx = 0i64;
    let mut frames_in_tx = 0i64;
    let mut frames_in_comp = 0i64;

    // Detailed Validation Statistics
    let mut stat_ipv4: u64 = 0;
    let mut stat_tcp: u64 = 0;
    let mut stat_http2_data: u64 = 0;
    let mut stat_grpc: u64 = 0;

    let mut err_too_small: u64 = 0;
    let mut err_non_ipv4: u64 = 0;
    let mut err_bad_ip_len: u64 = 0;
    let mut err_non_tcp: u64 = 0;
    let mut err_bad_ip_csum: u64 = 0;
    let mut err_bad_tcp_len: u64 = 0;
    let mut err_wrong_port: u64 = 0;
    let mut err_bad_http2: u64 = 0;
    let mut err_non_http2_data: u64 = 0;
    let mut err_bad_grpc: u64 = 0;
    let mut err_overflow: u64 = 0;

    let mut drop_validation_failed: u64 = 0;
    let mut drop_simulated: u64 = 0;

    info!(
        "Entering hot-path validation poll loop (target_port: {})...",
        args.target_port
    );

    loop {
        // A. Consume received packets from Rx Ring
        let received = unsafe { rx_q.consume(&mut rx_descs[..]) };

        if received > 0 {
            rx_packets += received as u64;
            frames_in_rx += received as i64;
            frames_in_fill -= received as i64;

            let mut tx_index = 0;

            for i in 0..received {
                let desc = &mut rx_descs[i];
                let len = desc.lengths().data();
                rx_bytes += len as u64;

                // Access raw packet bytes zero-copy
                let data = unsafe { umem.data(desc) };
                let buf = data.contents();

                // Validate headers
                match parse_grpc_packet(buf, args.target_port) {
                    Ok(parsed) => {
                        // Increment valid packet type statistics
                        stat_ipv4 += 1;
                        stat_tcp += 1;
                        stat_http2_data += 1;
                        stat_grpc += 1;

                        if args.verbose {
                            debug!(
                                "Valid gRPC packet: src_ip={:?} dst_ip={:?} src_port={} msg_len={}",
                                parsed.ip.src_ip,
                                parsed.ip.dst_ip,
                                parsed.tcp.src_port.get(),
                                parsed.grpc.message_len.get()
                            );
                        }

                        // Check simulated drop rate
                        if args.drop_rate > 0.0 && prng.next_f32() < args.drop_rate {
                            drop_simulated += 1;
                            if args.verbose {
                                debug!("Simulating drop for valid gRPC packet");
                            }
                            // Recycle frame directly
                            let mut offset = 0;
                            while offset < 1 {
                                let recycled = unsafe { fq.produce(&rx_descs[i..i + 1]) };
                                if recycled > 0 {
                                    offset += recycled;
                                    frames_in_fill += 1;
                                    frames_in_rx -= 1;
                                } else {
                                    if fq.needs_wakeup() {
                                        fq.wakeup(rx_q.fd_mut(), 0)?;
                                    }
                                }
                            }
                        } else {
                            // Forward packet (or Swap MAC if mode is echo)
                            if args.mode == OperationMode::Echo {
                                let mut data_mut = unsafe { umem.data_mut(desc) };
                                let contents = data_mut.contents_mut();
                                if contents.len() >= 12 {
                                    let mut mac_dst = [0u8; 6];
                                    let mut mac_src = [0u8; 6];
                                    mac_dst.copy_from_slice(&contents[0..6]);
                                    mac_src.copy_from_slice(&contents[6..12]);
                                    contents[0..6].copy_from_slice(&mac_src);
                                    contents[6..12].copy_from_slice(&mac_dst);
                                }
                            }

                            // Add to our batch to transmit
                            tx_descs[tx_index] = *desc;
                            tx_index += 1;
                        }
                    }
                    Err(err) => {
                        drop_validation_failed += 1;
                        // Record specific parsing error
                        match err {
                            ParseError::BufferTooSmall => err_too_small += 1,
                            ParseError::NonIPv4 => err_non_ipv4 += 1,
                            ParseError::BadIpHdrLen => err_bad_ip_len += 1,
                            ParseError::NonTCP => {
                                stat_ipv4 += 1;
                                err_non_tcp += 1;
                            }
                            ParseError::BadIpChecksum => {
                                stat_ipv4 += 1;
                                err_bad_ip_csum += 1;
                            }
                            ParseError::BadTcpHdrLen => {
                                stat_ipv4 += 1;
                                stat_tcp += 1;
                                err_bad_tcp_len += 1;
                            }
                            ParseError::WrongPort => {
                                stat_ipv4 += 1;
                                stat_tcp += 1;
                                err_wrong_port += 1;
                            }
                            ParseError::BadHttp2Hdr => {
                                stat_ipv4 += 1;
                                stat_tcp += 1;
                                err_bad_http2 += 1;
                            }
                            ParseError::NonHttp2Data => {
                                stat_ipv4 += 1;
                                stat_tcp += 1;
                                err_non_http2_data += 1;
                            }
                            ParseError::BadGrpcHdr => {
                                stat_ipv4 += 1;
                                stat_tcp += 1;
                                stat_http2_data += 1;
                                err_bad_grpc += 1;
                            }
                            ParseError::PayloadOverflow => {
                                stat_ipv4 += 1;
                                stat_tcp += 1;
                                stat_http2_data += 1;
                                err_overflow += 1;
                            }
                        }

                        if args.verbose {
                            debug!("Validation failure (dropping packet): {:?}", err);
                        }

                        // Recycle malformed frame immediately back to Fill Queue
                        let mut offset = 0;
                        while offset < 1 {
                            let recycled = unsafe { fq.produce(&rx_descs[i..i + 1]) };
                            if recycled > 0 {
                                offset += recycled;
                                frames_in_fill += 1;
                                frames_in_rx -= 1;
                            } else {
                                if fq.needs_wakeup() {
                                    fq.wakeup(rx_q.fd_mut(), 0)?;
                                }
                            }
                        }
                    }
                }
            }

            // Submit valid forwarded/echoed packets to TX Queue
            let mut tx_offset = 0;
            while tx_offset < tx_index {
                let produced = unsafe { tx_q.produce(&tx_descs[tx_offset..tx_index]) };
                if produced > 0 {
                    for desc in tx_descs[tx_offset..(tx_offset + produced)].iter() {
                        tx_bytes += desc.lengths().data() as u64;
                    }
                    tx_packets += produced as u64;
                    total_tx_packets += produced as u64;
                    frames_in_tx += produced as i64;
                    frames_in_rx -= produced as i64;
                    tx_offset += produced;
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

        // B. Reclaim completed Tx frames from Completion Ring and return to Fill Ring
        let completed = unsafe { cq.consume(&mut comp_descs[..]) };
        if completed > 0 {
            recycled_packets += completed as u64;
            total_recycled_packets += completed as u64;
            frames_in_comp += completed as i64;
            frames_in_tx -= completed as i64;

            let mut offset = 0;
            while offset < completed {
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

        // C. Periodic statistics printing and leak assertions (every 1 second)
        let elapsed = last_stats_time.elapsed();
        if elapsed.as_secs_f64() >= 1.0 {
            let pps_rx = rx_packets as f64 / elapsed.as_secs_f64();
            let pps_tx = tx_packets as f64 / elapsed.as_secs_f64();
            let pps_recycled = recycled_packets as f64 / elapsed.as_secs_f64();
            let mbps_rx = (rx_bytes as f64 / elapsed.as_secs_f64()) / (1024.0 * 1024.0);
            let mbps_tx = (tx_bytes as f64 / elapsed.as_secs_f64()) / (1024.0 * 1024.0);

            info!(
                "Stats: RX: {:.2} pps ({:.3} MB/s) | TX: {:.2} pps ({:.3} MB/s) | RECYCLED: {:.2} pps | Total RX: {}, TX: {}, RECYCLED: {}",
                pps_rx, mbps_rx, pps_tx, mbps_tx, pps_recycled, rx_packets, tx_packets, recycled_packets
            );

            // Detailed statistics breakdowns
            info!(
                "Protocol Distribution: IPv4: {} | TCP: {} | HTTP/2 DATA: {} | gRPC Frames: {}",
                stat_ipv4, stat_tcp, stat_http2_data, stat_grpc
            );
            info!(
                "Validation Failures (Total: {}): Bad MAC/Size: {} | Non-IPv4: {} | Bad IPv4 Len: {} | Bad IP Csum: {} | Non-TCP: {} | Bad TCP Len: {} | Wrong Port: {} | Bad HTTP/2 Hdr: {} | Non-DATA Frame: {} | Bad gRPC Hdr: {} | Payload Overflow: {}",
                drop_validation_failed, err_too_small, err_non_ipv4, err_bad_ip_len, err_bad_ip_csum, err_non_tcp, err_bad_tcp_len, err_wrong_port, err_bad_http2, err_non_http2_data, err_bad_grpc, err_overflow
            );
            info!(
                "Drops: Validation Failures: {} | Simulated Drops: {}",
                drop_validation_failed, drop_simulated
            );

            // UMEM frame distribution conservation check
            let total_tracked = frames_in_fill + frames_in_rx + frames_in_tx + frames_in_comp;
            trace!(
                "UMEM Frame Distribution: Fill Ring: {} | RX Ring: {} | TX Ring: {} | Completion Ring: {} (Total Tracked: {} / Expected: {})",
                frames_in_fill, frames_in_rx, frames_in_tx, frames_in_comp, total_tracked, args.frame_count
            );

            if total_tracked != args.frame_count as i64 {
                error!(
                    "CRITICAL: Frame accounting mismatch! Expected {} descriptors, tracked {}.",
                    args.frame_count, total_tracked
                );
                panic!("Descriptor leak detected!");
            }

            // Starvation/Leak Assertion
            let diff = if total_tx_packets >= total_recycled_packets {
                total_tx_packets - total_recycled_packets
            } else {
                total_recycled_packets - total_tx_packets
            };

            if diff > args.frame_count as u64 {
                error!(
                    "CRITICAL: Starvation check failed! Tx Count ({}) and Recycled Count ({}) differ by {} (limit: {}). Potential resource leak in completion queue consumption!",
                    total_tx_packets, total_recycled_packets, diff, args.frame_count
                );
                panic!("Starvation assertion failed! Resource leak detected.");
            }

            // Reset stats counters
            rx_packets = 0;
            tx_packets = 0;
            recycled_packets = 0;
            rx_bytes = 0;
            tx_bytes = 0;
            stat_ipv4 = 0;
            stat_tcp = 0;
            stat_http2_data = 0;
            stat_grpc = 0;
            err_too_small = 0;
            err_non_ipv4 = 0;
            err_bad_ip_len = 0;
            err_non_tcp = 0;
            err_bad_ip_csum = 0;
            err_bad_tcp_len = 0;
            err_wrong_port = 0;
            err_bad_http2 = 0;
            err_non_http2_data = 0;
            err_bad_grpc = 0;
            err_overflow = 0;
            drop_validation_failed = 0;
            drop_simulated = 0;
            last_stats_time = Instant::now();
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn Error>> {
    Err("AF_XDP packet processing is only supported on Linux".into())
}
