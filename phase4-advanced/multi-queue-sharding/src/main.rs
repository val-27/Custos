//! Phase 4: Multi-queue sharding daemon for Custos.
//!
//! Spawns N independent thread-pinned packet processors, each with a dedicated
//! AF_XDP socket, dedicated rings, and isolated UMEM. Communicates dynamically
//! through an ArcSwap-based policy/configuration reloading and aggregates lock-free stats.

use clap::Parser;
use custos_grpc_basic::ParseError;
use custos_multi_queue_sharding::{
    get_numa_cores, load_config_file, spawn_config_watcher, SharedConfig, ThreadStats,
};
use custos_protobuf::{
    validate_grpc_protobuf_packet, ProtoError, ValidationConfig, ValidationError,
};
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::convert::TryInto;
use std::error::Error;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{error, info, Level};
use tracing_subscriber::FmtSubscriber;
use xsk_rs::{
    config::{BindFlags, Interface, SocketConfig, UmemConfigBuilder},
    Socket, Umem,
};

/// Global shutdown flag updated by SIGINT/SIGTERM signal handlers.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// C-style signal handler for graceful shutdown.
extern "C" fn handle_shutdown_signal(_: libc::c_int) {
    SHUTDOWN.store(true, Ordering::Relaxed);
}

/// Registers signal actions for SIGINT and SIGTERM.
fn setup_signal_handlers() -> Result<(), nix::Error> {
    let handler = SigHandler::Handler(handle_shutdown_signal);
    let action = SigAction::new(handler, SaFlags::SA_RESTART, SigSet::empty());
    // SAFETY: Setting signal handlers for SIGINT and SIGTERM using safe Nix bindings.
    unsafe {
        sigaction(Signal::SIGINT, &action)?;
        sigaction(Signal::SIGTERM, &action)?;
    }
    Ok(())
}

/// Command line arguments for Phase 4 Multi-Queue Sharding daemon.
#[derive(Parser, Debug)]
#[command(name = "custos-multi-queue-sharding")]
#[command(about = "Phase 4: AF_XDP Multi-Queue Sharding Engine", long_about = None)]
struct Args {
    /// Interface name to bind to
    #[arg(short, long)]
    interface: String,

    /// Number of queues/threads (defaults to number of CPU cores / 2)
    #[arg(short, long)]
    queues: Option<usize>,

    /// Comma-separated list of CPU core IDs to pin the worker threads to (e.g. "2,4,6,8")
    #[arg(short, long)]
    cores: Option<String>,

    /// Frame count for UMEM per queue (must be a power of 2)
    #[arg(short, long, default_value_t = 2048)]
    frame_count: u32,

    /// Operation mode: "forward" (validate & forward) or "echo" (validate & swap MACs)
    #[arg(short, long, default_value = "forward", value_parser = ["forward", "echo"])]
    mode: String,

    /// Config file path (TOML) for validation rules
    #[arg(long)]
    config: Option<String>,

    /// Target gRPC port to validate packets for
    #[arg(short, long)]
    target_port: Option<u16>,

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

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // 1. Initialize tracing subscriber
    let log_level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let subscriber = FmtSubscriber::builder().with_max_level(log_level).finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting custos-multi-queue-sharding daemon...");
    info!("CLI configuration: {:?}", args);

    if args.force_copy && args.force_zerocopy {
        return Err("Cannot specify both --force-copy and --force-zerocopy".into());
    }
    if args.frame_count == 0 || !args.frame_count.is_power_of_two() {
        return Err("--frame-count must be a non-zero power of two".into());
    }

    // 2. Setup Unix signal handlers for clean shut-down
    setup_signal_handlers()?;
    info!("Signal handlers for SIGINT/SIGTERM registered successfully");

    // 3. Load configuration rules (TOML file or CLI overrides)
    let mut config = ValidationConfig::default();
    if let Some(config_path) = &args.config {
        info!("Loading TOML configuration from: {}", config_path);
        config = load_config_file(config_path)?;
    }
    if let Some(port) = args.target_port {
        config.target_port = port;
    }
    info!("Effective starting Validation Rules: {:?}", config);

    let shared_config = Arc::new(SharedConfig {
        validation: arc_swap::ArcSwap::new(Arc::new(config)),
    });

    // Spawn config file watcher thread if TOML file was supplied
    if let Some(config_path) = &args.config {
        spawn_config_watcher(config_path.clone(), shared_config.clone(), args.target_port);
    }

    // 4. Resolve CPU core pinning layout
    // Fetch number of online cores on system via sysconf
    // SAFETY: Calling libc::sysconf to get number of online processors.
    let online_cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    let online_cpus = if online_cpus < 0 {
        8
    } else {
        online_cpus as usize
    };
    info!("Detected {} online CPU core(s)", online_cpus);

    let num_queues = args.queues.unwrap_or_else(|| {
        let q = online_cpus / 2;
        if q == 0 {
            1
        } else {
            q
        }
    });
    if num_queues == 0 {
        return Err("--queues must be greater than zero".into());
    }
    info!(
        "Steering configurations: allocating {} queues / worker threads",
        num_queues
    );

    // Resolve pin layout
    let pin_layout = if let Some(cores_str) = &args.cores {
        let parsed: Result<Vec<usize>, _> = cores_str
            .split(',')
            .map(|s| s.trim().parse::<usize>())
            .collect();
        let list = parsed.map_err(|e| format!("Invalid --cores parameter: {:?}", e))?;
        if list.is_empty() {
            return Err("Core list is empty".into());
        }
        list
    } else if let Some(numa_cores) = get_numa_cores(&args.interface) {
        numa_cores
    } else {
        // Fallback: allocate sequentially starting from 0
        (0..online_cpus).collect()
    };

    // 5. Spawn worker threads
    let mut worker_handles = Vec::with_capacity(num_queues);
    let mut stats_list = Vec::with_capacity(num_queues);

    for queue_idx in 0..num_queues {
        // Map queue_idx to core in layout using round-robin if fewer cores than queues
        let core_id = pin_layout[queue_idx % pin_layout.len()];
        info!("Mapping Queue ID {} to CPU Core ID {}", queue_idx, core_id);

        let thread_stats = Arc::new(ThreadStats::default());
        stats_list.push(thread_stats.clone());

        let interface = args.interface.clone();
        let frame_count = args.frame_count;
        let mode = args.mode.clone();
        let shared_config_clone = shared_config.clone();
        let force_copy = args.force_copy;
        let force_zerocopy = args.force_zerocopy;
        let verbose = args.verbose;

        let handle = std::thread::spawn(move || {
            run_worker(
                queue_idx as u32,
                core_id,
                interface,
                frame_count,
                mode,
                shared_config_clone,
                thread_stats,
                force_copy,
                force_zerocopy,
                verbose,
            )
            .map_err(|e| format!("Worker thread on queue {} crashed: {:?}", queue_idx, e))
        });

        worker_handles.push(handle);
    }

    // 6. Main thread loops executing periodic stats aggregation and JSON metrics export
    let mut last_stats_time = Instant::now();
    let mut worker_error = None;

    while !SHUTDOWN.load(Ordering::Relaxed) {
        std::thread::sleep(std::time::Duration::from_secs(1));
        if let Some((idx, _)) = worker_handles
            .iter()
            .enumerate()
            .find(|(_, handle)| handle.is_finished())
        {
            worker_error = Some(format!(
                "Worker thread for queue {} exited unexpectedly",
                idx
            ));
            SHUTDOWN.store(true, Ordering::Relaxed);
            break;
        }
        let elapsed = last_stats_time.elapsed();
        custos_multi_queue_sharding::aggregate_and_report_stats(&stats_list, elapsed, args.verbose);
        last_stats_time = Instant::now();
    }

    info!("Shutdown signal received. Waiting for worker threads to exit...");
    for (idx, handle) in worker_handles.into_iter().enumerate() {
        match handle.join() {
            Ok(Ok(())) => info!("Worker thread for queue {} joined successfully", idx),
            Ok(Err(e)) => {
                error!("{}", e);
                worker_error = Some(e);
            }
            Err(_) => {
                let e = format!("Worker thread for queue {} panicked", idx);
                error!("{}", e);
                if worker_error.is_none() {
                    worker_error = Some(e);
                }
            }
        }
    }

    if let Some(e) = worker_error {
        return Err(e.into());
    }

    info!("Custos multi-queue sharding daemon terminated gracefully.");
    Ok(())
}

/// The worker thread main function. Runs in an infinite polling loop until SHUTDOWN signal.
fn run_worker(
    queue_id: u32,
    core_id: usize,
    interface: String,
    frame_count: u32,
    mode: String,
    shared_config: Arc<SharedConfig>,
    thread_stats: Arc<ThreadStats>,
    force_copy: bool,
    force_zerocopy: bool,
    verbose: bool,
) -> Result<(), Box<dyn Error>> {
    // A. Pin worker thread to the target CPU core
    custos_common::pin_thread_to_core(core_id)?;

    // B. Resolve interface
    let if_name: Interface = interface.parse()?;
    let frame_count_nonzero =
        NonZeroU32::new(frame_count).ok_or("Frame count must be non-zero and a power of two")?;

    // C. Initialize dedicated UMEM slice (allocated independently per queue)
    let umem_config = UmemConfigBuilder::new()
        .frame_size(2048.try_into().unwrap())
        .frame_headroom(0.try_into().unwrap())
        .fill_queue_size(frame_count_nonzero)
        .comp_queue_size(frame_count_nonzero)
        .build()
        .map_err(|e| {
            error!("[Queue {}] Failed to build UmemConfig: {:?}", queue_id, e);
            e
        })?;

    let use_huge_pages = false;
    let (umem, frame_descs) =
        Umem::new(umem_config, frame_count_nonzero, use_huge_pages).map_err(|e| {
            error!("[Queue {}] Failed to initialize UMEM: {:?}", queue_id, e);
            e
        })?;
    info!(
        "[Queue {}] Initialized dedicated UMEM with {} frames",
        queue_id, frame_count
    );

    // D. Configure AF_XDP socket
    let mut socket_config_builder = SocketConfig::builder();
    let mut bind_flags = BindFlags::XDP_USE_NEED_WAKEUP;
    if force_copy {
        bind_flags.insert(BindFlags::XDP_COPY);
        info!("[Queue {}] Forcing XDP_COPY mode", queue_id);
    } else if force_zerocopy {
        bind_flags.insert(BindFlags::XDP_ZEROCOPY);
        info!("[Queue {}] Forcing XDP_ZEROCOPY mode", queue_id);
    }
    socket_config_builder.bind_flags(bind_flags);

    // If queue_id > 0, inhibit default program load to prevent double-attachment conflicts on the interface
    if queue_id > 0 {
        use xsk_rs::config::LibxdpFlags;
        socket_config_builder.libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD);
        info!(
            "[Queue {}] Inhibiting XDP program load to prevent double-attachment conflicts",
            queue_id
        );
    }
    let socket_config = socket_config_builder.build();

    // SAFETY: Creating a dedicated AF_XDP Socket bound to the interface and queue ID.
    // The UMEM reference is held for the lifetime of this socket.
    let (tx_q, rx_q, fq_and_cq) = unsafe { Socket::new(socket_config, &umem, &if_name, queue_id) }
        .map_err(|e| {
            error!("[Queue {}] Failed to bind AF_XDP socket: {:?}", queue_id, e);
            e
        })?;

    let (mut fq, cq) =
        fq_and_cq.ok_or("Expected Fill and Completion queues from socket creation")?;
    info!(
        "[Queue {}] Bound AF_XDP socket to interface: {}, queue: {}",
        queue_id, interface, queue_id
    );

    // E. Populate Fill Queue with all pre-allocated descriptors
    // SAFETY: Populating the Fill Queue with all owned frame descriptors before polling.
    let produced = unsafe { fq.produce(&frame_descs) };
    if produced != frame_descs.len() {
        return Err(format!(
            "[Queue {}] Failed to populate Fill Queue: produced {} out of {} frames",
            queue_id,
            produced,
            frame_descs.len()
        )
        .into());
    }
    info!(
        "[Queue {}] Populated Fill Queue with all {} frames",
        queue_id, produced
    );

    // F. Start Hot Polling Loop
    run_packet_loop(
        queue_id,
        mode,
        verbose,
        umem,
        rx_q,
        tx_q,
        fq,
        cq,
        frame_descs[0],
        frame_count,
        shared_config,
        thread_stats,
    )?;

    Ok(())
}

/// Hot-path packet polling loop. Executed with zero heap allocations on the CPU-pinned thread.
fn run_packet_loop(
    queue_id: u32,
    mode: String,
    verbose: bool,
    umem: Umem,
    mut rx_q: xsk_rs::RxQueue,
    mut tx_q: xsk_rs::TxQueue,
    mut fq: xsk_rs::FillQueue,
    mut cq: xsk_rs::CompQueue,
    template_desc: xsk_rs::FrameDesc,
    frame_count: u32,
    shared_config: Arc<SharedConfig>,
    thread_stats: Arc<ThreadStats>,
) -> Result<(), Box<dyn Error>> {
    const BATCH_SIZE: usize = 64;

    // Pre-allocate descriptor arrays to avoid hot-path heap allocations
    let mut rx_descs = vec![template_desc; BATCH_SIZE];
    let mut tx_descs = vec![template_desc; BATCH_SIZE];
    let mut comp_descs = vec![template_desc; BATCH_SIZE];

    // Tracking variables for safety/starvation assertions
    let mut total_tx_packets: u64 = 0;
    let mut total_recycled_packets: u64 = 0;

    let mut frames_in_fill = frame_count as i64;
    let mut frames_in_rx = 0i64;
    let mut frames_in_tx = 0i64;
    let mut frames_in_comp = 0i64;

    info!(
        "[Queue {}] Entering hot-path packet polling loop...",
        queue_id
    );

    while !SHUTDOWN.load(Ordering::Relaxed) {
        // A. Consume received packets from Rx Ring
        // SAFETY: Consuming received packets from Rx Ring.
        let received = unsafe { rx_q.consume(&mut rx_descs[..]) };

        if received > 0 {
            thread_stats
                .rx_packets
                .fetch_add(received as u64, Ordering::Relaxed);
            frames_in_rx += received as i64;
            frames_in_fill -= received as i64;

            // Load active config once per batch (lock-free)
            let active_config = shared_config.validation.load();
            let mut tx_index = 0;

            for i in 0..received {
                let desc = &mut rx_descs[i];
                let len = desc.lengths().data();
                thread_stats
                    .rx_bytes
                    .fetch_add(len as u64, Ordering::Relaxed);

                // Increment payload size histogram
                if len <= 64 {
                    thread_stats
                        .hist_payload_0_64
                        .fetch_add(1, Ordering::Relaxed);
                } else if len <= 256 {
                    thread_stats
                        .hist_payload_65_256
                        .fetch_add(1, Ordering::Relaxed);
                } else if len <= 1024 {
                    thread_stats
                        .hist_payload_257_1024
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    thread_stats
                        .hist_payload_1025_2048
                        .fetch_add(1, Ordering::Relaxed);
                }

                // SAFETY: Accessing packet memory within bounds of the allocated UMEM frame descriptor.
                let data = unsafe { umem.data(desc) };
                let buf = data.contents();

                // Validate headers and Walk Protobuf Zero-Copy
                match validate_grpc_protobuf_packet(buf, &active_config) {
                    Ok((shape, shape_len)) => {
                        thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                        thread_stats.stat_tcp.fetch_add(1, Ordering::Relaxed);
                        thread_stats.stat_http2_data.fetch_add(1, Ordering::Relaxed);
                        thread_stats.stat_grpc.fetch_add(1, Ordering::Relaxed);
                        thread_stats.stat_protobuf.fetch_add(1, Ordering::Relaxed);

                        if verbose {
                            tracing::debug!(
                                "[Queue {}] Valid Protobuf Shape: src_mac={:02x?} shape={:?}",
                                queue_id,
                                &buf[6..12],
                                &shape[0..shape_len]
                            );
                        }

                        // Echo mode: Swap MAC address in place
                        if mode == "echo" {
                            // SAFETY: Modifying packet memory within bounds of the allocated UMEM frame descriptor.
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

                        tx_descs[tx_index] = *desc;
                        tx_index += 1;
                    }
                    Err(validation_err) => {
                        thread_stats
                            .drop_validation_failed
                            .fetch_add(1, Ordering::Relaxed);

                        match validation_err {
                            ValidationError::Parse(parse_err) => match parse_err {
                                ParseError::BufferTooSmall => {
                                    thread_stats.err_too_small.fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::NonIPv4 => {
                                    thread_stats.err_non_ipv4.fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::BadIpHdrLen => {
                                    thread_stats.err_bad_ip_len.fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::NonTCP => {
                                    thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.err_non_tcp.fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::BadIpChecksum => {
                                    thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.err_bad_ip_csum.fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::BadTcpHdrLen => {
                                    thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.stat_tcp.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.err_bad_tcp_len.fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::WrongPort => {
                                    thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.stat_tcp.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.err_wrong_port.fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::BadHttp2Hdr => {
                                    thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.stat_tcp.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.err_bad_http2.fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::NonHttp2Data => {
                                    thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.stat_tcp.fetch_add(1, Ordering::Relaxed);
                                    thread_stats
                                        .err_non_http2_data
                                        .fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::BadGrpcHdr => {
                                    thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.stat_tcp.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.stat_http2_data.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.err_bad_grpc.fetch_add(1, Ordering::Relaxed);
                                }
                                ParseError::PayloadOverflow => {
                                    thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.stat_tcp.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.stat_http2_data.fetch_add(1, Ordering::Relaxed);
                                    thread_stats.err_l4_overflow.fetch_add(1, Ordering::Relaxed);
                                }
                            },
                            ValidationError::Proto(proto_err) => {
                                thread_stats.stat_ipv4.fetch_add(1, Ordering::Relaxed);
                                thread_stats.stat_tcp.fetch_add(1, Ordering::Relaxed);
                                thread_stats.stat_http2_data.fetch_add(1, Ordering::Relaxed);
                                thread_stats.stat_grpc.fetch_add(1, Ordering::Relaxed);

                                match proto_err {
                                    ProtoError::InvalidVarint => {
                                        thread_stats
                                            .anomaly_invalid_varint
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    ProtoError::InvalidWireType => {
                                        thread_stats
                                            .anomaly_invalid_wire_type
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    ProtoError::RecursionLimit => {
                                        thread_stats
                                            .anomaly_recursion_limit
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    ProtoError::BufferUnderflow => {
                                        thread_stats
                                            .anomaly_buffer_underflow
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    ProtoError::ShapeDimensionLimit => {
                                        thread_stats
                                            .anomaly_shape_dim_limit
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    ProtoError::ShapeValueInvalid => {
                                        thread_stats
                                            .anomaly_shape_val_invalid
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    ProtoError::TensorSizeLimit => {
                                        thread_stats
                                            .anomaly_tensor_size_limit
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                    ProtoError::InvalidVarintBytes => {
                                        thread_stats
                                            .anomaly_invalid_varint_bytes
                                            .fetch_add(1, Ordering::Relaxed);
                                    }
                                }
                            }
                        }

                        // Recycle malformed frame immediately back to Fill Queue
                        let mut offset = 0;
                        while offset < 1 {
                            // SAFETY: Returning invalid/dropped frame descriptor back to Fill Queue.
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

            // Submit valid packets to TX Queue
            let mut tx_offset = 0;
            while tx_offset < tx_index {
                // SAFETY: Submitting processed frame descriptors to Tx Queue. Descriptor ownership transfers to kernel.
                let produced = unsafe { tx_q.produce(&tx_descs[tx_offset..tx_index]) };
                if produced > 0 {
                    for desc in tx_descs[tx_offset..(tx_offset + produced)].iter() {
                        thread_stats
                            .tx_bytes
                            .fetch_add(desc.lengths().data() as u64, Ordering::Relaxed);
                    }
                    thread_stats
                        .tx_packets
                        .fetch_add(produced as u64, Ordering::Relaxed);
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

            if tx_q.needs_wakeup() {
                tx_q.wakeup()?;
            }
        }

        // B. Reclaim completed Tx frames from Completion Ring and return to Fill Ring
        // SAFETY: Reclaiming completed descriptors from Completion Queue.
        let completed = unsafe { cq.consume(&mut comp_descs[..]) };
        if completed > 0 {
            thread_stats
                .recycled_packets
                .fetch_add(completed as u64, Ordering::Relaxed);
            total_recycled_packets += completed as u64;
            frames_in_comp += completed as i64;
            frames_in_tx -= completed as i64;

            let mut offset = 0;
            while offset < completed {
                // SAFETY: Returning completed frame descriptor back to Fill Queue.
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

        if fq.needs_wakeup() {
            fq.wakeup(rx_q.fd_mut(), 0)?;
        }

        // C. Health and Leak Assertions (Conservation of Descriptors)
        let total_tracked = frames_in_fill + frames_in_rx + frames_in_tx + frames_in_comp;
        if total_tracked != frame_count as i64 {
            error!(
                "[Queue {}] CRITICAL: Frame accounting mismatch! Expected {} descriptors, tracked {}.",
                queue_id, frame_count, total_tracked
            );
            return Err("Descriptor leak detected!".into());
        }

        let diff = if total_tx_packets >= total_recycled_packets {
            total_tx_packets - total_recycled_packets
        } else {
            total_recycled_packets - total_tx_packets
        };

        if diff > frame_count as u64 {
            error!(
                "[Queue {}] CRITICAL: Starvation check failed! Tx Count ({}) and Recycled Count ({}) differ by {} (limit: {}).",
                queue_id, total_tx_packets, total_recycled_packets, diff, frame_count
            );
            return Err("Starvation assertion failed! Resource leak detected.".into());
        }
    }

    Ok(())
}
