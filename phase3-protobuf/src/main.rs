//! Phase 3: Protobuf Wire-Format Walker and Shape Validation.
//!
//! Validates Ethernet, IPv4, TCP, HTTP/2, gRPC, and Protobuf layers zero-copy.
//! Configures rules via TOML, exports Prometheus/JSON metrics, and runs with zero heap allocations in the hot path.

#[cfg(target_os = "linux")]
use clap::Parser;
#[cfg(target_os = "linux")]
use custos_common::OperationMode;
#[cfg(target_os = "linux")]
use custos_grpc_basic::ParseError;
#[cfg(target_os = "linux")]
use custos_protobuf::{
    validate_grpc_protobuf_packet, ProtoError, ValidationConfig, ValidationError,
};
#[cfg(target_os = "linux")]
use std::convert::TryInto;
use std::error::Error;
#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io::Write;
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

/// CLI Arguments for Phase 3.
#[cfg(target_os = "linux")]
#[derive(Parser, Debug)]
#[command(name = "custos-phase3-protobuf")]
#[command(about = "Phase 3: AF_XDP Zero-Copy Protobuf Shape Validation Engine", long_about = None)]
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

    /// Config file path (TOML) for validation rules
    #[arg(long)]
    config: Option<String>,

    /// Target gRPC port to validate packets for
    #[arg(short, long)]
    target_port: Option<u16>,

    /// Protobuf field number containing the shape array
    #[arg(long)]
    shape_field: Option<u32>,

    /// Maximum allowed dimensions
    #[arg(long)]
    max_dims: Option<usize>,

    /// Maximum allowed total elements in tensor
    #[arg(long)]
    max_elements: Option<u64>,

    /// Maximum recursion depth
    #[arg(long)]
    max_depth: Option<usize>,

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

    info!("Starting custos-phase3-protobuf...");
    info!("CLI configuration: {:?}", args);

    if args.force_copy && args.force_zerocopy {
        return Err("Cannot specify both --force-copy and --force-zerocopy".into());
    }

    // 1. Load configuration: CLI defaults or TOML overrides
    let mut config = ValidationConfig::default();

    if let Some(config_path) = &args.config {
        info!("Loading TOML configuration from: {}", config_path);
        let content = std::fs::read_to_string(config_path)?;
        let toml_config: ValidationConfig = toml::from_str(&content)?;
        config = toml_config;
    }

    // CLI overrides take precedence over TOML values
    if let Some(port) = args.target_port {
        config.target_port = port;
    }
    if let Some(field) = args.shape_field {
        config.shape_field_number = field;
    }
    if let Some(dims) = args.max_dims {
        config.max_dimensions = dims;
    }
    if let Some(elements) = args.max_elements {
        config.max_tensor_elements = elements;
    }
    if let Some(depth) = args.max_depth {
        config.max_recursion_depth = depth;
    }

    info!("Effective Validation Rules: {:?}", config);

    // 2. Thread Pinning
    custos_common::pin_thread_to_core(args.core)?;

    // 3. Interface Resolution
    let if_name: Interface = args.interface.parse().map_err(|e| {
        error!(
            "Failed to parse interface name '{}': {:?}",
            args.interface, e
        );
        e
    })?;

    // 4. UMEM Configuration (2 KiB frames, ring sizes from shared constants)
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

    // 5. Socket Configuration
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

    // 6. Populate Fill Queue with all available UMEM frames
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

    // 7. Packet Processing Loop
    run_packet_loop(args, config, umem, rx_q, tx_q, fq, cq, frame_descs[0])?;

    Ok(())
}

/// The core packet processing loop. Runs with zero heap allocations in the hot path.
///
/// # Purpose
/// Polls the AF_XDP Rx ring in batches, validates each packet through all
/// layers (L2-L7) via `validate_grpc_protobuf_packet`, dispatches according
/// to `mode` (Forward / Echo), and recycles invalid frames immediately.
///
/// # Performance Rationale
/// `mode` is stored as an `OperationMode` enum so the per-packet branch is an
/// integer comparison rather than a heap-allocated string scan.
#[cfg(target_os = "linux")]
fn run_packet_loop(
    args: Args,
    config: ValidationConfig,
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

    // Protocol Distribution Statistics
    let mut stat_ipv4: u64 = 0;
    let mut stat_tcp: u64 = 0;
    let mut stat_http2_data: u64 = 0;
    let mut stat_grpc: u64 = 0;
    let mut stat_protobuf: u64 = 0;

    // L2-L5 Parser Failure Statistics
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
    let mut err_l4_overflow: u64 = 0;

    // L6-L7 Protobuf Validation Failure Statistics (Anomaly Counts)
    let mut anomaly_invalid_varint: u64 = 0;
    let mut anomaly_invalid_wire_type: u64 = 0;
    let mut anomaly_recursion_limit: u64 = 0;
    let mut anomaly_buffer_underflow: u64 = 0;
    let mut anomaly_shape_dim_limit: u64 = 0;
    let mut anomaly_shape_val_invalid: u64 = 0;
    let mut anomaly_tensor_size_limit: u64 = 0;
    let mut anomaly_invalid_varint_bytes: u64 = 0;

    // Histogram of payload sizes (ranges: 0-64, 65-256, 257-1024, 1025-2048)
    let mut hist_payload_0_64: u64 = 0;
    let mut hist_payload_65_256: u64 = 0;
    let mut hist_payload_257_1024: u64 = 0;
    let mut hist_payload_1025_2048: u64 = 0;

    let mut drop_validation_failed: u64 = 0;

    info!("Entering Phase 3 zero-copy protobuf walker poll loop...");

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

                // Increment payload size histogram
                if len <= 64 {
                    hist_payload_0_64 += 1;
                } else if len <= 256 {
                    hist_payload_65_256 += 1;
                } else if len <= 1024 {
                    hist_payload_257_1024 += 1;
                } else {
                    hist_payload_1025_2048 += 1;
                }

                // Access raw packet bytes zero-copy
                let data = unsafe { umem.data(desc) };
                let buf = data.contents();

                // Validate wrappers & walk Protobuf Zero-Copy
                match validate_grpc_protobuf_packet(buf, &config) {
                    Ok((shape, shape_len)) => {
                        // Success! Update stats
                        stat_ipv4 += 1;
                        stat_tcp += 1;
                        stat_http2_data += 1;
                        stat_grpc += 1;
                        stat_protobuf += 1;

                        if args.verbose {
                            debug!(
                                "Valid Protobuf Shape: src_mac={:02x?} shape={:?}",
                                &buf[6..12],
                                &shape[0..shape_len]
                            );
                        }

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
                    Err(validation_err) => {
                        drop_validation_failed += 1;

                        match validation_err {
                            ValidationError::Parse(parse_err) => {
                                // Layer 2-5 validation failure
                                match parse_err {
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
                                        err_l4_overflow += 1;
                                    }
                                }

                                if args.verbose {
                                    debug!("L2-L5 validation failure (dropped): {:?}", parse_err);
                                }
                            }
                            ValidationError::Proto(proto_err) => {
                                // L6-L7 Protobuf Anomaly
                                stat_ipv4 += 1;
                                stat_tcp += 1;
                                stat_http2_data += 1;
                                stat_grpc += 1;

                                match proto_err {
                                    ProtoError::InvalidVarint => anomaly_invalid_varint += 1,
                                    ProtoError::InvalidWireType => anomaly_invalid_wire_type += 1,
                                    ProtoError::RecursionLimit => anomaly_recursion_limit += 1,
                                    ProtoError::BufferUnderflow => anomaly_buffer_underflow += 1,
                                    ProtoError::ShapeDimensionLimit => anomaly_shape_dim_limit += 1,
                                    ProtoError::ShapeValueInvalid => anomaly_shape_val_invalid += 1,
                                    ProtoError::TensorSizeLimit => anomaly_tensor_size_limit += 1,
                                    ProtoError::InvalidVarintBytes => {
                                        anomaly_invalid_varint_bytes += 1
                                    }
                                }

                                if args.verbose {
                                    debug!(
                                        "Protobuf anomaly validation failure (dropped): {:?}",
                                        proto_err
                                    );
                                }
                            }
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

            // Submit valid packets to TX Queue
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

        if fq.needs_wakeup() {
            fq.wakeup(rx_q.fd_mut(), 0)?;
        }

        // C. Periodic statistics printing, metric exports, and leak assertions (every 1 second)
        let elapsed = last_stats_time.elapsed();
        if elapsed.as_secs_f64() >= 1.0 {
            let pps_rx = rx_packets as f64 / elapsed.as_secs_f64();
            let pps_tx = tx_packets as f64 / elapsed.as_secs_f64();
            let mbps_rx = (rx_bytes as f64 / elapsed.as_secs_f64()) / (1024.0 * 1024.0);
            let mbps_tx = (tx_bytes as f64 / elapsed.as_secs_f64()) / (1024.0 * 1024.0);

            info!(
                "Stats: RX: {:.2} pps ({:.3} MB/s) | TX: {:.2} pps ({:.3} MB/s) | Total RX: {}, TX: {}, RECYCLED: {}, DROPPED: {}",
                pps_rx, mbps_rx, pps_tx, mbps_tx, rx_packets, tx_packets, recycled_packets, drop_validation_failed
            );
            info!(
                "Protocols: IPv4: {} | TCP: {} | HTTP/2: {} | gRPC: {} | Protobuf: {}",
                stat_ipv4, stat_tcp, stat_http2_data, stat_grpc, stat_protobuf
            );
            info!(
                "L2-L5 Parser Failures: TooSmall: {} | NonIPv4: {} | BadIpLen: {} | NonTCP: {} | BadIpCsum: {} | BadTcpLen: {} | WrongPort: {} | BadHttp2: {} | NonHttp2Data: {} | BadGrpc: {} | L4Overflow: {}",
                err_too_small, err_non_ipv4, err_bad_ip_len, err_non_tcp, err_bad_ip_csum, err_bad_tcp_len, err_wrong_port, err_bad_http2, err_non_http2_data, err_bad_grpc, err_l4_overflow
            );
            info!(
                "Anomalies: Varint: {} | WireType: {} | Recursion: {} | Underflow: {} | Dims: {} | DimVal: {} | TensorSize: {} | VarintBytes: {}",
                anomaly_invalid_varint, anomaly_invalid_wire_type, anomaly_recursion_limit, anomaly_buffer_underflow, anomaly_shape_dim_limit, anomaly_shape_val_invalid, anomaly_tensor_size_limit, anomaly_invalid_varint_bytes
            );

            // Export stats as JSON file `/tmp/custos_metrics.json`
            let json_metrics = format!(
                r#"{{
  "rx_packets": {},
  "tx_packets": {},
  "recycled_packets": {},
  "drop_validation_failed": {},
  "rx_bytes": {},
  "tx_bytes": {},
  "protocol_counts": {{
    "ipv4": {},
    "tcp": {},
    "http2": {},
    "grpc": {},
    "protobuf": {}
  }},
  "parser_failures": {{
    "too_small": {},
    "non_ipv4": {},
    "bad_ip_len": {},
    "non_tcp": {},
    "bad_ip_csum": {},
    "bad_tcp_len": {},
    "wrong_port": {},
    "bad_http2": {},
    "non_http2_data": {},
    "bad_grpc": {},
    "l4_overflow": {}
  }},
  "anomaly_counts": {{
    "invalid_varint": {},
    "invalid_wire_type": {},
    "recursion_limit": {},
    "buffer_underflow": {},
    "shape_dim_limit": {},
    "shape_val_invalid": {},
    "tensor_size_limit": {},
    "invalid_varint_bytes": {}
  }},
  "histogram_payload_sizes": {{
    "0_64": {},
    "65_256": {},
    "257_1024": {},
    "1025_2048": {}
  }}
}}"#,
                rx_packets,
                tx_packets,
                recycled_packets,
                drop_validation_failed,
                rx_bytes,
                tx_bytes,
                stat_ipv4,
                stat_tcp,
                stat_http2_data,
                stat_grpc,
                stat_protobuf,
                err_too_small,
                err_non_ipv4,
                err_bad_ip_len,
                err_non_tcp,
                err_bad_ip_csum,
                err_bad_tcp_len,
                err_wrong_port,
                err_bad_http2,
                err_non_http2_data,
                err_bad_grpc,
                err_l4_overflow,
                anomaly_invalid_varint,
                anomaly_invalid_wire_type,
                anomaly_recursion_limit,
                anomaly_buffer_underflow,
                anomaly_shape_dim_limit,
                anomaly_shape_val_invalid,
                anomaly_tensor_size_limit,
                anomaly_invalid_varint_bytes,
                hist_payload_0_64,
                hist_payload_65_256,
                hist_payload_257_1024,
                hist_payload_1025_2048
            );

            if let Ok(mut file) = File::create("/tmp/custos_metrics.json") {
                let _ = file.write_all(json_metrics.as_bytes());
            }

            // Export stats in Prometheus format `/tmp/custos_metrics.prom`
            let prom_metrics = format!(
                r#"# HELP custos_rx_packets Total received packets.
# TYPE custos_rx_packets counter
custos_rx_packets {}

# HELP custos_tx_packets Total transmitted packets.
# TYPE custos_tx_packets counter
custos_tx_packets {}

# HELP custos_recycled_packets Total recycled packets.
# TYPE custos_recycled_packets counter
custos_recycled_packets {}

# HELP custos_drop_validation_failed Total packets dropped due to validation failure.
# TYPE custos_drop_validation_failed counter
custos_drop_validation_failed {}

# HELP custos_rx_bytes Total received bytes.
# TYPE custos_rx_bytes counter
custos_rx_bytes {}

# HELP custos_protocol_total Total packets parsed by protocol layer.
# TYPE custos_protocol_total counter
custos_protocol_total{{proto="ipv4"}} {}
custos_protocol_total{{proto="tcp"}} {}
custos_protocol_total{{proto="http2"}} {}
custos_protocol_total{{proto="grpc"}} {}
custos_protocol_total{{proto="protobuf"}} {}

# HELP custos_parser_failures_total Total parser failures at L2-L5 layer.
# TYPE custos_parser_failures_total counter
custos_parser_failures_total{{reason="too_small"}} {}
custos_parser_failures_total{{reason="non_ipv4"}} {}
custos_parser_failures_total{{reason="bad_ip_len"}} {}
custos_parser_failures_total{{reason="non_tcp"}} {}
custos_parser_failures_total{{reason="bad_ip_csum"}} {}
custos_parser_failures_total{{reason="bad_tcp_len"}} {}
custos_parser_failures_total{{reason="wrong_port"}} {}
custos_parser_failures_total{{reason="bad_http2"}} {}
custos_parser_failures_total{{reason="non_http2_data"}} {}
custos_parser_failures_total{{reason="bad_grpc"}} {}
custos_parser_failures_total{{reason="l4_overflow"}} {}

# HELP custos_anomalies_total Total protobuf and shape anomalies.
# TYPE custos_anomalies_total counter
custos_anomalies_total{{reason="invalid_varint"}} {}
custos_anomalies_total{{reason="invalid_wire_type"}} {}
custos_anomalies_total{{reason="recursion_limit"}} {}
custos_anomalies_total{{reason="buffer_underflow"}} {}
custos_anomalies_total{{reason="shape_dim_limit"}} {}
custos_anomalies_total{{reason="shape_val_invalid"}} {}
custos_anomalies_total{{reason="tensor_size_limit"}} {}
custos_anomalies_total{{reason="invalid_varint_bytes"}} {}

# HELP custos_payload_size_bucket Histogram of payload sizes.
# TYPE custos_payload_size_bucket counter
custos_payload_size_bucket{{le="64"}} {}
custos_payload_size_bucket{{le="256"}} {}
custos_payload_size_bucket{{le="1024"}} {}
custos_payload_size_bucket{{le="2048"}} {}
"#,
                rx_packets,
                tx_packets,
                recycled_packets,
                drop_validation_failed,
                rx_bytes,
                stat_ipv4,
                stat_tcp,
                stat_http2_data,
                stat_grpc,
                stat_protobuf,
                err_too_small,
                err_non_ipv4,
                err_bad_ip_len,
                err_non_tcp,
                err_bad_ip_csum,
                err_bad_tcp_len,
                err_wrong_port,
                err_bad_http2,
                err_non_http2_data,
                err_bad_grpc,
                err_l4_overflow,
                anomaly_invalid_varint,
                anomaly_invalid_wire_type,
                anomaly_recursion_limit,
                anomaly_buffer_underflow,
                anomaly_shape_dim_limit,
                anomaly_shape_val_invalid,
                anomaly_tensor_size_limit,
                anomaly_invalid_varint_bytes,
                hist_payload_0_64,
                hist_payload_65_256,
                hist_payload_257_1024,
                hist_payload_1025_2048
            );

            if let Ok(mut file) = File::create("/tmp/custos_metrics.prom") {
                let _ = file.write_all(prom_metrics.as_bytes());
            }

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
            stat_protobuf = 0;
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
            err_l4_overflow = 0;
            anomaly_invalid_varint = 0;
            anomaly_invalid_wire_type = 0;
            anomaly_recursion_limit = 0;
            anomaly_buffer_underflow = 0;
            anomaly_shape_dim_limit = 0;
            anomaly_shape_val_invalid = 0;
            anomaly_tensor_size_limit = 0;
            anomaly_invalid_varint_bytes = 0;
            drop_validation_failed = 0;
            last_stats_time = Instant::now();
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> Result<(), Box<dyn Error>> {
    Err("AF_XDP packet processing is only supported on Linux".into())
}
