//! Multi-queue sharding, CPU core thread pinning, and NUMA-aware core selection.
//! Supports shared-nothing Fast Path threads per interface queue with lock-free stats.

use arc_swap::ArcSwap;
use custos_protobuf::ValidationConfig;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub use custos_common::ThreadStats;

/// Shared configuration containing the dynamically hot-swappable rules.
pub struct SharedConfig {
    pub validation: ArcSwap<ValidationConfig>,
}

/// Loads the validation rules configuration from a TOML file.
pub fn load_config_file(path: &str) -> Result<ValidationConfig, Box<dyn std::error::Error>> {
    let content = std::fs::read_to_string(path)?;
    let config: ValidationConfig = toml::from_str(&content)?;
    Ok(config)
}

/// Detects the CPU cores associated with the NUMA node of the specified network interface.
///
/// Under Linux, queries `/sys/class/net/<interface>/device/numa_node` and then parses the
/// CPU list corresponding to that NUMA node.
pub fn get_numa_cores(interface: &str) -> Option<Vec<usize>> {
    let numa_node_path = format!("/sys/class/net/{}/device/numa_node", interface);
    let numa_node_str = std::fs::read_to_string(&numa_node_path).ok()?;
    let numa_node: i32 = numa_node_str.trim().parse().ok()?;
    if numa_node < 0 {
        return None;
    }

    let cpulist_path = format!("/sys/devices/system/node/node{}/cpulist", numa_node);
    let cpulist_str = std::fs::read_to_string(&cpulist_path).ok()?;

    let mut cores = Vec::new();
    for part in cpulist_str.trim().split(',') {
        if part.is_empty() {
            continue;
        }
        if part.contains('-') {
            let mut range = part.split('-');
            let start: usize = range.next()?.parse().ok()?;
            let end: usize = range.next()?.parse().ok()?;
            for c in start..=end {
                cores.push(c);
            }
        } else {
            let core: usize = part.parse().ok()?;
            cores.push(core);
        }
    }

    if cores.is_empty() {
        None
    } else {
        tracing::info!(
            "NUMA awareness: detected NUMA node {} for interface {} with CPU cores {:?}",
            numa_node,
            interface,
            cores
        );
        Some(cores)
    }
}

/// Spawns a configuration file watcher thread.
///
/// Periodically monitors the target file for modification time changes and atomic-swaps
/// the live config when an update is detected.
pub fn spawn_config_watcher(
    path: String,
    shared_config: Arc<SharedConfig>,
    target_port_override: Option<u16>,
) {
    std::thread::spawn(move || {
        let mut last_modified = std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| std::time::SystemTime::now());

        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            if let Ok(metadata) = std::fs::metadata(&path) {
                if let Ok(modified) = metadata.modified() {
                    if modified > last_modified {
                        last_modified = modified;
                        match load_config_file(&path) {
                            Ok(mut new_config) => {
                                if let Some(port) = target_port_override {
                                    new_config.target_port = port;
                                }
                                shared_config.validation.store(Arc::new(new_config));
                                tracing::info!(
                                    "Configuration dynamically reloaded from TOML: {}",
                                    path
                                );
                            }
                            Err(e) => {
                                tracing::error!(
                                    "Failed to dynamically reload TOML config from {}: {:?}",
                                    path,
                                    e
                                );
                            }
                        }
                    }
                }
            }
        }
    });
}

/// Aggregates stats from all worker threads in a lock-free manner and prints/saves them.
pub fn aggregate_and_report_stats(
    stats_list: &[Arc<ThreadStats>],
    elapsed: std::time::Duration,
    verbose: bool,
) {
    let mut rx_packets = 0;
    let mut rx_bytes = 0;
    let mut tx_packets = 0;
    let mut tx_bytes = 0;
    let mut recycled_packets = 0;
    let mut drop_validation_failed = 0;

    let mut stat_ipv4 = 0;
    let mut stat_tcp = 0;
    let mut stat_http2_data = 0;
    let mut stat_grpc = 0;
    let mut stat_protobuf = 0;

    let mut err_too_small = 0;
    let mut err_non_ipv4 = 0;
    let mut err_bad_ip_len = 0;
    let mut err_non_tcp = 0;
    let mut err_bad_ip_csum = 0;
    let mut err_bad_tcp_len = 0;
    let mut err_wrong_port = 0;
    let mut err_bad_http2 = 0;
    let mut err_non_http2_data = 0;
    let mut err_bad_grpc = 0;
    let mut err_l4_overflow = 0;

    let mut anomaly_invalid_varint = 0;
    let mut anomaly_invalid_wire_type = 0;
    let mut anomaly_recursion_limit = 0;
    let mut anomaly_buffer_underflow = 0;
    let mut anomaly_shape_dim_limit = 0;
    let mut anomaly_shape_val_invalid = 0;
    let mut anomaly_tensor_size_limit = 0;
    let mut anomaly_invalid_varint_bytes = 0;

    let mut hist_payload_0_64 = 0;
    let mut hist_payload_65_256 = 0;
    let mut hist_payload_257_1024 = 0;
    let mut hist_payload_1025_2048 = 0;

    for s in stats_list {
        rx_packets += s.rx_packets.load(Ordering::Relaxed);
        rx_bytes += s.rx_bytes.load(Ordering::Relaxed);
        tx_packets += s.tx_packets.load(Ordering::Relaxed);
        tx_bytes += s.tx_bytes.load(Ordering::Relaxed);
        recycled_packets += s.recycled_packets.load(Ordering::Relaxed);
        drop_validation_failed += s.drop_validation_failed.load(Ordering::Relaxed);

        stat_ipv4 += s.stat_ipv4.load(Ordering::Relaxed);
        stat_tcp += s.stat_tcp.load(Ordering::Relaxed);
        stat_http2_data += s.stat_http2_data.load(Ordering::Relaxed);
        stat_grpc += s.stat_grpc.load(Ordering::Relaxed);
        stat_protobuf += s.stat_protobuf.load(Ordering::Relaxed);

        err_too_small += s.err_too_small.load(Ordering::Relaxed);
        err_non_ipv4 += s.err_non_ipv4.load(Ordering::Relaxed);
        err_bad_ip_len += s.err_bad_ip_len.load(Ordering::Relaxed);
        err_non_tcp += s.err_non_tcp.load(Ordering::Relaxed);
        err_bad_ip_csum += s.err_bad_ip_csum.load(Ordering::Relaxed);
        err_bad_tcp_len += s.err_bad_tcp_len.load(Ordering::Relaxed);
        err_wrong_port += s.err_wrong_port.load(Ordering::Relaxed);
        err_bad_http2 += s.err_bad_http2.load(Ordering::Relaxed);
        err_non_http2_data += s.err_non_http2_data.load(Ordering::Relaxed);
        err_bad_grpc += s.err_bad_grpc.load(Ordering::Relaxed);
        err_l4_overflow += s.err_l4_overflow.load(Ordering::Relaxed);

        anomaly_invalid_varint += s.anomaly_invalid_varint.load(Ordering::Relaxed);
        anomaly_invalid_wire_type += s.anomaly_invalid_wire_type.load(Ordering::Relaxed);
        anomaly_recursion_limit += s.anomaly_recursion_limit.load(Ordering::Relaxed);
        anomaly_buffer_underflow += s.anomaly_buffer_underflow.load(Ordering::Relaxed);
        anomaly_shape_dim_limit += s.anomaly_shape_dim_limit.load(Ordering::Relaxed);
        anomaly_shape_val_invalid += s.anomaly_shape_val_invalid.load(Ordering::Relaxed);
        anomaly_tensor_size_limit += s.anomaly_tensor_size_limit.load(Ordering::Relaxed);
        anomaly_invalid_varint_bytes += s.anomaly_invalid_varint_bytes.load(Ordering::Relaxed);

        hist_payload_0_64 += s.hist_payload_0_64.load(Ordering::Relaxed);
        hist_payload_65_256 += s.hist_payload_65_256.load(Ordering::Relaxed);
        hist_payload_257_1024 += s.hist_payload_257_1024.load(Ordering::Relaxed);
        hist_payload_1025_2048 += s.hist_payload_1025_2048.load(Ordering::Relaxed);
    }

    let secs = elapsed.as_secs_f64();
    let pps_rx = rx_packets as f64 / secs;
    let pps_tx = tx_packets as f64 / secs;
    let mbps_rx = (rx_bytes as f64 / secs) / (1024.0 * 1024.0);
    let mbps_tx = (tx_bytes as f64 / secs) / (1024.0 * 1024.0);

    tracing::info!(
        "Stats: RX: {:.2} pps ({:.3} MB/s) | TX: {:.2} pps ({:.3} MB/s) | Total RX: {}, TX: {}, RECYCLED: {}, DROPPED: {}",
        pps_rx, mbps_rx, pps_tx, mbps_tx, rx_packets, tx_packets, recycled_packets, drop_validation_failed
    );
    if verbose {
        tracing::debug!(
            "Protocols: IPv4: {} | TCP: {} | HTTP/2: {} | gRPC: {} | Protobuf: {}",
            stat_ipv4,
            stat_tcp,
            stat_http2_data,
            stat_grpc,
            stat_protobuf
        );
        tracing::debug!(
            "L2-L5 Parser Failures: TooSmall: {} | NonIPv4: {} | BadIpLen: {} | NonTCP: {} | BadIpCsum: {} | BadTcpLen: {} | WrongPort: {} | BadHttp2: {} | NonHttp2Data: {} | BadGrpc: {} | L4Overflow: {}",
            err_too_small, err_non_ipv4, err_bad_ip_len, err_non_tcp, err_bad_ip_csum, err_bad_tcp_len, err_wrong_port, err_bad_http2, err_non_http2_data, err_bad_grpc, err_l4_overflow
        );
        tracing::debug!(
            "Anomalies: Varint: {} | WireType: {} | Recursion: {} | Underflow: {} | Dims: {} | DimVal: {} | TensorSize: {} | VarintBytes: {}",
            anomaly_invalid_varint, anomaly_invalid_wire_type, anomaly_recursion_limit, anomaly_buffer_underflow, anomaly_shape_dim_limit, anomaly_shape_val_invalid, anomaly_tensor_size_limit, anomaly_invalid_varint_bytes
        );
    }

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
  "anomalies": {{
    "invalid_varint": {},
    "invalid_wire_type": {},
    "recursion_limit": {},
    "buffer_underflow": {},
    "shape_dim_limit": {},
    "shape_val_invalid": {},
    "tensor_size_limit": {},
    "invalid_varint_bytes": {}
  }},
  "payload_size_histogram": {{
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

    if let Ok(mut file) = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open("/tmp/custos_metrics.json")
    {
        let _ = file.write_all(json_metrics.as_bytes());
    }
}

use custos_common::pin_thread_to_core;
use custos_tx_optimizations::{
    get_interface_numa_node, pin_thread_to_numa_node_core, CompQueue, FillQueue, FrameDesc,
    OptimizedForwarder, RxQueue, TxQueue, Umem,
};

/// Per-queue resources owned exclusively by a sharded worker.
pub struct ShardResources {
    /// UMEM backing the RX/TX queue pair.
    pub umem: Umem,
    /// Receive queue for the assigned NIC queue.
    pub rx_q: RxQueue,
    /// Transmit queue for the assigned NIC queue.
    pub tx_q: TxQueue,
    /// Completion queue for transmitted descriptors.
    pub cq: CompQueue,
    /// Fill queue for recycled receive descriptors.
    pub fq: FillQueue,
}

/// Spawns a worker sharded to a specific core and queue ID.
///
/// # Performance Rationale
///
/// Implements a strict shared-nothing Fast Path polling loop.
/// The thread is pinned to the specified core, and operates on the dedicated queue
/// without cross-thread sharing of ring buffers or descriptors, avoiding cache bouncing.
/// It also queries the NIC's NUMA affinity and aligns the CPU core pinning accordingly.
pub fn spawn_sharded_worker(
    core_id: usize,
    queue_id: u32,
    interface: &str,
    resources: ShardResources,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. NUMA and Core Affinity Alignment
    // Try to retrieve NUMA node of the interface and align the polling thread.
    if let Some(numa_node) = get_interface_numa_node(interface) {
        tracing::info!(
            "Interface {} is bound to NUMA node {}. Aligning thread...",
            interface,
            numa_node
        );
        match pin_thread_to_numa_node_core(numa_node, core_id) {
            Ok(pinned_core) => {
                tracing::info!(
                    "Successfully pinned thread to NUMA-aligned core {}",
                    pinned_core
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to pin thread to NUMA-aligned core: {:?}. Falling back to core {}.",
                    e,
                    core_id
                );
                pin_thread_to_core(core_id)?;
            }
        }
    } else {
        tracing::info!(
            "No NUMA configuration found for interface {}. Pinning to core {}.",
            interface,
            core_id
        );
        pin_thread_to_core(core_id)?;
    }

    run_worker_loop(core_id, queue_id, resources)
}

/// Spawns a sharded worker backed by mock queues for simulation platforms.
#[cfg(not(target_os = "linux"))]
pub fn spawn_mock_sharded_worker(
    core_id: usize,
    queue_id: u32,
    interface: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (umem, _frame_descs) = Umem::new_mock(65536);
    spawn_sharded_worker(
        core_id,
        queue_id,
        interface,
        ShardResources {
            umem,
            rx_q: RxQueue::new(),
            tx_q: TxQueue::new(),
            cq: CompQueue::new(),
            fq: FillQueue::new(),
        },
    )
}

fn run_worker_loop(
    core_id: usize,
    queue_id: u32,
    resources: ShardResources,
) -> Result<(), Box<dyn std::error::Error>> {
    let ShardResources {
        umem,
        mut rx_q,
        tx_q,
        mut cq,
        mut fq,
    } = resources;

    let mut forwarder = OptimizedForwarder::new(tx_q, 64);
    let mut rx_descs = vec![FrameDesc::default(); 64];

    tracing::info!(
        "Starting sharded Fast Path event loop for queue={} on core={}",
        queue_id,
        core_id
    );

    // 3. Fast Path Polling Loop
    loop {
        // A. Consume from Rx Queue
        // SAFETY: Safe queue access.
        let received = unsafe { rx_q.consume(&mut rx_descs[..]) };

        if received > 0 {
            // B. Zero-copy process and forward
            for desc in rx_descs.iter().take(received) {
                let mut desc = *desc;
                // In-place payload modification / MAC swap simulation
                // SAFETY: Exclusive ownership of the received descriptor.
                unsafe {
                    let mut data = umem.data_mut(&mut desc);
                    let content = data.contents_mut();
                    if content.len() >= 12 {
                        let mut mac_dst = [0u8; 6];
                        let mut mac_src = [0u8; 6];
                        mac_dst.copy_from_slice(&content[0..6]);
                        mac_src.copy_from_slice(&content[6..12]);
                        content[0..6].copy_from_slice(&mac_src);
                        content[6..12].copy_from_slice(&mac_dst);
                    }

                    // Enqueue to TX batcher
                    let _ = forwarder.forward(desc)?;
                }
            }
        }

        // C. Periodic completion reclaiming and batch flushing
        // SAFETY: Safe to reclaim completed Tx frames and flush the batcher.
        unsafe {
            let _ = forwarder.reclaim_completed(&mut cq, &mut fq, &umem, &mut rx_q)?;
            let _ = forwarder.flush()?;
        }

        // Yield slightly if no packets in this cycle
        if received == 0 {
            std::hint::spin_loop();
        }
    }
}
