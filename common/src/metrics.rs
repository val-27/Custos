//! Prometheus metrics exporter for Custos.
//!
//! Provides a lock-free thread statistics accumulator (`ThreadStats`) and a lightweight,
//! dedicated HTTP server serving metrics in Prometheus Exposition format.
//!
//! # Performance Rationale
//! To guarantee **zero impact on the hot packet processing loop**:
//! 1. Fast-path packet threads update only thread-local atomic counters (`AtomicU64`)
//!    with `Ordering::Relaxed`.
//! 2. Counter structures (`ThreadStats`) are cache-line aligned (64 bytes) to prevent
//!    false sharing across CPU cores.
//! 3. The Prometheus HTTP endpoint runs on an isolated background thread with a minimal
//!    `axum` async web server. It only reads atomic snapshots when scraped by Prometheus.

use axum::{http::header::CONTENT_TYPE, routing::get, Router};
use std::net::SocketAddr;
use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

/// Thread-local metrics structure, aligned to cache lines (64 bytes) to prevent false sharing.
///
/// Each worker CPU core maintains its own instance of `ThreadStats`. All counter updates
/// in the packet loop use atomic operations with `Ordering::Relaxed` to avoid synchronization
/// locks and cache line bounce across cores.
#[derive(Debug)]
#[repr(align(64))]
pub struct ThreadStats {
    /// Total RX packets received by this worker core.
    pub rx_packets: AtomicU64,
    /// Total RX bytes received by this worker core.
    pub rx_bytes: AtomicU64,
    /// Total TX packets submitted by this worker core.
    pub tx_packets: AtomicU64,
    /// Total TX bytes submitted by this worker core.
    pub tx_bytes: AtomicU64,
    /// Total UMEM frames recycled back to the Fill ring.
    pub recycled_packets: AtomicU64,
    /// Total packets dropped due to validation failures.
    pub drop_validation_failed: AtomicU64,

    // Protocol counters
    /// Packets passing Ethernet/IPv4 layer inspection.
    pub stat_ipv4: AtomicU64,
    /// Packets passing TCP layer inspection.
    pub stat_tcp: AtomicU64,
    /// Packets identified as HTTP/2 DATA frames.
    pub stat_http2_data: AtomicU64,
    /// Packets identified as gRPC payload frames.
    pub stat_grpc: AtomicU64,
    /// Packets passing Protobuf wire-format validation.
    pub stat_protobuf: AtomicU64,

    // L2-L5 Parser failure counters
    /// Frame size smaller than minimum Ethernet/IP header.
    pub err_too_small: AtomicU64,
    /// Non-IPv4 EtherType frame.
    pub err_non_ipv4: AtomicU64,
    /// Invalid IPv4 header length or total length.
    pub err_bad_ip_len: AtomicU64,
    /// Non-TCP IP protocol payload.
    pub err_non_tcp: AtomicU64,
    /// Bad IPv4 header checksum.
    pub err_bad_ip_csum: AtomicU64,
    /// Bad TCP data offset or length overflow.
    pub err_bad_tcp_len: AtomicU64,
    /// Destination port does not match target gRPC port.
    pub err_wrong_port: AtomicU64,
    /// Malformed HTTP/2 connection preface or frame header.
    pub err_bad_http2: AtomicU64,
    /// HTTP/2 frame type is not DATA.
    pub err_non_http2_data: AtomicU64,
    /// Invalid gRPC length-prefixed message header.
    pub err_bad_grpc: AtomicU64,
    /// Layer 4 payload boundary overflow.
    pub err_l4_overflow: AtomicU64,

    // Protobuf anomaly counters
    /// Malformed Protobuf varint encoding.
    pub anomaly_invalid_varint: AtomicU64,
    /// Unknown or corrupted wire type field.
    pub anomaly_invalid_wire_type: AtomicU64,
    /// Embedded message recursion depth limit exceeded.
    pub anomaly_recursion_limit: AtomicU64,
    /// Packet truncated before completing Protobuf field tag/value.
    pub anomaly_buffer_underflow: AtomicU64,
    /// Tensor dimension array length limit exceeded.
    pub anomaly_shape_dim_limit: AtomicU64,
    /// Tensor shape dimension value contains invalid value.
    pub anomaly_shape_val_invalid: AtomicU64,
    /// Total tensor byte allocation size limit exceeded.
    pub anomaly_tensor_size_limit: AtomicU64,
    /// Varint length exceeds maximum 10-byte encoding limit.
    pub anomaly_invalid_varint_bytes: AtomicU64,

    // Payload size histogram buckets
    /// Payload size <= 64 bytes.
    pub hist_payload_0_64: AtomicU64,
    /// Payload size 65..=256 bytes.
    pub hist_payload_65_256: AtomicU64,
    /// Payload size 257..=1024 bytes.
    pub hist_payload_257_1024: AtomicU64,
    /// Payload size 1025..=2048 bytes.
    pub hist_payload_1025_2048: AtomicU64,
    /// Payload size > 2048 bytes.
    pub hist_payload_2049_inf: AtomicU64,

    // Packet processing latency histogram (nanoseconds)
    /// Processing latency <= 100 ns.
    pub hist_latency_100ns: AtomicU64,
    /// Processing latency <= 500 ns.
    pub hist_latency_500ns: AtomicU64,
    /// Processing latency <= 1,000 ns (1 us).
    pub hist_latency_1us: AtomicU64,
    /// Processing latency <= 5,000 ns (5 us).
    pub hist_latency_5us: AtomicU64,
    /// Processing latency <= 10,000 ns (10 us).
    pub hist_latency_10us: AtomicU64,
    /// Processing latency <= 50,000 ns (50 us).
    pub hist_latency_50us: AtomicU64,
    /// Processing latency > 50,000 ns (> 50 us).
    pub hist_latency_inf: AtomicU64,
    /// Total cumulative processing latency in nanoseconds.
    pub latency_sum_ns: AtomicU64,
    /// Total count of latency samples measured.
    pub latency_count: AtomicU64,
}

impl Default for ThreadStats {
    fn default() -> Self {
        Self {
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            recycled_packets: AtomicU64::new(0),
            drop_validation_failed: AtomicU64::new(0),
            stat_ipv4: AtomicU64::new(0),
            stat_tcp: AtomicU64::new(0),
            stat_http2_data: AtomicU64::new(0),
            stat_grpc: AtomicU64::new(0),
            stat_protobuf: AtomicU64::new(0),
            err_too_small: AtomicU64::new(0),
            err_non_ipv4: AtomicU64::new(0),
            err_bad_ip_len: AtomicU64::new(0),
            err_non_tcp: AtomicU64::new(0),
            err_bad_ip_csum: AtomicU64::new(0),
            err_bad_tcp_len: AtomicU64::new(0),
            err_wrong_port: AtomicU64::new(0),
            err_bad_http2: AtomicU64::new(0),
            err_non_http2_data: AtomicU64::new(0),
            err_bad_grpc: AtomicU64::new(0),
            err_l4_overflow: AtomicU64::new(0),
            anomaly_invalid_varint: AtomicU64::new(0),
            anomaly_invalid_wire_type: AtomicU64::new(0),
            anomaly_recursion_limit: AtomicU64::new(0),
            anomaly_buffer_underflow: AtomicU64::new(0),
            anomaly_shape_dim_limit: AtomicU64::new(0),
            anomaly_shape_val_invalid: AtomicU64::new(0),
            anomaly_tensor_size_limit: AtomicU64::new(0),
            anomaly_invalid_varint_bytes: AtomicU64::new(0),
            hist_payload_0_64: AtomicU64::new(0),
            hist_payload_65_256: AtomicU64::new(0),
            hist_payload_257_1024: AtomicU64::new(0),
            hist_payload_1025_2048: AtomicU64::new(0),
            hist_payload_2049_inf: AtomicU64::new(0),
            hist_latency_100ns: AtomicU64::new(0),
            hist_latency_500ns: AtomicU64::new(0),
            hist_latency_1us: AtomicU64::new(0),
            hist_latency_5us: AtomicU64::new(0),
            hist_latency_10us: AtomicU64::new(0),
            hist_latency_50us: AtomicU64::new(0),
            hist_latency_inf: AtomicU64::new(0),
            latency_sum_ns: AtomicU64::new(0),
            latency_count: AtomicU64::new(0),
        }
    }
}

impl ThreadStats {
    /// Increments the appropriate payload size histogram bucket for a packet.
    #[inline]
    pub fn record_payload_size(&self, bytes: usize) {
        match bytes {
            0..=64 => {
                self.hist_payload_0_64.fetch_add(1, Ordering::Relaxed);
            }
            65..=256 => {
                self.hist_payload_65_256.fetch_add(1, Ordering::Relaxed);
            }
            257..=1024 => {
                self.hist_payload_257_1024.fetch_add(1, Ordering::Relaxed);
            }
            1025..=2048 => {
                self.hist_payload_1025_2048.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.hist_payload_2049_inf.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Records a packet processing latency sample (in nanoseconds) into histogram buckets.
    #[inline]
    pub fn record_latency_ns(&self, nanos: u64) {
        self.latency_sum_ns.fetch_add(nanos, Ordering::Relaxed);
        self.latency_count.fetch_add(1, Ordering::Relaxed);

        if nanos <= 100 {
            self.hist_latency_100ns.fetch_add(1, Ordering::Relaxed);
        } else if nanos <= 500 {
            self.hist_latency_500ns.fetch_add(1, Ordering::Relaxed);
        } else if nanos <= 1_000 {
            self.hist_latency_1us.fetch_add(1, Ordering::Relaxed);
        } else if nanos <= 5_000 {
            self.hist_latency_5us.fetch_add(1, Ordering::Relaxed);
        } else if nanos <= 10_000 {
            self.hist_latency_10us.fetch_add(1, Ordering::Relaxed);
        } else if nanos <= 50_000 {
            self.hist_latency_50us.fetch_add(1, Ordering::Relaxed);
        } else {
            self.hist_latency_inf.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Configuration parameters for the Prometheus HTTP metrics exporter.
#[derive(Debug, Clone)]
pub struct MetricsConfig {
    /// Whether the Prometheus HTTP endpoint is enabled.
    pub enabled: bool,
    /// TCP port to bind the HTTP server to (default: 9090).
    pub port: u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 9090,
        }
    }
}

/// Handle to manage the background Prometheus HTTP server thread.
pub struct MetricsServerHandle {
    /// Port on which the metrics server is running.
    pub port: u16,
}

/// Renders all accumulated thread counters into Prometheus Exposition Format text.
///
/// Converts atomic snapshots into standard Prometheus metric types (counters, gauges,
/// histograms) with clear labels for per-core breakdown, protocols, parser error reasons,
/// and Protobuf anomaly categories.
pub fn render_prometheus_metrics(stats_list: &[Arc<ThreadStats>], start_time: Instant) -> String {
    let mut rx_packets_total = 0u64;
    let mut rx_bytes_total = 0u64;
    let mut tx_packets_total = 0u64;
    let mut tx_bytes_total = 0u64;
    let mut recycled_packets_total = 0u64;
    let mut drop_validation_failed_total = 0u64;

    let mut stat_ipv4 = 0u64;
    let mut stat_tcp = 0u64;
    let mut stat_http2_data = 0u64;
    let mut stat_grpc = 0u64;
    let mut stat_protobuf = 0u64;

    let mut err_too_small = 0u64;
    let mut err_non_ipv4 = 0u64;
    let mut err_bad_ip_len = 0u64;
    let mut err_non_tcp = 0u64;
    let mut err_bad_ip_csum = 0u64;
    let mut err_bad_tcp_len = 0u64;
    let mut err_wrong_port = 0u64;
    let mut err_bad_http2 = 0u64;
    let mut err_non_http2_data = 0u64;
    let mut err_bad_grpc = 0u64;
    let mut err_l4_overflow = 0u64;

    let mut anomaly_invalid_varint = 0u64;
    let mut anomaly_invalid_wire_type = 0u64;
    let mut anomaly_recursion_limit = 0u64;
    let mut anomaly_buffer_underflow = 0u64;
    let mut anomaly_shape_dim_limit = 0u64;
    let mut anomaly_shape_val_invalid = 0u64;
    let mut anomaly_tensor_size_limit = 0u64;
    let mut anomaly_invalid_varint_bytes = 0u64;

    let mut hist_payload_0_64 = 0u64;
    let mut hist_payload_65_256 = 0u64;
    let mut hist_payload_257_1024 = 0u64;
    let mut hist_payload_1025_2048 = 0u64;
    let mut hist_payload_2049_inf = 0u64;

    let mut hist_lat_100ns = 0u64;
    let mut hist_lat_500ns = 0u64;
    let mut hist_lat_1us = 0u64;
    let mut hist_lat_5us = 0u64;
    let mut hist_lat_10us = 0u64;
    let mut hist_lat_50us = 0u64;
    let mut hist_lat_inf = 0u64;
    let mut lat_sum_ns = 0u64;
    let mut lat_count = 0u64;

    let mut per_core_lines = String::new();

    for (core_idx, s) in stats_list.iter().enumerate() {
        let rx_p = s.rx_packets.load(Ordering::Relaxed);
        let rx_b = s.rx_bytes.load(Ordering::Relaxed);
        let tx_p = s.tx_packets.load(Ordering::Relaxed);
        let tx_b = s.tx_bytes.load(Ordering::Relaxed);
        let drop_val = s.drop_validation_failed.load(Ordering::Relaxed);

        rx_packets_total += rx_p;
        rx_bytes_total += rx_b;
        tx_packets_total += tx_p;
        tx_bytes_total += tx_b;
        recycled_packets_total += s.recycled_packets.load(Ordering::Relaxed);
        drop_validation_failed_total += drop_val;

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
        hist_payload_2049_inf += s.hist_payload_2049_inf.load(Ordering::Relaxed);

        hist_lat_100ns += s.hist_latency_100ns.load(Ordering::Relaxed);
        hist_lat_500ns += s.hist_latency_500ns.load(Ordering::Relaxed);
        hist_lat_1us += s.hist_latency_1us.load(Ordering::Relaxed);
        hist_lat_5us += s.hist_latency_5us.load(Ordering::Relaxed);
        hist_lat_10us += s.hist_latency_10us.load(Ordering::Relaxed);
        hist_lat_50us += s.hist_latency_50us.load(Ordering::Relaxed);
        hist_lat_inf += s.hist_latency_inf.load(Ordering::Relaxed);
        lat_sum_ns += s.latency_sum_ns.load(Ordering::Relaxed);
        lat_count += s.latency_count.load(Ordering::Relaxed);

        per_core_lines.push_str(&format!(
            "custos_core_rx_packets_total{{core=\"{}\"}} {}\n",
            core_idx, rx_p
        ));
        per_core_lines.push_str(&format!(
            "custos_core_tx_packets_total{{core=\"{}\"}} {}\n",
            core_idx, tx_p
        ));
        per_core_lines.push_str(&format!(
            "custos_core_dropped_packets_total{{core=\"{}\"}} {}\n",
            core_idx, drop_val
        ));
        per_core_lines.push_str(&format!(
            "custos_core_rx_bytes_total{{core=\"{}\"}} {}\n",
            core_idx, rx_b
        ));
        per_core_lines.push_str(&format!(
            "custos_core_tx_bytes_total{{core=\"{}\"}} {}\n",
            core_idx, tx_b
        ));
    }

    let elapsed_secs = start_time.elapsed().as_secs_f64();
    let uptime = if elapsed_secs > 0.0 {
        elapsed_secs
    } else {
        0.001
    };
    let rx_pps = rx_packets_total as f64 / uptime;
    let tx_pps = tx_packets_total as f64 / uptime;
    let rx_bps = rx_bytes_total as f64 / uptime;
    let tx_bps = tx_bytes_total as f64 / uptime;

    // Cumulative histogram bucket counts for payload size
    let cum_p64 = hist_payload_0_64;
    let cum_p256 = cum_p64 + hist_payload_65_256;
    let cum_p1024 = cum_p256 + hist_payload_257_1024;
    let cum_p2048 = cum_p1024 + hist_payload_1025_2048;
    let cum_p_inf = cum_p2048 + hist_payload_2049_inf;

    // Cumulative histogram bucket counts for processing latency (in seconds)
    let cum_l100ns = hist_lat_100ns;
    let cum_l500ns = cum_l100ns + hist_lat_500ns;
    let cum_l1us = cum_l500ns + hist_lat_1us;
    let cum_l5us = cum_l1us + hist_lat_5us;
    let cum_l10us = cum_l5us + hist_lat_10us;
    let cum_l50us = cum_l10us + hist_lat_50us;
    let cum_linf = cum_l50us + hist_lat_inf;
    let latency_sum_seconds = lat_sum_ns as f64 / 1_000_000_000.0;

    let mut out = String::with_capacity(4096);

    out.push_str("# HELP custos_up Appliance status (1 for running).\n");
    out.push_str("# TYPE custos_up gauge\n");
    out.push_str("custos_up 1\n\n");

    out.push_str("# HELP custos_uptime_seconds Appliance uptime in seconds.\n");
    out.push_str("# TYPE custos_uptime_seconds counter\n");
    out.push_str(&format!("custos_uptime_seconds {:.3}\n\n", uptime));

    out.push_str("# HELP custos_rx_packets_total Total packets received across all cores.\n");
    out.push_str("# TYPE custos_rx_packets_total counter\n");
    out.push_str(&format!("custos_rx_packets_total {}\n\n", rx_packets_total));

    out.push_str("# HELP custos_rx_bytes_total Total bytes received across all cores.\n");
    out.push_str("# TYPE custos_rx_bytes_total counter\n");
    out.push_str(&format!("custos_rx_bytes_total {}\n\n", rx_bytes_total));

    out.push_str("# HELP custos_tx_packets_total Total packets transmitted across all cores.\n");
    out.push_str("# TYPE custos_tx_packets_total counter\n");
    out.push_str(&format!("custos_tx_packets_total {}\n\n", tx_packets_total));

    out.push_str("# HELP custos_tx_bytes_total Total bytes transmitted across all cores.\n");
    out.push_str("# TYPE custos_tx_bytes_total counter\n");
    out.push_str(&format!("custos_tx_bytes_total {}\n\n", tx_bytes_total));

    out.push_str(
        "# HELP custos_recycled_packets_total Total frames recycled back to UMEM fill ring.\n",
    );
    out.push_str("# TYPE custos_recycled_packets_total counter\n");
    out.push_str(&format!(
        "custos_recycled_packets_total {}\n\n",
        recycled_packets_total
    ));

    out.push_str("# HELP custos_dropped_packets_total Total dropped packets by drop reason.\n");
    out.push_str("# TYPE custos_dropped_packets_total counter\n");
    out.push_str(&format!(
        "custos_dropped_packets_total{{reason=\"validation_failed\"}} {}\n\n",
        drop_validation_failed_total
    ));

    out.push_str("# HELP custos_core_rx_packets_total Received packets per CPU core.\n");
    out.push_str("# TYPE custos_core_rx_packets_total counter\n");
    out.push_str("# HELP custos_core_tx_packets_total Transmitted packets per CPU core.\n");
    out.push_str("# TYPE custos_core_tx_packets_total counter\n");
    out.push_str("# HELP custos_core_dropped_packets_total Dropped packets per CPU core.\n");
    out.push_str("# TYPE custos_core_dropped_packets_total counter\n");
    out.push_str("# HELP custos_core_rx_bytes_total Received bytes per CPU core.\n");
    out.push_str("# TYPE custos_core_rx_bytes_total counter\n");
    out.push_str("# HELP custos_core_tx_bytes_total Transmitted bytes per CPU core.\n");
    out.push_str("# TYPE custos_core_tx_bytes_total counter\n");
    out.push_str(&per_core_lines);
    out.push('\n');

    out.push_str("# HELP custos_protocol_packets_total Total packets inspected by protocol.\n");
    out.push_str("# TYPE custos_protocol_packets_total counter\n");
    out.push_str(&format!(
        "custos_protocol_packets_total{{protocol=\"ipv4\"}} {}\n",
        stat_ipv4
    ));
    out.push_str(&format!(
        "custos_protocol_packets_total{{protocol=\"tcp\"}} {}\n",
        stat_tcp
    ));
    out.push_str(&format!(
        "custos_protocol_packets_total{{protocol=\"http2\"}} {}\n",
        stat_http2_data
    ));
    out.push_str(&format!(
        "custos_protocol_packets_total{{protocol=\"grpc\"}} {}\n",
        stat_grpc
    ));
    out.push_str(&format!(
        "custos_protocol_packets_total{{protocol=\"protobuf\"}} {}\n\n",
        stat_protobuf
    ));

    out.push_str("# HELP custos_parser_errors_total Total L2-L5 parser errors by reason.\n");
    out.push_str("# TYPE custos_parser_errors_total counter\n");
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"too_small\"}} {}\n",
        err_too_small
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"non_ipv4\"}} {}\n",
        err_non_ipv4
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"bad_ip_len\"}} {}\n",
        err_bad_ip_len
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"non_tcp\"}} {}\n",
        err_non_tcp
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"bad_ip_csum\"}} {}\n",
        err_bad_ip_csum
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"bad_tcp_len\"}} {}\n",
        err_bad_tcp_len
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"wrong_port\"}} {}\n",
        err_wrong_port
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"bad_http2\"}} {}\n",
        err_bad_http2
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"non_http2_data\"}} {}\n",
        err_non_http2_data
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"bad_grpc\"}} {}\n",
        err_bad_grpc
    ));
    out.push_str(&format!(
        "custos_parser_errors_total{{reason=\"l4_overflow\"}} {}\n\n",
        err_l4_overflow
    ));

    out.push_str("# HELP custos_anomalies_total Total Protobuf wire-format anomalies by type.\n");
    out.push_str("# TYPE custos_anomalies_total counter\n");
    out.push_str(&format!(
        "custos_anomalies_total{{type=\"invalid_varint\"}} {}\n",
        anomaly_invalid_varint
    ));
    out.push_str(&format!(
        "custos_anomalies_total{{type=\"invalid_wire_type\"}} {}\n",
        anomaly_invalid_wire_type
    ));
    out.push_str(&format!(
        "custos_anomalies_total{{type=\"recursion_limit\"}} {}\n",
        anomaly_recursion_limit
    ));
    out.push_str(&format!(
        "custos_anomalies_total{{type=\"buffer_underflow\"}} {}\n",
        anomaly_buffer_underflow
    ));
    out.push_str(&format!(
        "custos_anomalies_total{{type=\"shape_dim_limit\"}} {}\n",
        anomaly_shape_dim_limit
    ));
    out.push_str(&format!(
        "custos_anomalies_total{{type=\"shape_val_invalid\"}} {}\n",
        anomaly_shape_val_invalid
    ));
    out.push_str(&format!(
        "custos_anomalies_total{{type=\"tensor_size_limit\"}} {}\n",
        anomaly_tensor_size_limit
    ));
    out.push_str(&format!(
        "custos_anomalies_total{{type=\"invalid_varint_bytes\"}} {}\n\n",
        anomaly_invalid_varint_bytes
    ));

    out.push_str("# HELP custos_payload_bytes Payload size histogram in bytes.\n");
    out.push_str("# TYPE custos_payload_bytes histogram\n");
    out.push_str(&format!(
        "custos_payload_bytes_bucket{{le=\"64\"}} {}\n",
        cum_p64
    ));
    out.push_str(&format!(
        "custos_payload_bytes_bucket{{le=\"256\"}} {}\n",
        cum_p256
    ));
    out.push_str(&format!(
        "custos_payload_bytes_bucket{{le=\"1024\"}} {}\n",
        cum_p1024
    ));
    out.push_str(&format!(
        "custos_payload_bytes_bucket{{le=\"2048\"}} {}\n",
        cum_p2048
    ));
    out.push_str(&format!(
        "custos_payload_bytes_bucket{{le=\"+Inf\"}} {}\n",
        cum_p_inf
    ));
    out.push_str(&format!("custos_payload_bytes_count {}\n\n", cum_p_inf));

    out.push_str("# HELP custos_processing_latency_seconds Packet processing latency histogram in seconds.\n");
    out.push_str("# TYPE custos_processing_latency_seconds histogram\n");
    out.push_str(&format!(
        "custos_processing_latency_seconds_bucket{{le=\"0.0000001\"}} {}\n",
        cum_l100ns
    ));
    out.push_str(&format!(
        "custos_processing_latency_seconds_bucket{{le=\"0.0000005\"}} {}\n",
        cum_l500ns
    ));
    out.push_str(&format!(
        "custos_processing_latency_seconds_bucket{{le=\"0.000001\"}} {}\n",
        cum_l1us
    ));
    out.push_str(&format!(
        "custos_processing_latency_seconds_bucket{{le=\"0.000005\"}} {}\n",
        cum_l5us
    ));
    out.push_str(&format!(
        "custos_processing_latency_seconds_bucket{{le=\"0.00001\"}} {}\n",
        cum_l10us
    ));
    out.push_str(&format!(
        "custos_processing_latency_seconds_bucket{{le=\"0.00005\"}} {}\n",
        cum_l50us
    ));
    out.push_str(&format!(
        "custos_processing_latency_seconds_bucket{{le=\"+Inf\"}} {}\n",
        cum_linf
    ));
    out.push_str(&format!(
        "custos_processing_latency_seconds_sum {:.9}\n",
        latency_sum_seconds
    ));
    out.push_str(&format!(
        "custos_processing_latency_seconds_count {}\n\n",
        lat_count
    ));

    out.push_str("# HELP custos_rx_pps Calculated RX rate in packets per second.\n");
    out.push_str("# TYPE custos_rx_pps gauge\n");
    out.push_str(&format!("custos_rx_pps {:.2}\n\n", rx_pps));

    out.push_str("# HELP custos_tx_pps Calculated TX rate in packets per second.\n");
    out.push_str("# TYPE custos_tx_pps gauge\n");
    out.push_str(&format!("custos_tx_pps {:.2}\n\n", tx_pps));

    out.push_str("# HELP custos_rx_bps Calculated RX rate in bytes per second.\n");
    out.push_str("# TYPE custos_rx_bps gauge\n");
    out.push_str(&format!("custos_rx_bps {:.2}\n\n", rx_bps));

    out.push_str("# HELP custos_tx_bps Calculated TX rate in bytes per second.\n");
    out.push_str("# TYPE custos_tx_bps gauge\n");
    out.push_str(&format!("custos_tx_bps {:.2}\n", tx_bps));

    out
}

/// Starts the Prometheus HTTP metrics exporter on a dedicated background thread.
///
/// If `config.enabled` is `false`, this function immediately returns without launching
/// any network thread or allocating resources.
///
/// When enabled, spawns an isolated thread with a single-threaded Tokio runtime running an
/// `axum` web server. Scraped metrics are rendered on-demand from atomic counter snapshots.
pub fn start_metrics_server(
    config: MetricsConfig,
    stats_list: Vec<Arc<ThreadStats>>,
) -> std::io::Result<Option<MetricsServerHandle>> {
    if !config.enabled {
        tracing::info!("Prometheus metrics exporter disabled by configuration");
        return Ok(None);
    }

    let port = config.port;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let start_time = Instant::now();

    std::thread::Builder::new()
        .name("custos-metrics".to_string())
        .spawn(move || {
            rt.block_on(async move {
                let stats_for_metrics = stats_list.clone();
                let app = Router::new()
                    .route(
                        "/metrics",
                        get(move || {
                            let s = stats_for_metrics.clone();
                            async move {
                                let body = render_prometheus_metrics(&s, start_time);
                                (
                                    [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
                                    body,
                                )
                            }
                        }),
                    )
                    .route("/healthz", get(|| async { "OK" }))
                    .route(
                        "/",
                        get(|| async { "Custos Prometheus Metrics Exporter: GET /metrics" }),
                    );

                tracing::info!(
                    "Prometheus metrics endpoint listening on http://{}/metrics",
                    addr
                );

                match tokio::net::TcpListener::from_std(listener) {
                    Ok(listener) => {
                        if let Err(err) = axum::serve(listener, app).await {
                            tracing::error!("Prometheus metrics HTTP server error: {:?}", err);
                        }
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to start Prometheus metrics HTTP server on port {}: {:?}",
                            port,
                            e
                        );
                    }
                }
            });
        })
        .map(|_| ())?;

    Ok(Some(MetricsServerHandle { port }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_stats_recording() {
        let stats = ThreadStats::default();
        stats.rx_packets.fetch_add(10, Ordering::Relaxed);
        stats.rx_bytes.fetch_add(15000, Ordering::Relaxed);
        stats.record_payload_size(100);
        stats.record_payload_size(1200);
        stats.record_latency_ns(450);

        assert_eq!(stats.rx_packets.load(Ordering::Relaxed), 10);
        assert_eq!(stats.rx_bytes.load(Ordering::Relaxed), 15000);
        assert_eq!(stats.hist_payload_65_256.load(Ordering::Relaxed), 1);
        assert_eq!(stats.hist_payload_1025_2048.load(Ordering::Relaxed), 1);
        assert_eq!(stats.hist_latency_500ns.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_prometheus_exposition_format() {
        let stats1 = Arc::new(ThreadStats::default());
        stats1.rx_packets.store(100, Ordering::Relaxed);
        stats1.tx_packets.store(95, Ordering::Relaxed);
        stats1.drop_validation_failed.store(5, Ordering::Relaxed);
        stats1.stat_ipv4.store(100, Ordering::Relaxed);
        stats1.stat_grpc.store(95, Ordering::Relaxed);
        stats1.record_payload_size(500);
        stats1.record_latency_ns(800);

        let stats2 = Arc::new(ThreadStats::default());
        stats2.rx_packets.store(200, Ordering::Relaxed);
        stats2.tx_packets.store(200, Ordering::Relaxed);

        let start = Instant::now() - std::time::Duration::from_secs(2);
        let metrics_text = render_prometheus_metrics(&[stats1, stats2], start);

        assert!(metrics_text.contains("custos_up 1"));
        assert!(metrics_text.contains("custos_rx_packets_total 300"));
        assert!(metrics_text.contains("custos_tx_packets_total 295"));
        assert!(
            metrics_text.contains("custos_dropped_packets_total{reason=\"validation_failed\"} 5")
        );
        assert!(metrics_text.contains("custos_core_rx_packets_total{core=\"0\"} 100"));
        assert!(metrics_text.contains("custos_core_rx_packets_total{core=\"1\"} 200"));
        assert!(metrics_text.contains("custos_protocol_packets_total{protocol=\"grpc\"} 95"));
        assert!(metrics_text.contains("custos_payload_bytes_bucket{le=\"1024\"} 1"));
        assert!(
            metrics_text.contains("custos_processing_latency_seconds_bucket{le=\"0.000001\"} 1")
        );
    }
}
