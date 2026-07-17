//! Custos Benchmark and Visualization Tool Library
//!
//! Provides the core packet generator, PCAP writer, metrics tracker,
//! and visualization services (web dashboard and reporting).

use std::io::{self, Write};
use std::time::Duration;
use serde::{Deserialize, Serialize};
use zerocopy::byteorder::network_endian::{U16, U32};
use zerocopy::AsBytes;

use custos_grpc_basic::{EtherHdr, IpHdr, TcpHdr, Http2Hdr, GrpcHdr, calculate_checksum};

// =========================================================================
// 1. Packet Generation Engine
// =========================================================================

/// Types of traffic to simulate, covering normal flows and validation errors.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum TrafficProfile {
    /// Valid packed shape protobuf over gRPC.
    ValidPacked,
    /// Valid unpacked shape protobuf over gRPC.
    ValidUnpacked,
    /// Invalid shape dimension value (<= 0).
    InvalidShapeValue,
    /// Number of dimensions exceeds maximum allowed.
    ShapeDimLimitExceeded,
    /// Recursion depth limit exceeded.
    RecursionLimitExceeded,
    /// Invalid Varint encoding.
    InvalidVarint,
    /// Buffer underflow during field reading.
    BufferUnderflow,
    /// Invalid wire type for shape field.
    InvalidWireType,
    /// Incorrect TCP checksum.
    BadTcpChecksum,
    /// Malformed IP header length.
    BadIpHdrLen,
    /// Protocol is not IPv4.
    NonIpv4,
    /// Target port is incorrect.
    WrongPort,
    /// Malformed HTTP/2 frame.
    BadHttp2,
    /// Malformed gRPC header.
    BadGrpc,
}

/// Parameters for packet creation.
#[derive(Debug, Clone)]
pub struct PacketGenParams {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub profile: TrafficProfile,
}

impl Default for PacketGenParams {
    fn default() -> Self {
        Self {
            dst_mac: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
            src_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            src_ip: [192, 168, 1, 2],
            dst_ip: [192, 168, 1, 1],
            src_port: 12345,
            dst_port: 50051,
            profile: TrafficProfile::ValidPacked,
        }
    }
}

/// Generates a serialized Ethernet frame representing the requested traffic profile.
pub fn generate_packet(params: &PacketGenParams) -> Vec<u8> {
    // 1. Generate protobuf payload according to profile
    let proto_payload = match params.profile {
        TrafficProfile::ValidPacked => {
            // Shape: [1, 3, 224, 224] (packed)
            // Tag: 0x0a (field 1, wire type 2), Length: 5, Values: 1, 3, 224, 224
            vec![0x0a, 5, 1, 3, 0xe0, 0x01, 0xe0, 0x01]
        }
        TrafficProfile::ValidUnpacked => {
            // Shape: [1, 3, 10] (unpacked)
            // Tag: 0x08 (field 1, wire type 0)
            vec![0x08, 1, 0x08, 3, 0x08, 10]
        }
        TrafficProfile::InvalidShapeValue => {
            // Shape contains a 0 or negative: [1, 0, 5] -> [0x0a, 3, 1, 0, 5]
            vec![0x0a, 3, 1, 0, 5]
        }
        TrafficProfile::ShapeDimLimitExceeded => {
            // Generates more than 16 dimensions (dimension limit is 16 in parser buffer)
            let mut payload = vec![0x0a, 20];
            for _ in 0..20 {
                payload.push(1);
            }
            payload
        }
        TrafficProfile::RecursionLimitExceeded => {
            // Nested messages exceeding limit (max recursion is 3)
            // Field 2 (wire type 2) nested 5 times:
            // Msg5: Shape [1] -> [0x0a, 1, 1]
            // Msg4: [0x12, 3, 0x0a, 1, 1] (len 3)
            // Msg3: [0x12, 5, 0x12, 3, 0x0a, 1, 1] (len 5)
            // Msg2: [0x12, 7, 0x12, 5, 0x12, 3, 0x0a, 1, 1] (len 7)
            // Msg1: [0x12, 9, 0x12, 7, 0x12, 5, 0x12, 3, 0x0a, 1, 1] (len 9)
            vec![0x12, 9, 0x12, 7, 0x12, 5, 0x12, 3, 0x0a, 1, 1]
        }
        TrafficProfile::InvalidVarint => {
            // A varint exceeding 10 bytes standard limit
            vec![0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        }
        TrafficProfile::BufferUnderflow => {
            // Declares length 100 but only provides 3 bytes
            vec![0x0a, 100, 1, 2, 3]
        }
        TrafficProfile::InvalidWireType => {
            // Field 1 with wire type 5 (32-bit float) instead of varint or length-delimited
            vec![0x0d, 1, 2, 3, 4]
        }
        _ => {
            // For other headers-only failures, use valid protobuf payload
            vec![0x0a, 5, 1, 3, 0xe0, 0x01, 0xe0, 0x01]
        }
    };

    // Calculate wrapper lengths
    let proto_len = proto_payload.len();
    let mut grpc_payload_len = proto_len;
    let http2_payload_len = proto_len + 5; // Includes 5 bytes gRPC header
    
    if let TrafficProfile::BadGrpc = params.profile {
        // Bad gRPC: message len field is corrupted or larger than HTTP2 frame
        grpc_payload_len = proto_len + 1000;
    }

    let mut frame_type = 0x0; // DATA
    if let TrafficProfile::BadHttp2 = params.profile {
        // HTTP/2 frame type is not DATA (e.g. 0x9 which is invalid for grpc request body validation)
        frame_type = 0xff;
    }

    let total_l5_len = http2_payload_len + 9; // HTTP2 header is 9 bytes
    let total_l4_len = total_l5_len + 20;    // TCP header is 20 bytes minimum
    let mut total_l3_len = total_l4_len + 20; // IP header is 20 bytes minimum

    if let TrafficProfile::BadIpHdrLen = params.profile {
        // Malformed IP length
        total_l3_len = 10;
    }

    // Allocate buffer
    let buffer_size = 14 + (total_l3_len as usize);
    let mut buf = vec![0u8; buffer_size];

    // 2. Ethernet Header
    let ether_type = if let TrafficProfile::NonIpv4 = params.profile {
        0x0806 // ARP instead of IPv4
    } else {
        0x0800 // IPv4
    };
    let eth = EtherHdr {
        dst_mac: params.dst_mac,
        src_mac: params.src_mac,
        ether_type: U16::new(ether_type),
    };
    buf[0..14].copy_from_slice(eth.as_bytes());

    // 3. IP Header
    let mut version_ihl = 0x45; // Version 4, IHL 5 (20 bytes)
    if let TrafficProfile::BadIpHdrLen = params.profile {
        version_ihl = 0x44; // IHL 4 is malformed (< 5 is invalid)
    }

    let mut ip = IpHdr {
        version_ihl,
        tos: 0,
        total_len: U16::new(total_l3_len as u16),
        id: U16::new(42),
        flags_fragment: U16::new(0),
        ttl: 64,
        proto: 6, // TCP
        hdr_checksum: U16::new(0),
        src_ip: params.src_ip,
        dst_ip: params.dst_ip,
    };
    // Calculate IP checksum
    let csum = calculate_checksum(ip.as_bytes());
    ip.hdr_checksum = U16::new(csum);
    buf[14..34].copy_from_slice(ip.as_bytes());

    // 4. TCP Header
    let dst_port = if let TrafficProfile::WrongPort = params.profile {
        9999 // Wrong port
    } else {
        params.dst_port
    };

    let mut tcp = TcpHdr {
        src_port: U16::new(params.src_port),
        dst_port: U16::new(dst_port),
        seq_num: U32::new(1000),
        ack_num: U32::new(2000),
        data_offset_reserved_flags: U16::new(5 << 12), // 20 bytes TCP header
        window_size: U16::new(8192),
        checksum: U16::new(0),
        urgent_pointer: U16::new(0),
    };

    // Calculate TCP Checksum (requires pseudo header)
    // For benchmarks, we can calculate a valid one unless BadTcpChecksum is requested
    let mut tcp_bytes = tcp.as_bytes().to_vec();
    // HTTP2 header
    let h2_len = http2_payload_len as u32;
    let h2_hdr = Http2Hdr {
        length: [
            ((h2_len >> 16) & 0xff) as u8,
            ((h2_len >> 8) & 0xff) as u8,
            (h2_len & 0xff) as u8,
        ],
        frame_type,
        flags: 0,
        stream_id: U32::new(1),
    };
    tcp_bytes.extend_from_slice(h2_hdr.as_bytes());

    // gRPC header
    let grpc_hdr = GrpcHdr {
        compression_flag: 0,
        message_len: U32::new(grpc_payload_len as u32),
    };
    tcp_bytes.extend_from_slice(grpc_hdr.as_bytes());
    tcp_bytes.extend_from_slice(&proto_payload);

    // Padding if odd size
    if tcp_bytes.len() % 2 != 0 {
        tcp_bytes.push(0);
    }

    // Pseudo-header calculation for TCP checksum
    let mut pseudo_hdr = Vec::new();
    pseudo_hdr.extend_from_slice(&params.src_ip);
    pseudo_hdr.extend_from_slice(&params.dst_ip);
    pseudo_hdr.push(0);
    pseudo_hdr.push(6); // TCP proto
    let tcp_len = (tcp_bytes.len() as u16).to_be_bytes();
    pseudo_hdr.extend_from_slice(&tcp_len);
    pseudo_hdr.extend_from_slice(&tcp_bytes);

    let tcp_csum = if let TrafficProfile::BadTcpChecksum = params.profile {
        0xdead // Corrupted checksum
    } else {
        calculate_checksum(&pseudo_hdr)
    };
    
    tcp.checksum = U16::new(tcp_csum);
    buf[34..54].copy_from_slice(tcp.as_bytes());

    // 5. HTTP/2 and gRPC payloads
    buf[54..63].copy_from_slice(h2_hdr.as_bytes());
    buf[63..68].copy_from_slice(grpc_hdr.as_bytes());
    buf[68..68+proto_len].copy_from_slice(&proto_payload);

    buf
}

// =========================================================================
// 2. PCAP Writing Engine
// =========================================================================

/// Beautiful, dependency-free PCAP file writer.
pub struct PcapWriter<W: Write> {
    writer: W,
}

impl<W: Write> PcapWriter<W> {
    /// Creates a new PCAP writer and initializes it with the standard PCAP global header.
    pub fn new(mut writer: W) -> io::Result<Self> {
        // Write global PCAP header (24 bytes)
        // Magic: 0xa1b2c3d4 (microsecond resolution)
        writer.write_all(&0xa1b2c3d4u32.to_ne_bytes())?;
        writer.write_all(&2u16.to_ne_bytes())?; // Version Major
        writer.write_all(&4u16.to_ne_bytes())?; // Version Minor
        writer.write_all(&0i32.to_ne_bytes())?; // Timezone
        writer.write_all(&0u32.to_ne_bytes())?; // Sigfigs
        writer.write_all(&65535u32.to_ne_bytes())?; // Snaplen
        writer.write_all(&1u32.to_ne_bytes())?; // Network Link-Type (1 = Ethernet)
        Ok(Self { writer })
    }

    /// Appends a packet to the PCAP file.
    pub fn write_packet(&mut self, timestamp: Duration, packet: &[u8]) -> io::Result<()> {
        let ts_sec = timestamp.as_secs() as u32;
        let ts_usec = timestamp.subsec_micros() as u32;
        let len = packet.len() as u32;

        // Record header (16 bytes)
        self.writer.write_all(&ts_sec.to_ne_bytes())?;
        self.writer.write_all(&ts_usec.to_ne_bytes())?;
        self.writer.write_all(&len.to_ne_bytes())?; // Saved length
        self.writer.write_all(&len.to_ne_bytes())?; // Original length
        self.writer.write_all(packet)?;
        Ok(())
    }
}

// =========================================================================
// 3. Metrics Tracking & Calculation
// =========================================================================

/// Replicated structure of `/tmp/custos_metrics.json`
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CustosMetrics {
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub recycled_packets: u64,
    pub drop_validation_failed: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub protocol_counts: ProtocolCounts,
    pub parser_failures: ParserFailures,
    pub anomalies: Anomalies,
    pub payload_size_histogram: PayloadHistogram,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProtocolCounts {
    pub ipv4: u64,
    pub tcp: u64,
    pub http2: u64,
    pub grpc: u64,
    pub protobuf: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParserFailures {
    pub too_small: u64,
    pub non_ipv4: u64,
    pub bad_ip_len: u64,
    pub non_tcp: u64,
    pub bad_ip_csum: u64,
    pub bad_tcp_len: u64,
    pub wrong_port: u64,
    pub bad_http2: u64,
    pub non_http2_data: u64,
    pub bad_grpc: u64,
    pub l4_overflow: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Anomalies {
    pub invalid_varint: u64,
    pub invalid_wire_type: u64,
    pub recursion_limit: u64,
    pub buffer_underflow: u64,
    pub shape_dim_limit: u64,
    pub shape_val_invalid: u64,
    pub tensor_size_limit: u64,
    pub invalid_varint_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PayloadHistogram {
    #[serde(rename = "0_64")]
    pub range_0_64: u64,
    #[serde(rename = "65_256")]
    pub range_65_256: u64,
    #[serde(rename = "257_1024")]
    pub range_257_1024: u64,
    #[serde(rename = "1025_2048")]
    pub range_1025_2048: u64,
}

/// Latency distribution metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LatencyStats {
    pub p50_us: f64,
    pub p90_us: f64,
    pub p99_us: f64,
    pub p999_us: f64,
}

/// Aggregated rate metrics computed over a time window.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RateMetrics {
    pub rx_pps: f64,
    pub tx_pps: f64,
    pub drop_pps: f64,
    pub rx_gbps: f64,
    pub tx_gbps: f64,
    pub total_rx: u64,
    pub total_tx: u64,
    pub total_dropped: u64,
    pub cpu_cores_pct: Vec<f32>,
    pub cache_miss_rate: f64,
}

/// A circular buffer history tracking metrics for UI rendering.
#[derive(Clone)]
pub struct PerformanceHistory {
    pub rx_pps: Vec<f64>,
    pub rx_gbps: Vec<f64>,
    pub drop_pps: Vec<f64>,
    pub capacity: usize,
}

impl PerformanceHistory {
    pub fn new(capacity: usize) -> Self {
        Self {
            rx_pps: vec![0.0; capacity],
            rx_gbps: vec![0.0; capacity],
            drop_pps: vec![0.0; capacity],
            capacity,
        }
    }

    pub fn push(&mut self, rx_pps: f64, rx_gbps: f64, drop_pps: f64) {
        if self.rx_pps.len() >= self.capacity {
            self.rx_pps.remove(0);
            self.rx_gbps.remove(0);
            self.drop_pps.remove(0);
        }
        self.rx_pps.push(rx_pps);
        self.rx_gbps.push(rx_gbps);
        self.drop_pps.push(drop_pps);
    }
}

// =========================================================================
// 4. In-Memory Validator (Used for mock / overhead benching)
// =========================================================================

/// Measures overhead of the validation engine.
pub fn run_in_memory_validation(packet: &[u8], config: &custos_protobuf::ValidationConfig) -> Result<([i64; 16], usize), custos_protobuf::ValidationError> {
    custos_protobuf::validate_grpc_protobuf_packet(packet, config)
}

// =========================================================================
// 5. Web Dashboard Chart Renderer (Using Plotters for clean SVGs)
// =========================================================================

/// Renders a beautiful SVG line chart representing throughput or packet rate history.
pub fn render_svg_chart(
    title: &str,
    labels: &[String],
    data: &[f64],
    _y_label: &str,
    color_hex: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    use plotters::prelude::*;

    let mut svg_buf = String::new();
    {
        let root = SVGBackend::with_string(&mut svg_buf, (600, 300)).into_drawing_area();
        root.fill(&RGBAColor(30, 37, 44, 1.0))?; // Dark dashboard theme background

        let max_val = data.iter().cloned().fold(0.0f64, f64::max) * 1.15;
        let max_val = if max_val == 0.0 { 1.0 } else { max_val };

        let mut chart = ChartBuilder::on(&root)
            .caption(title, ("sans-serif", 16, &WHITE))
            .margin(10)
            .x_label_area_size(30)
            .y_label_area_size(40)
            .build_cartesian_2d(0..data.len(), 0.0..max_val)?;

        chart.configure_mesh()
            .bold_line_style(&RGBAColor(60, 70, 80, 0.4))
            .light_line_style(&RGBAColor(50, 60, 70, 0.2))
            .x_label_formatter(&|x| {
                if *x < labels.len() {
                    labels[*x].clone()
                } else {
                    String::new()
                }
            })
            .axis_style(&RGBAColor(120, 130, 140, 0.8))
            .label_style(("sans-serif", 10, &RGBAColor(200, 200, 200, 0.9)))
            .draw()?;

        // Parse color
        let r = u8::from_str_radix(&color_hex[1..3], 16)?;
        let g = u8::from_str_radix(&color_hex[3..5], 16)?;
        let b = u8::from_str_radix(&color_hex[5..7], 16)?;
        let plot_color = RGBAColor(r, g, b, 1.0);
        let area_color = RGBAColor(r, g, b, 0.15);

        // Draw area under line
        chart.draw_series(
            AreaSeries::new(
                (0..data.len()).map(|x| (x, data[x])),
                0.0,
                &area_color,
            )
        )?;

        // Draw line
        chart.draw_series(LineSeries::new(
            (0..data.len()).map(|x| (x, data[x])),
            &plot_color,
        ))?;
        
        root.present()?;
    }

    Ok(svg_buf)
}

/// Renders a latency histogram SVG.
pub fn render_latency_histogram(
    stats: &LatencyStats,
) -> Result<String, Box<dyn std::error::Error>> {
    use plotters::prelude::*;

    let mut svg_buf = String::new();
    {
        let root = SVGBackend::with_string(&mut svg_buf, (600, 300)).into_drawing_area();
        root.fill(&RGBAColor(30, 37, 44, 1.0))?;

        let labels = ["p50", "p90", "p99", "p99.9"];
        let values = [stats.p50_us, stats.p90_us, stats.p99_us, stats.p999_us];
        let max_val = values.iter().cloned().fold(0.0f64, f64::max) * 1.15;
        let max_val = if max_val == 0.0 { 1.0 } else { max_val };

        let mut chart = ChartBuilder::on(&root)
            .caption("Packet Latency Profile (microseconds)", ("sans-serif", 16, &WHITE))
            .margin(10)
            .x_label_area_size(30)
            .y_label_area_size(45)
            .build_cartesian_2d(0..4, 0.0..max_val)?;

        chart.configure_mesh()
            .bold_line_style(&RGBAColor(60, 70, 80, 0.4))
            .light_line_style(&RGBAColor(50, 60, 70, 0.2))
            .x_label_formatter(&|x: &i32| {
                let idx = *x as usize;
                if idx < 4 {
                    labels[idx].to_string()
                } else {
                    String::new()
                }
            })
            .axis_style(&RGBAColor(120, 130, 140, 0.8))
            .label_style(("sans-serif", 10, &RGBAColor(200, 200, 200, 0.9)))
            .draw()?;

        chart.draw_series(
            (0..4).map(|x: i32| {
                let color = match x {
                    0 => RGBAColor(46, 204, 113, 0.8),  // emerald green
                    1 => RGBAColor(52, 152, 219, 0.8),  // blue
                    2 => RGBAColor(241, 196, 15, 0.8),  // yellow
                    _ => RGBAColor(231, 76, 60, 0.8),   // red
                };
                Rectangle::new(
                    [(x, 0.0), (x + 1, values[x as usize])],
                    color.filled(),
                )
            })
        )?;

        root.present()?;
    }

    Ok(svg_buf)
}

// =========================================================================
// 6. PDF/HTML Report Generator
// =========================================================================

/// Builds a self-contained HTML report with embedded styles and charts.
pub fn generate_html_report(
    profile_name: &str,
    duration: Duration,
    metrics: &CustosMetrics,
    rates: &RateMetrics,
    _latency: &LatencyStats,
    throughput_svg: &str,
    latency_svg: &str,
) -> String {
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Custos Performance Benchmark Report</title>
    <style>
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0f141c;
            color: #e2e8f0;
            margin: 0;
            padding: 40px;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1000px;
            margin: 0 auto;
            background: #18202c;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.5);
            border: 1px solid #2d3748;
        }}
        h1 {{
            color: #63b3ed;
            font-size: 2.2rem;
            margin-bottom: 5px;
            border-bottom: 2px solid #2d3748;
            padding-bottom: 15px;
        }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin: 30px 0;
            background: #1e293b;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #334155;
        }}
        .meta-card h3 {{
            margin: 0;
            font-size: 0.85rem;
            color: #94a3b8;
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }}
        .meta-card p {{
            margin: 5px 0 0 0;
            font-size: 1.25rem;
            font-weight: bold;
            color: #f8fafc;
        }}
        .section-title {{
            color: #cbd5e1;
            font-size: 1.4rem;
            margin-top: 40px;
            margin-bottom: 20px;
            border-bottom: 1px solid #334155;
            padding-bottom: 8px;
        }}
        .chart-container {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin: 30px 0;
        }}
        .chart-box {{
            background: #131924;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #2d3748;
            text-align: center;
        }}
        .chart-box svg {{
            width: 100%;
            max-width: 100%;
            height: auto;
            border-radius: 4px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            background: #1e293b;
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #334155;
        }}
        th {{
            background-color: #0f172a;
            color: #38bdf8;
            font-size: 0.9rem;
            text-transform: uppercase;
        }}
        tr:hover {{
            background-color: #243247;
        }}
        .badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .badge-success {{ background: #064e3b; color: #34d399; }}
        .badge-error {{ background: #7f1d1d; color: #f87171; }}
        .footer {{
            margin-top: 50px;
            text-align: center;
            font-size: 0.85rem;
            color: #64748b;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Custos Validation Performance Report</h1>
        <p style="color:#94a3b8; margin-top:-5px;">Generated at: <strong>{now}</strong> | System: <strong>Project Custos High-Performance Pipeline</strong></p>

        <div class="meta-grid">
            <div class="meta-card">
                <h3>Test Profile</h3>
                <p>{profile_name}</p>
            </div>
            <div class="meta-card">
                <h3>Duration</h3>
                <p>{duration:?}</p>
            </div>
            <div class="meta-card">
                <h3>Avg Throughput</h3>
                <p>{rates_rx_gbps:.3} Gbps</p>
            </div>
            <div class="meta-card">
                <h3>Avg Packet Rate</h3>
                <p>{rates_rx_pps:.1} pps</p>
            </div>
        </div>

        <div class="section-title">Performance Graphs</div>
        <div class="chart-container">
            <div class="chart-box">
                <h4 style="margin: 0 0 10px 0; color: #63b3ed;">Throughput Profile</h4>
                {throughput_svg}
            </div>
            <div class="chart-box">
                <h4 style="margin: 0 0 10px 0; color: #63b3ed;">Latency Percentiles</h4>
                {latency_svg}
            </div>
        </div>

        <div class="section-title">Aggregated Packet Counters</div>
        <table>
            <thead>
                <tr>
                    <th>Metric Counter</th>
                    <th>Total Value</th>
                    <th>Average Rate (per sec)</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Packets Received (RX)</td>
                    <td><strong>{metrics_rx_packets}</strong></td>
                    <td>{rates_rx_pps:.2} pps</td>
                </tr>
                <tr>
                    <td>Packets Transmitted (TX)</td>
                    <td><strong>{metrics_tx_packets}</strong></td>
                    <td>{rates_tx_pps:.2} pps</td>
                </tr>
                <tr>
                    <td>Packets Recycled (Fast Re-use)</td>
                    <td><strong>{metrics_recycled_packets}</strong></td>
                    <td>-</td>
                </tr>
                <tr>
                    <td>Validation Drop Decisions</td>
                    <td><strong style="color: #f87171;">{metrics_drop_validation_failed}</strong></td>
                    <td style="color: #f87171;">{rates_drop_pps:.2} pps</td>
                </tr>
                <tr>
                    <td>Bytes Received (RX)</td>
                    <td><strong>{metrics_rx_bytes} B</strong> ({metrics_rx_bytes_mb:.2} MB)</td>
                    <td>{rates_rx_mbps:.2} Mbps</td>
                </tr>
            </tbody>
        </table>

        <div class="section-title">Protocol Breakdown</div>
        <table>
            <thead>
                <tr>
                    <th>Layer</th>
                    <th>Protocol</th>
                    <th>Match Count</th>
                </tr>
            </thead>
            <tbody>
                <tr>
                    <td>Layer 3 (Network)</td>
                    <td>IPv4</td>
                    <td>{metrics_proto_ipv4}</td>
                </tr>
                <tr>
                    <td>Layer 4 (Transport)</td>
                    <td>TCP</td>
                    <td>{metrics_proto_tcp}</td>
                </tr>
                <tr>
                    <td>Layer 5 (Application)</td>
                    <td>HTTP/2</td>
                    <td>{metrics_proto_http2}</td>
                </tr>
                <tr>
                    <td>Layer 6 (RPC)</td>
                    <td>gRPC</td>
                    <td>{metrics_proto_grpc}</td>
                </tr>
                <tr>
                    <td>Layer 7 (Serialization)</td>
                    <td>Protobuf Payload Walked</td>
                    <td>{metrics_proto_protobuf}</td>
                </tr>
            </tbody>
        </table>

        <div class="section-title">Parser Overhead & Validation Failures</div>
        <div style="display:grid; grid-template-columns: 1fr 1fr; gap: 20px;">
            <div>
                <h4 style="color:#f87171;">L2-L5 Wrapper Failures</h4>
                <table>
                    <thead>
                        <tr>
                            <th>Failure Cause</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Packet Too Small</td><td>{pf_too_small}</td></tr>
                        <tr><td>Non-IPv4 Frame</td><td>{pf_non_ipv4}</td></tr>
                        <tr><td>Invalid IP Length</td><td>{pf_bad_ip_len}</td></tr>
                        <tr><td>Non-TCP Segment</td><td>{pf_non_tcp}</td></tr>
                        <tr><td>Bad IP Checksum</td><td>{pf_bad_ip_csum}</td></tr>
                        <tr><td>Bad TCP Length</td><td>{pf_bad_tcp_len}</td></tr>
                        <tr><td>Wrong Destination Port</td><td>{pf_wrong_port}</td></tr>
                        <tr><td>Bad HTTP/2 Frame</td><td>{pf_bad_http2}</td></tr>
                        <tr><td>Non-HTTP/2 Data</td><td>{pf_non_http2_data}</td></tr>
                        <tr><td>Bad gRPC Envelope</td><td>{pf_bad_grpc}</td></tr>
                        <tr><td>L4 Packet Overflow</td><td>{pf_l4_overflow}</td></tr>
                    </tbody>
                </table>
            </div>

            <div>
                <h4 style="color:#f87171;">Protobuf Wire & Shape Anomalies</h4>
                <table>
                    <thead>
                        <tr>
                            <th>Anomaly Type</th>
                            <th>Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        <tr><td>Invalid Varint</td><td>{an_invalid_varint}</td></tr>
                        <tr><td>Invalid Wire Type</td><td>{an_invalid_wire_type}</td></tr>
                        <tr><td>Recursion Depth Limit Exceeded</td><td>{an_recursion_limit}</td></tr>
                        <tr><td>Buffer Underflow</td><td>{an_buffer_underflow}</td></tr>
                        <tr><td>Dimension Count Limit Exceeded</td><td>{an_shape_dim_limit}</td></tr>
                        <tr><td>Negative/Zero Shape Value</td><td>{an_shape_val_invalid}</td></tr>
                        <tr><td>Total Tensor Size Limit Exceeded</td><td>{an_tensor_size_limit}</td></tr>
                        <tr><td>Max Varint Bytes Exceeded</td><td>{an_invalid_varint_bytes}</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

        <div class="footer">
            <p>Project Custos Benchmark Tool &bull; Designed for Extreme Performance Security Validation</p>
        </div>
    </div>
</body>
</html>"#,
        profile_name = profile_name,
        now = now,
        duration = duration,
        rates_rx_gbps = rates.rx_gbps,
        rates_rx_pps = rates.rx_pps,
        rates_rx_mbps = rates.rx_gbps * 1000.0,
        throughput_svg = throughput_svg,
        latency_svg = latency_svg,
        metrics_rx_packets = metrics.rx_packets,
        rates_tx_pps = rates.tx_pps,
        metrics_tx_packets = metrics.tx_packets,
        metrics_recycled_packets = metrics.recycled_packets,
        metrics_drop_validation_failed = metrics.drop_validation_failed,
        rates_drop_pps = rates.drop_pps,
        metrics_rx_bytes = metrics.rx_bytes,
        metrics_rx_bytes_mb = (metrics.rx_bytes as f64) / (1024.0 * 1024.0),
        metrics_proto_ipv4 = metrics.protocol_counts.ipv4,
        metrics_proto_tcp = metrics.protocol_counts.tcp,
        metrics_proto_http2 = metrics.protocol_counts.http2,
        metrics_proto_grpc = metrics.protocol_counts.grpc,
        metrics_proto_protobuf = metrics.protocol_counts.protobuf,
        pf_too_small = metrics.parser_failures.too_small,
        pf_non_ipv4 = metrics.parser_failures.non_ipv4,
        pf_bad_ip_len = metrics.parser_failures.bad_ip_len,
        pf_non_tcp = metrics.parser_failures.non_tcp,
        pf_bad_ip_csum = metrics.parser_failures.bad_ip_csum,
        pf_bad_tcp_len = metrics.parser_failures.bad_tcp_len,
        pf_wrong_port = metrics.parser_failures.wrong_port,
        pf_bad_http2 = metrics.parser_failures.bad_http2,
        pf_non_http2_data = metrics.parser_failures.non_http2_data,
        pf_bad_grpc = metrics.parser_failures.bad_grpc,
        pf_l4_overflow = metrics.parser_failures.l4_overflow,
        an_invalid_varint = metrics.anomalies.invalid_varint,
        an_invalid_wire_type = metrics.anomalies.invalid_wire_type,
        an_recursion_limit = metrics.anomalies.recursion_limit,
        an_buffer_underflow = metrics.anomalies.buffer_underflow,
        an_shape_dim_limit = metrics.anomalies.shape_dim_limit,
        an_shape_val_invalid = metrics.anomalies.shape_val_invalid,
        an_tensor_size_limit = metrics.anomalies.tensor_size_limit,
        an_invalid_varint_bytes = metrics.anomalies.invalid_varint_bytes,
    )
}
