use custos_rules_engine::{
    match_packet, BlockReason, DynamicPolicy, MatchResult, Policy, PolicyManager,
};
use std::fs::File;
use std::io::Write;
use std::time::Duration;

// Helper to calculate IPv4 Internet Checksum
fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..data.len()).step_by(2) {
        if i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            sum += word as u32;
        } else {
            sum += (data[i] as u32) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn build_mock_packet(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
    use zerocopy::byteorder::network_endian::{U16, U32};
    use zerocopy::AsBytes;

    let mut buf = vec![0u8; 68];

    // Ethernet
    let eth = custos_grpc_basic::EtherHdr {
        dst_mac: [0u8; 6],
        src_mac: [0u8; 6],
        ether_type: U16::new(0x0800),
    };
    buf[0..14].copy_from_slice(eth.as_bytes());

    // IP
    let mut ip = custos_grpc_basic::IpHdr {
        version_ihl: 0x45,
        tos: 0,
        total_len: U16::new(54),
        id: U16::new(1),
        flags_fragment: U16::new(0),
        ttl: 64,
        proto: 6,
        hdr_checksum: U16::new(0),
        src_ip,
        dst_ip,
    };
    let csum = calculate_checksum(&ip.as_bytes());
    ip.hdr_checksum = U16::new(csum);
    buf[14..34].copy_from_slice(ip.as_bytes());

    // TCP
    let tcp = custos_grpc_basic::TcpHdr {
        src_port: U16::new(12345),
        dst_port: U16::new(50051),
        seq_num: U32::new(100),
        ack_num: U32::new(200),
        data_offset_reserved_flags: U16::new(5 << 12),
        window_size: U16::new(1024),
        checksum: U16::new(0),
        urgent_pointer: U16::new(0),
    };
    buf[34..54].copy_from_slice(tcp.as_bytes());

    // HTTP/2
    let http2 = custos_grpc_basic::Http2Hdr {
        length: [0, 0, 5],
        frame_type: 0x0,
        flags: 0,
        stream_id: U32::new(1),
    };
    buf[54..63].copy_from_slice(http2.as_bytes());

    // gRPC
    let grpc = custos_grpc_basic::GrpcHdr {
        compression_flag: 0,
        message_len: U32::new(0),
    };
    buf[63..68].copy_from_slice(grpc.as_bytes());

    buf
}

fn write_policy_to_file(path: &str, content: &str) {
    let mut file = File::create(path).unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
}

fn main() {
    // Initialize tracing logger
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    println!("============================================================");
    println!("        CUSTOS RULES ENGINE: HOT-RELOAD DEMONSTRATION       ");
    println!("============================================================");

    let temp_policy_path = "temp_policy_demo.toml";

    // 1. Write Initial Policy Version 1 (blocks 10.0.0.1)
    let policy_v1_toml = r#"
        version = "1.0.0"
        allowed_ports = [50051]
        blocked_ips = ["10.0.0.1"]
    "#;
    write_policy_to_file(temp_policy_path, policy_v1_toml);
    println!("[Demo] Wrote initial policy configuration (v1.0.0) blocking 10.0.0.1");

    // 2. Load policy and initialize manager
    let policy_v1 = Policy::from_toml(policy_v1_toml).unwrap();
    let dyn_policy_v1 = DynamicPolicy::try_from(policy_v1).unwrap();
    let manager = PolicyManager::new(dyn_policy_v1);

    // 3. Start background file watcher (checking every 100ms)
    let _watcher_thread = manager.start_file_watcher(temp_policy_path, Duration::from_millis(100));
    println!("[Demo] Started background file watcher thread...");

    // Allow the background file watcher thread to start and capture v1 modification time
    std::thread::sleep(Duration::from_millis(200));

    // 4. Simulate packet validation stream

    let pkt_from_h1 = build_mock_packet([10, 0, 0, 1], [192, 168, 1, 2]); // Blocked under v1
    let pkt_from_h2 = build_mock_packet([10, 0, 0, 2], [192, 168, 1, 2]); // Allowed under v1

    println!("\n--- Phase 1: Evaluating with Policy v1.0.0 ---");

    // Evaluate h1
    let res_h1 = match_packet(&pkt_from_h1, &manager.get_policy());
    println!("[Traffic-Loop] Packet from 10.0.0.1: {:?}", res_h1);
    assert!(matches!(
        res_h1,
        MatchResult::Block(BlockReason::BlockedIP(_))
    ));

    // Evaluate h2
    let res_h2 = match_packet(&pkt_from_h2, &manager.get_policy());
    println!("[Traffic-Loop] Packet from 10.0.0.2: {:?}", res_h2);
    assert_eq!(res_h2, MatchResult::Allow);

    // 5. Update Policy on disk to Version 2 (blocks 10.0.0.2)
    let policy_v2_toml = r#"
        version = "2.0.0"
        allowed_ports = [50051]
        blocked_ips = ["10.0.0.2"]
    "#;
    println!("\n[Demo] Modifying policy file to v2.0.0 (blocks 10.0.0.2, allows 10.0.0.1)...");
    write_policy_to_file(temp_policy_path, policy_v2_toml);

    // Wait for file watcher to detect change and reload (250ms is plenty)
    std::thread::sleep(Duration::from_millis(250));

    println!("\n--- Phase 2: Evaluating with Policy v2.0.0 (Hot-Reloaded) ---");
    println!(
        "[Demo] Active Policy Version: {}",
        manager.get_policy().version
    );
    assert_eq!(manager.get_policy().version, "2.0.0");

    // Evaluate h1 (should now be ALLOWED)
    let res_h1_v2 = match_packet(&pkt_from_h1, &manager.get_policy());
    println!("[Traffic-Loop] Packet from 10.0.0.1: {:?}", res_h1_v2);
    assert_eq!(res_h1_v2, MatchResult::Allow);

    // Evaluate h2 (should now be BLOCKED)
    let res_h2_v2 = match_packet(&pkt_from_h2, &manager.get_policy());
    println!("[Traffic-Loop] Packet from 10.0.0.2: {:?}", res_h2_v2);
    assert!(matches!(
        res_h2_v2,
        MatchResult::Block(BlockReason::BlockedIP(_))
    ));

    // 6. Cleanup
    let _ = std::fs::remove_file(temp_policy_path);
    println!("\n[Demo] Cleaned up temporary files.");
    println!("[Demo] SUCCESS: Hot-reload performed atomically without interrupting the traffic validation loop!");
    println!("============================================================");
}
