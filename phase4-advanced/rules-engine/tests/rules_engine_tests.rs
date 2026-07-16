use custos_rules_engine::{
    match_packet, BlockReason, DimensionBound, DynamicPolicy, MatchResult, Policy, PolicyManager,
    ProtobufRules, ShapeRule,
};
use std::collections::HashSet;
use std::net::Ipv4Addr;

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

fn build_mock_packet(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto_payload: &[u8],
) -> Vec<u8> {
    use zerocopy::byteorder::network_endian::{U16, U32};
    use zerocopy::AsBytes;

    let mut buf = vec![0u8; 68 + proto_payload.len()];

    // 1. Ethernet Header (14 bytes)
    let eth = custos_grpc_basic::EtherHdr {
        dst_mac: [0u8; 6],
        src_mac: [0u8; 6],
        ether_type: U16::new(0x0800),
    };
    buf[0..14].copy_from_slice(eth.as_bytes());

    // 2. IPv4 Header (20 bytes)
    let mut ip = custos_grpc_basic::IpHdr {
        version_ihl: 0x45,
        tos: 0,
        total_len: U16::new((54 + proto_payload.len()) as u16),
        id: U16::new(1),
        flags_fragment: U16::new(0),
        ttl: 64,
        proto: 6, // TCP
        hdr_checksum: U16::new(0),
        src_ip,
        dst_ip,
    };
    let csum = calculate_checksum(&ip.as_bytes());
    ip.hdr_checksum = U16::new(csum);
    buf[14..34].copy_from_slice(ip.as_bytes());

    // 3. TCP Header (20 bytes)
    let tcp = custos_grpc_basic::TcpHdr {
        src_port: U16::new(src_port),
        dst_port: U16::new(dst_port),
        seq_num: U32::new(100),
        ack_num: U32::new(200),
        data_offset_reserved_flags: U16::new(5 << 12),
        window_size: U16::new(1024),
        checksum: U16::new(0),
        urgent_pointer: U16::new(0),
    };
    buf[34..54].copy_from_slice(tcp.as_bytes());

    // 4. HTTP/2 Header (9 bytes)
    let http2_len = (proto_payload.len() + 5) as u32;
    let http2 = custos_grpc_basic::Http2Hdr {
        length: [
            ((http2_len >> 16) & 0xff) as u8,
            ((http2_len >> 8) & 0xff) as u8,
            (http2_len & 0xff) as u8,
        ],
        frame_type: 0x0, // DATA
        flags: 0,
        stream_id: U32::new(1),
    };
    buf[54..63].copy_from_slice(http2.as_bytes());

    // 5. gRPC Header (5 bytes)
    let grpc = custos_grpc_basic::GrpcHdr {
        compression_flag: 0,
        message_len: U32::new(proto_payload.len() as u32),
    };
    buf[63..68].copy_from_slice(grpc.as_bytes());

    // 6. Protobuf Payload
    buf[68..].copy_from_slice(proto_payload);

    buf
}

fn build_mock_packet_with_message_len(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    proto_payload: &[u8],
    message_len: u32,
) -> Vec<u8> {
    use zerocopy::byteorder::network_endian::U32;

    let mut buf = build_mock_packet(src_ip, dst_ip, src_port, dst_port, proto_payload);
    let grpc = custos_grpc_basic::GrpcHdr {
        compression_flag: 0,
        message_len: U32::new(message_len),
    };
    buf[63..68].copy_from_slice(zerocopy::AsBytes::as_bytes(&grpc));
    buf
}

#[test]
fn test_ip_and_port_validation() {
    let mut allowed_ports = HashSet::new();
    allowed_ports.insert(50051);

    let mut blocked_ips = HashSet::new();
    blocked_ips.insert(Ipv4Addr::new(192, 168, 1, 10));

    let policy = DynamicPolicy::try_from(Policy {
        version: "1.0.0".to_string(),
        description: None,
        allowed_ports: Some(allowed_ports),
        blocked_ips: Some(blocked_ips),
        protobuf_rules: None,
    })
    .unwrap();

    // 1. Allowed packet
    let packet_ok = build_mock_packet([192, 168, 1, 1], [192, 168, 1, 2], 12345, 50051, &[]);
    assert_eq!(match_packet(&packet_ok, &policy), MatchResult::Allow);

    // 2. Blocked by IP
    let packet_bad_ip = build_mock_packet([192, 168, 1, 10], [192, 168, 1, 2], 12345, 50051, &[]);
    assert_eq!(
        match_packet(&packet_bad_ip, &policy),
        MatchResult::Block(BlockReason::BlockedIP(Ipv4Addr::new(192, 168, 1, 10)))
    );

    // 3. Blocked by Port
    let packet_bad_port = build_mock_packet([192, 168, 1, 1], [192, 168, 1, 2], 12345, 8080, &[]);
    assert_eq!(
        match_packet(&packet_bad_port, &policy),
        MatchResult::Block(BlockReason::BlockedPort(8080))
    );

    let mut packet_udp = build_mock_packet([192, 168, 1, 1], [192, 168, 1, 2], 12345, 50051, &[]);
    packet_udp[23] = 17;
    assert_eq!(
        match_packet(&packet_udp, &policy),
        MatchResult::Block(BlockReason::InvalidPacket)
    );
}

#[test]
fn test_field_allow_list() {
    let mut field_allow_list = HashSet::new();
    field_allow_list.insert(1); // field 1 allowed

    let policy = DynamicPolicy::try_from(Policy {
        version: "1.0.0".to_string(),
        description: None,
        allowed_ports: None,
        blocked_ips: None,
        protobuf_rules: Some(ProtobufRules {
            max_varint_bytes: None,
            max_recursion_depth: None,
            field_allow_list: Some(field_allow_list),
            shape_rules: None,
        }),
    })
    .unwrap();

    // Field 1 tag: (1 << 3) | 0 = 8 (Varint)
    // Value: 42
    let payload_ok = vec![0x08, 0x2A];
    let packet_ok = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_ok,
    );
    assert_eq!(match_packet(&packet_ok, &policy), MatchResult::Allow);

    // Field 2 tag: (2 << 3) | 0 = 16 (Varint)
    let payload_bad = vec![0x10, 0x2A];
    let packet_bad = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_bad,
    );
    assert_eq!(
        match_packet(&packet_bad, &policy),
        MatchResult::Block(BlockReason::DisallowedField(2))
    );
}

#[test]
fn test_shape_dimension_bounds() {
    let policy = DynamicPolicy::try_from(Policy {
        version: "1.0.0".to_string(),
        description: None,
        allowed_ports: None,
        blocked_ips: None,
        protobuf_rules: Some(ProtobufRules {
            max_varint_bytes: None,
            max_recursion_depth: None,
            field_allow_list: None,
            shape_rules: Some(vec![ShapeRule {
                field_number: 1,
                min_dimensions: Some(2),
                max_dimensions: Some(4),
                max_tensor_elements: None,
                exact_shapes: None,
                dimension_bounds: None,
            }]),
        }),
    })
    .unwrap();

    // 1. Packed Shape [128, 128] -> 2 dimensions (OK)
    // Tag: (1 << 3) | 2 = 10 (0x0A)
    // Length: 4 bytes
    // Values: 128 (0x80, 0x01), 128 (0x80, 0x01)
    let payload_ok = vec![0x0A, 0x04, 0x80, 0x01, 0x80, 0x01];
    let packet_ok = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_ok,
    );
    assert_eq!(match_packet(&packet_ok, &policy), MatchResult::Allow);

    // 2. Packed Shape [224] -> 1 dimension (Too small)
    // Length: 2 bytes
    // Values: 224 (0xE0, 0x01)
    let payload_too_small = vec![0x0A, 0x02, 0xE0, 0x01];
    let packet_too_small = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_too_small,
    );
    assert_eq!(
        match_packet(&packet_too_small, &policy),
        MatchResult::Block(BlockReason::ShapeDimensionTooSmall {
            field: 1,
            got: 1,
            limit: 2
        })
    );

    // 3. Packed Shape [1, 3, 224, 224, 224] -> 5 dimensions (Too large)
    let payload_too_large = vec![0x0A, 0x07, 0x01, 0x03, 0xE0, 0x01, 0xE0, 0x01, 0xE0, 0x01];
    let packet_too_large = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_too_large,
    );
    assert_eq!(
        match_packet(&packet_too_large, &policy),
        MatchResult::Block(BlockReason::ShapeDimensionLimitExceeded {
            field: 1,
            got: 5,
            limit: 4
        })
    );

    let payload_unpacked_ok = vec![0x08, 0x80, 0x01, 0x08, 0x80, 0x01];
    let packet_unpacked_ok = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_unpacked_ok,
    );
    assert_eq!(
        match_packet(&packet_unpacked_ok, &policy),
        MatchResult::Allow
    );
}

#[test]
fn test_grpc_message_len_bounds_protobuf_walk() {
    let mut field_allow_list = HashSet::new();
    field_allow_list.insert(1);

    let policy = DynamicPolicy::try_from(Policy {
        version: "1.0.0".to_string(),
        description: None,
        allowed_ports: None,
        blocked_ips: None,
        protobuf_rules: Some(ProtobufRules {
            max_varint_bytes: None,
            max_recursion_depth: None,
            field_allow_list: Some(field_allow_list),
            shape_rules: None,
        }),
    })
    .unwrap();

    let payload = vec![0x08, 0x2A, 0x10, 0x2A];
    let packet = build_mock_packet_with_message_len(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload,
        2,
    );

    assert_eq!(match_packet(&packet, &policy), MatchResult::Allow);
}

#[test]
fn test_grpc_message_len_bounds_scalar_skip() {
    let mut field_allow_list = HashSet::new();
    field_allow_list.insert(1);

    let policy = DynamicPolicy::try_from(Policy {
        version: "1.0.0".to_string(),
        description: None,
        allowed_ports: None,
        blocked_ips: None,
        protobuf_rules: Some(ProtobufRules {
            max_varint_bytes: None,
            max_recursion_depth: None,
            field_allow_list: Some(field_allow_list),
            shape_rules: None,
        }),
    })
    .unwrap();

    let payload = vec![0x09, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let packet = build_mock_packet_with_message_len(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload,
        2,
    );

    assert_eq!(
        match_packet(&packet, &policy),
        MatchResult::Block(BlockReason::InvalidProto(
            custos_protobuf::ProtoError::BufferUnderflow
        ))
    );
}

#[test]
fn test_tensor_size_constraints() {
    let policy = DynamicPolicy::try_from(Policy {
        version: "1.0.0".to_string(),
        description: None,
        allowed_ports: None,
        blocked_ips: None,
        protobuf_rules: Some(ProtobufRules {
            max_varint_bytes: None,
            max_recursion_depth: None,
            field_allow_list: None,
            shape_rules: Some(vec![ShapeRule {
                field_number: 1,
                min_dimensions: None,
                max_dimensions: None,
                max_tensor_elements: Some(10000), // Limit is 10k elements
                exact_shapes: None,
                dimension_bounds: None,
            }]),
        }),
    })
    .unwrap();

    // [64, 64] = 4096 (OK)
    let payload_ok = vec![0x0A, 0x02, 0x40, 0x40];
    let packet_ok = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_ok,
    );
    assert_eq!(match_packet(&packet_ok, &policy), MatchResult::Allow);

    // [128, 128] = 16384 (Too large)
    // 128 in varint: 0x80, 0x01
    let payload_bad = vec![0x0A, 0x04, 0x80, 0x01, 0x80, 0x01];
    let packet_bad = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_bad,
    );
    assert_eq!(
        match_packet(&packet_bad, &policy),
        MatchResult::Block(BlockReason::TensorSizeLimitExceeded {
            field: 1,
            got: 16384,
            limit: 10000
        })
    );

    let payload_split_bad = vec![0x0A, 0x02, 0xE8, 0x07, 0x0A, 0x02, 0xE8, 0x07];
    let packet_split_bad = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_split_bad,
    );
    assert_eq!(
        match_packet(&packet_split_bad, &policy),
        MatchResult::Block(BlockReason::TensorSizeLimitExceeded {
            field: 1,
            got: 1000000,
            limit: 10000
        })
    );
}

#[test]
fn test_exact_shapes() {
    let policy = DynamicPolicy::try_from(Policy {
        version: "1.0.0".to_string(),
        description: None,
        allowed_ports: None,
        blocked_ips: None,
        protobuf_rules: Some(ProtobufRules {
            max_varint_bytes: None,
            max_recursion_depth: None,
            field_allow_list: None,
            shape_rules: Some(vec![ShapeRule {
                field_number: 1,
                min_dimensions: None,
                max_dimensions: None,
                max_tensor_elements: None,
                exact_shapes: Some(vec![vec![1, 3, 224, 224], vec![1, 3, 256, 256]]),
                dimension_bounds: None,
            }]),
        }),
    })
    .unwrap();

    // Shape [1, 3, 224, 224] (OK)
    let payload_ok = vec![0x0A, 0x06, 0x01, 0x03, 0xE0, 0x01, 0xE0, 0x01];
    let packet_ok = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_ok,
    );
    assert_eq!(match_packet(&packet_ok, &policy), MatchResult::Allow);

    // Shape [1, 3, 128, 128] (Mismatch)
    let payload_bad = vec![0x0A, 0x06, 0x01, 0x03, 0x80, 0x01, 0x80, 0x01];
    let packet_bad = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_bad,
    );
    assert_eq!(
        match_packet(&packet_bad, &policy),
        MatchResult::Block(BlockReason::ExactShapeMismatch { field: 1 })
    );
}

#[test]
fn test_dimension_index_bounds() {
    let policy = DynamicPolicy::try_from(Policy {
        version: "1.0.0".to_string(),
        description: None,
        allowed_ports: None,
        blocked_ips: None,
        protobuf_rules: Some(ProtobufRules {
            max_varint_bytes: None,
            max_recursion_depth: None,
            field_allow_list: None,
            shape_rules: Some(vec![ShapeRule {
                field_number: 1,
                min_dimensions: None,
                max_dimensions: None,
                max_tensor_elements: None,
                exact_shapes: None,
                dimension_bounds: Some(vec![
                    DimensionBound {
                        index: 0, // Batch size must be [1, 8]
                        min: Some(1),
                        max: Some(8),
                    },
                    DimensionBound {
                        index: 1, // Channels must be exactly 3
                        min: Some(3),
                        max: Some(3),
                    },
                ]),
            }]),
        }),
    })
    .unwrap();

    // Shape [4, 3, 224, 224] (OK)
    let payload_ok = vec![0x0A, 0x06, 0x04, 0x03, 0xE0, 0x01, 0xE0, 0x01];
    let packet_ok = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_ok,
    );
    assert_eq!(match_packet(&packet_ok, &policy), MatchResult::Allow);

    // Shape [16, 3, 224, 224] (Batch size 16 exceeds limit 8)
    let payload_bad_batch = vec![0x0A, 0x06, 0x10, 0x03, 0xE0, 0x01, 0xE0, 0x01];
    let packet_bad_batch = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_bad_batch,
    );
    assert_eq!(
        match_packet(&packet_bad_batch, &policy),
        MatchResult::Block(BlockReason::DimensionBoundViolation {
            field: 1,
            index: 0,
            val: 16,
            min: Some(1),
            max: Some(8)
        })
    );

    // Shape [4, 1, 224, 224] (Channels size 1 is below limit 3)
    let payload_bad_chan = vec![0x0A, 0x06, 0x04, 0x01, 0xE0, 0x01, 0xE0, 0x01];
    let packet_bad_chan = build_mock_packet(
        [192, 168, 1, 1],
        [192, 168, 1, 2],
        12345,
        50051,
        &payload_bad_chan,
    );
    assert_eq!(
        match_packet(&packet_bad_chan, &policy),
        MatchResult::Block(BlockReason::DimensionBoundViolation {
            field: 1,
            index: 1,
            val: 1,
            min: Some(3),
            max: Some(3)
        })
    );
}

#[test]
fn test_policy_manager_hot_reload() {
    let policy_v1 = DynamicPolicy::try_from(Policy {
        version: "1.0.0".to_string(),
        description: None,
        allowed_ports: None,
        blocked_ips: None,
        protobuf_rules: Some(ProtobufRules {
            max_varint_bytes: None,
            max_recursion_depth: None,
            field_allow_list: None,
            shape_rules: Some(vec![ShapeRule {
                field_number: 1,
                min_dimensions: None,
                max_dimensions: Some(4), // Rank <= 4
                max_tensor_elements: None,
                exact_shapes: None,
                dimension_bounds: None,
            }]),
        }),
    })
    .unwrap();

    let manager = PolicyManager::new(policy_v1);

    // Shape [1, 3, 224, 224] (Rank 4, OK)
    let payload = vec![0x0A, 0x06, 0x01, 0x03, 0xE0, 0x01, 0xE0, 0x01];
    let packet = build_mock_packet([192, 168, 1, 1], [192, 168, 1, 2], 12345, 50051, &payload);

    // Match against current policy (OK)
    assert_eq!(
        match_packet(&packet, &manager.get_policy()),
        MatchResult::Allow
    );

    // Swap/reload with version 2 policy restricting Rank <= 2
    let policy_v2 = DynamicPolicy::try_from(Policy {
        version: "2.0.0".to_string(),
        description: None,
        allowed_ports: None,
        blocked_ips: None,
        protobuf_rules: Some(ProtobufRules {
            max_varint_bytes: None,
            max_recursion_depth: None,
            field_allow_list: None,
            shape_rules: Some(vec![ShapeRule {
                field_number: 1,
                min_dimensions: None,
                max_dimensions: Some(2), // Rank <= 2
                max_tensor_elements: None,
                exact_shapes: None,
                dimension_bounds: None,
            }]),
        }),
    })
    .unwrap();

    manager.reload(policy_v2);

    // Verify policy reloaded to 2.0.0
    assert_eq!(manager.get_policy().version, "2.0.0");

    // Match the same packet again (should now be BLOCKED due to Rank 4 > 2)
    assert_eq!(
        match_packet(&packet, &manager.get_policy()),
        MatchResult::Block(BlockReason::ShapeDimensionLimitExceeded {
            field: 1,
            got: 4,
            limit: 2
        })
    );
}

#[test]
fn test_policy_parsing_json_toml() {
    let toml_str = r#"
        version = "1.1.0"
        allowed_ports = [50051, 8080]
        blocked_ips = ["10.0.0.1", "192.168.1.5"]

        [protobuf_rules]
        max_varint_bytes = 9
        max_recursion_depth = 5
        field_allow_list = [1, 2, 3]

        [[protobuf_rules.shape_rules]]
        field_number = 1
        min_dimensions = 2
        max_dimensions = 4
        max_tensor_elements = 1000000
        exact_shapes = [[1, 3, 224, 224], [1, 3, 256, 256]]

        [[protobuf_rules.shape_rules.dimension_bounds]]
        index = 0
        min = 1
        max = 32
    "#;

    let policy_toml = Policy::from_toml(toml_str).unwrap();
    assert_eq!(policy_toml.version, "1.1.0");
    assert!(policy_toml.allowed_ports.unwrap().contains(&50051));
    assert!(policy_toml
        .blocked_ips
        .unwrap()
        .contains(&Ipv4Addr::new(10, 0, 0, 1)));

    let json_str = r#"{
        "version": "1.2.0",
        "allowed_ports": [50051],
        "blocked_ips": ["10.0.0.2"],
        "protobuf_rules": {
            "max_varint_bytes": 10,
            "max_recursion_depth": 3,
            "field_allow_list": [1],
            "shape_rules": [
                {
                    "field_number": 1,
                    "min_dimensions": 2,
                    "max_dimensions": 4,
                    "max_tensor_elements": 50000,
                    "exact_shapes": [[1, 3, 224, 224]]
                }
            ]
        }
    }"#;

    let policy_json = Policy::from_json(json_str).unwrap();
    assert_eq!(policy_json.version, "1.2.0");
    assert_eq!(
        policy_json.protobuf_rules.unwrap().max_varint_bytes,
        Some(10)
    );
}
