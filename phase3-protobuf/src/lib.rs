//! Phase 3 Library: lightweight Varint-based Protobuf wire-format walker.
//! Parses and validates Ethernet, IPv4, TCP, HTTP/2, gRPC, and Protobuf layers zero-copy.

use custos_grpc_basic::{parse_grpc_packet, ParseError};
use serde::{Deserialize, Serialize};

/// Error types for Protobuf parsing and validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtoError {
    InvalidVarint,
    InvalidWireType,
    RecursionLimit,
    BufferUnderflow,
    ShapeDimensionLimit,
    ShapeValueInvalid,
    TensorSizeLimit,
    InvalidVarintBytes,
}

/// Unified error representing either a Layer 2-5 wrapper parsing error
/// or a Layer 6-7 Protobuf wire / shape validation anomaly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    Parse(ParseError),
    Proto(ProtoError),
}

/// Configuration for Protobuf and Shape validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationConfig {
    /// Target destination port
    pub target_port: u16,
    /// Protobuf field number containing the shape array
    pub shape_field_number: u32,
    /// Maximum allowed number of shape dimensions (e.g. 4)
    pub max_dimensions: usize,
    /// Maximum allowed total elements in tensor (product of shape)
    pub max_tensor_elements: u64,
    /// Maximum recursion depth for nested messages
    pub max_recursion_depth: usize,
    /// Maximum bytes allowed for a single varint (limits memory usage, default < 10)
    pub max_varint_bytes: usize,
}

impl Default for ValidationConfig {
    fn default() -> Self {
        Self {
            target_port: 50051,
            shape_field_number: 1,
            max_dimensions: 4,
            max_tensor_elements: 1000000,
            max_recursion_depth: 3,
            max_varint_bytes: 9,
        }
    }
}

/// Reads a Varint from a buffer starting at offset, updating offset.
/// Rejects varints that are larger than max_bytes or >= 10 bytes (standard Proto limit).
pub fn read_varint(buf: &[u8], offset: &mut usize, max_bytes: usize) -> Result<u64, ProtoError> {
    let mut val = 0u64;
    let mut shift = 0;
    let mut bytes_read = 0;

    while *offset < buf.len() {
        let byte = buf[*offset];
        *offset += 1;
        bytes_read += 1;

        if bytes_read >= 10 {
            return Err(ProtoError::InvalidVarint);
        }
        if bytes_read > max_bytes {
            return Err(ProtoError::InvalidVarintBytes);
        }

        val |= ((byte & 0x7f) as u64) << shift;
        if (byte & 0x80) == 0 {
            return Ok(val);
        }
        shift += 7;
    }
    Err(ProtoError::BufferUnderflow)
}

/// Skips a field based on its wire type.
pub fn skip_field(
    buf: &[u8],
    offset: &mut usize,
    wire_type: u8,
    max_varint_bytes: usize,
) -> Result<(), ProtoError> {
    match wire_type {
        0 => {
            // Varint
            read_varint(buf, offset, max_varint_bytes)?;
            Ok(())
        }
        1 => {
            // 64-bit
            if *offset + 8 > buf.len() {
                return Err(ProtoError::BufferUnderflow);
            }
            *offset += 8;
            Ok(())
        }
        2 => {
            // Length-delimited
            let len = read_varint(buf, offset, max_varint_bytes)? as usize;
            if *offset + len > buf.len() {
                return Err(ProtoError::BufferUnderflow);
            }
            *offset += len;
            Ok(())
        }
        5 => {
            // 32-bit
            if *offset + 4 > buf.len() {
                return Err(ProtoError::BufferUnderflow);
            }
            *offset += 4;
            Ok(())
        }
        _ => Err(ProtoError::InvalidWireType),
    }
}

/// Walks a protobuf message recursively to extract shape array.
pub fn walk_message(
    buf: &[u8],
    offset: &mut usize,
    end_offset: usize,
    depth: usize,
    config: &ValidationConfig,
    shape: &mut [i64; 16],
    shape_len: &mut usize,
) -> Result<(), ProtoError> {
    if depth > config.max_recursion_depth {
        return Err(ProtoError::RecursionLimit);
    }

    while *offset < end_offset {
        let tag = read_varint(buf, offset, config.max_varint_bytes)?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        if field_number == config.shape_field_number {
            if wire_type == 2 {
                // Packed shape: [Length][Varint][Varint]...
                let len = read_varint(buf, offset, config.max_varint_bytes)? as usize;
                if *offset + len > end_offset {
                    return Err(ProtoError::BufferUnderflow);
                }
                let pack_end = *offset + len;
                while *offset < pack_end {
                    let dim = read_varint(buf, offset, config.max_varint_bytes)? as i64;
                    if *shape_len >= shape.len() {
                        return Err(ProtoError::ShapeDimensionLimit);
                    }
                    if dim <= 0 {
                        return Err(ProtoError::ShapeValueInvalid);
                    }
                    shape[*shape_len] = dim;
                    *shape_len += 1;
                }
            } else if wire_type == 0 {
                // Unpacked shape: [Tag][Varint], [Tag][Varint]...
                let dim = read_varint(buf, offset, config.max_varint_bytes)? as i64;
                if *shape_len >= shape.len() {
                    return Err(ProtoError::ShapeDimensionLimit);
                }
                if dim <= 0 {
                    return Err(ProtoError::ShapeValueInvalid);
                }
                shape[*shape_len] = dim;
                *shape_len += 1;
            } else {
                return Err(ProtoError::InvalidWireType);
            }
        } else {
            // Non-shape field.
            // Speculatively walk inside wire type 2 as a sub-message.
            // If it is a string/bytes, speculative walk fails with Err and we skip it.
            if wire_type == 2 {
                let len = read_varint(buf, offset, config.max_varint_bytes)? as usize;
                if *offset + len > end_offset {
                    return Err(ProtoError::BufferUnderflow);
                }
                let sub_end = *offset + len;
                let mut sub_offset = *offset;

                let saved_shape = *shape;
                let saved_shape_len = *shape_len;

                match walk_message(
                    buf,
                    &mut sub_offset,
                    sub_end,
                    depth + 1,
                    config,
                    shape,
                    shape_len,
                ) {
                    Ok(()) => {
                        *offset = sub_end;
                    }
                    Err(ProtoError::RecursionLimit) => {
                        return Err(ProtoError::RecursionLimit);
                    }
                    Err(_) => {
                        *shape = saved_shape;
                        *shape_len = saved_shape_len;
                        *offset = sub_end;
                    }
                }
            } else {
                skip_field(buf, offset, wire_type, config.max_varint_bytes)?;
            }
        }
    }
    Ok(())
}

/// Fully parses the Ethernet/IP/TCP/HTTP2/gRPC wrappers, walks the Protobuf payload,
/// and validates the tensor shape.
pub fn validate_grpc_protobuf_packet(
    buf: &[u8],
    config: &ValidationConfig,
) -> Result<([i64; 16], usize), ValidationError> {
    // 1. Walk Layer 2-5 wrappers using Phase 2 zero-copy parser
    let parsed = parse_grpc_packet(buf, config.target_port).map_err(ValidationError::Parse)?;

    // 2. Identify the gRPC Payload offset
    // Ethernet (14) + IP Hdr (ihl*4) + TCP Hdr (data_offset*4) + HTTP/2 Hdr (9) + gRPC Hdr (5)
    let ip_offset = 14;
    let ihl = (parsed.ip.version_ihl & 0x0f) as usize;
    let ip_hdr_len = ihl * 4;
    let tcp_offset = ip_offset + ip_hdr_len;
    let data_offset = (parsed.tcp.data_offset_reserved_flags.get() >> 12) as usize;
    let tcp_hdr_len = data_offset * 4;
    let payload_offset = tcp_offset + tcp_hdr_len;

    // Start of the Protobuf payload is after the 9-byte HTTP/2 and 5-byte gRPC header
    let proto_start = payload_offset + 9 + 5;
    let http2_payload_len = ((parsed.http2.length[0] as usize) << 16)
        | ((parsed.http2.length[1] as usize) << 8)
        | (parsed.http2.length[2] as usize);

    // End offset of Protobuf payload inside the TCP frame
    let proto_end = payload_offset + 9 + http2_payload_len;

    if proto_end > buf.len() {
        return Err(ValidationError::Proto(ProtoError::BufferUnderflow));
    }

    let mut shape = [0i64; 16];
    let mut shape_len = 0;
    let mut offset = proto_start;

    // 3. Walk Protobuf fields zero-copy
    walk_message(
        buf,
        &mut offset,
        proto_end,
        0,
        config,
        &mut shape,
        &mut shape_len,
    )
    .map_err(ValidationError::Proto)?;

    // 4. Validate Tensor Dimensions and Element Size
    if shape_len > config.max_dimensions {
        return Err(ValidationError::Proto(ProtoError::ShapeDimensionLimit));
    }

    if shape_len > 0 {
        let mut total_elements = 1u64;
        for &dim in &shape[0..shape_len] {
            total_elements = total_elements
                .checked_mul(dim as u64)
                .ok_or(ValidationError::Proto(ProtoError::TensorSizeLimit))?;
        }
        if total_elements > config.max_tensor_elements {
            return Err(ValidationError::Proto(ProtoError::TensorSizeLimit));
        }
    }

    Ok((shape, shape_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use custos_grpc_basic::calculate_checksum;
    use zerocopy::byteorder::network_endian::{U16, U32};
    use zerocopy::AsBytes;

    fn build_proto_packet(proto_payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 68 + proto_payload.len()];
        let eth = custos_grpc_basic::EtherHdr {
            dst_mac: [0u8; 6],
            src_mac: [0u8; 6],
            ether_type: U16::new(0x0800),
        };
        buf[0..14].copy_from_slice(eth.as_bytes());

        let mut ip = custos_grpc_basic::IpHdr {
            version_ihl: 0x45,
            tos: 0,
            total_len: U16::new((54 + proto_payload.len()) as u16),
            id: U16::new(1),
            flags_fragment: U16::new(0),
            ttl: 64,
            proto: 6,
            hdr_checksum: U16::new(0),
            src_ip: [192, 168, 1, 1],
            dst_ip: [192, 168, 1, 2],
        };
        let csum = calculate_checksum(&ip.as_bytes());
        ip.hdr_checksum = U16::new(csum);
        buf[14..34].copy_from_slice(ip.as_bytes());

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

        let http2_len = (proto_payload.len() + 5) as u32;
        let http2 = custos_grpc_basic::Http2Hdr {
            length: [
                ((http2_len >> 16) & 0xff) as u8,
                ((http2_len >> 8) & 0xff) as u8,
                (http2_len & 0xff) as u8,
            ],
            frame_type: 0x0,
            flags: 0,
            stream_id: U32::new(1),
        };
        buf[54..63].copy_from_slice(http2.as_bytes());

        let grpc = custos_grpc_basic::GrpcHdr {
            compression_flag: 0,
            message_len: U32::new(proto_payload.len() as u32),
        };
        buf[63..68].copy_from_slice(grpc.as_bytes());
        buf[68..].copy_from_slice(proto_payload);

        buf
    }

    #[test]
    fn test_valid_packed_shape() {
        let proto = vec![0x0a, 5, 1, 3, 0xe0, 0x01, 0xe0, 0x01];
        let buf = build_proto_packet(&proto);
        let config = ValidationConfig::default();
        let (shape, len) = validate_grpc_protobuf_packet(&buf, &config).unwrap();

        assert_eq!(len, 4);
        assert_eq!(&shape[0..4], &[1, 3, 224, 224]);
    }

    #[test]
    fn test_valid_unpacked_shape() {
        let proto = vec![0x08, 1, 0x08, 3, 0x08, 10];
        let buf = build_proto_packet(&proto);
        let config = ValidationConfig::default();
        let (shape, len) = validate_grpc_protobuf_packet(&buf, &config).unwrap();

        assert_eq!(len, 3);
        assert_eq!(&shape[0..3], &[1, 3, 10]);
    }

    #[test]
    fn test_varint_overflow() {
        let proto = vec![0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        let buf = build_proto_packet(&proto);
        let config = ValidationConfig::default();
        let err = validate_grpc_protobuf_packet(&buf, &config).unwrap_err();
        assert_eq!(err, ValidationError::Proto(ProtoError::InvalidVarint));
    }

    #[test]
    fn test_varint_bytes_limit() {
        let proto = vec![0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01];
        let buf = build_proto_packet(&proto);
        let mut config = ValidationConfig::default();
        config.max_varint_bytes = 4;
        let err = validate_grpc_protobuf_packet(&buf, &config).unwrap_err();
        assert_eq!(err, ValidationError::Proto(ProtoError::InvalidVarintBytes));
    }

    #[test]
    fn test_shape_dimension_limit() {
        let proto = vec![0x0a, 6, 1, 2, 3, 4, 5, 6];
        let buf = build_proto_packet(&proto);
        let mut config = ValidationConfig::default();
        config.max_dimensions = 4;
        let err = validate_grpc_protobuf_packet(&buf, &config).unwrap_err();
        assert_eq!(err, ValidationError::Proto(ProtoError::ShapeDimensionLimit));
    }

    #[test]
    fn test_shape_value_invalid() {
        let proto = vec![0x0a, 2, 1, 0];
        let buf = build_proto_packet(&proto);
        let config = ValidationConfig::default();
        let err = validate_grpc_protobuf_packet(&buf, &config).unwrap_err();
        assert_eq!(err, ValidationError::Proto(ProtoError::ShapeValueInvalid));
    }

    #[test]
    fn test_tensor_size_limit() {
        let proto = vec![0x0a, 4, 100, 100, 100, 10];
        let buf = build_proto_packet(&proto);
        let mut config = ValidationConfig::default();
        config.max_tensor_elements = 500000;
        let err = validate_grpc_protobuf_packet(&buf, &config).unwrap_err();
        assert_eq!(err, ValidationError::Proto(ProtoError::TensorSizeLimit));
    }

    #[test]
    fn test_tensor_size_overflow() {
        let proto = vec![0x0a, 17, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 100];
        let buf = build_proto_packet(&proto);
        let config = ValidationConfig::default();
        let err = validate_grpc_protobuf_packet(&buf, &config).unwrap_err();
        assert_eq!(err, ValidationError::Proto(ProtoError::TensorSizeLimit));
    }

    #[test]
    fn test_recursion_limit() {
        let proto = vec![
            0x12, 12,
            0x12, 10,
            0x12, 8,
            0x12, 6,
            0x0a, 4, 1, 2, 3, 4
        ];
        let buf = build_proto_packet(&proto);
        let mut config = ValidationConfig::default();
        config.max_recursion_depth = 2;
        let err = validate_grpc_protobuf_packet(&buf, &config).unwrap_err();
        assert_eq!(err, ValidationError::Proto(ProtoError::RecursionLimit));
    }
}
