//! Phase 2 Library: zero-copy parser and PRNG implementation.

use zerocopy::byteorder::network_endian::{U16, U32};
use zerocopy::{AsBytes, FromBytes, FromZeroes, Unaligned};

/// Ethernet Header (14 bytes)
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct EtherHdr {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: U16,
}

/// IPv4 Header (20 bytes minimum)
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct IpHdr {
    pub version_ihl: u8,
    pub tos: u8,
    pub total_len: U16,
    pub id: U16,
    pub flags_fragment: U16,
    pub ttl: u8,
    pub proto: u8,
    pub hdr_checksum: U16,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
}

/// TCP Header (20 bytes minimum)
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct TcpHdr {
    pub src_port: U16,
    pub dst_port: U16,
    pub seq_num: U32,
    pub ack_num: U32,
    pub data_offset_reserved_flags: U16,
    pub window_size: U16,
    pub checksum: U16,
    pub urgent_pointer: U16,
}

/// HTTP/2 Frame Header (9 bytes)
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct Http2Hdr {
    pub length: [u8; 3], // 24-bit big-endian payload length
    pub frame_type: u8,  // DATA is 0x0
    pub flags: u8,
    pub stream_id: U32, // 31-bit stream ID
}

/// gRPC Frame Header (5 bytes)
#[derive(FromZeroes, FromBytes, AsBytes, Unaligned, Clone, Copy, Debug)]
#[repr(C, packed)]
pub struct GrpcHdr {
    pub compression_flag: u8, // 0 or 1
    pub message_len: U32,     // 4-byte big-endian message length
}

/// Specific validation errors for filtering and statistics reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    BufferTooSmall,
    NonIPv4,
    BadIpHdrLen,
    NonTCP,
    BadIpChecksum,
    BadTcpHdrLen,
    WrongPort,
    BadHttp2Hdr,
    NonHttp2Data,
    BadGrpcHdr,
    PayloadOverflow,
}

/// Result of a successful zero-copy parse operation.
#[derive(Debug)]
pub struct ParsedGrpc<'a> {
    pub eth: &'a EtherHdr,
    pub ip: &'a IpHdr,
    pub tcp: &'a TcpHdr,
    pub http2: &'a Http2Hdr,
    pub grpc: &'a GrpcHdr,
}

/// A fast, zero-allocation Xorshift pseudorandom number generator for simulated drops.
pub struct Xorshift {
    state: u32,
}

impl Xorshift {
    pub fn new(seed: u32) -> Self {
        Self {
            state: if seed == 0 { 1 } else { seed },
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.state = x;
        x
    }

    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> u32 {
        self.next_u32()
    }

    /// Returns a float between 0.0 and 1.0.
    pub fn next_f32(&mut self) -> f32 {
        (self.next_u32() & 0xffffff) as f32 / 16777216.0
    }
}

/// Calculates the internet checksum over a slice of bytes.
/// Returns 0 if the checksum is correct when including the checksum field in the sum.
pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    for i in (0..data.len()).step_by(2) {
        if i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            sum += word as u32;
        } else {
            // Odd byte
            sum += (data[i] as u32) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Parses and validates a gRPC-over-HTTP/2-over-TCP packet in-place.
pub fn parse_grpc_packet(buf: &[u8], target_port: u16) -> Result<ParsedGrpc<'_>, ParseError> {
    // 1. Ethernet Header Parsing (14 bytes)
    if buf.len() < 14 {
        return Err(ParseError::BufferTooSmall);
    }
    let eth = EtherHdr::ref_from(&buf[0..14]).ok_or(ParseError::BufferTooSmall)?;
    if eth.ether_type.get() != 0x0800 {
        return Err(ParseError::NonIPv4);
    }

    // 2. IPv4 Header Parsing (Minimum 20 bytes)
    let ip_offset = 14;
    if buf.len() < ip_offset + 20 {
        return Err(ParseError::BufferTooSmall);
    }
    let ip = IpHdr::ref_from(&buf[ip_offset..ip_offset + 20]).ok_or(ParseError::BufferTooSmall)?;

    let ihl = (ip.version_ihl & 0x0f) as usize;
    if ihl < 5 {
        return Err(ParseError::BadIpHdrLen);
    }
    let ip_hdr_len = ihl * 4;
    if buf.len() < ip_offset + ip_hdr_len {
        return Err(ParseError::BufferTooSmall);
    }

    // Check IPv4 protocol: TCP is 6
    if ip.proto != 6 {
        return Err(ParseError::NonTCP);
    }

    // Validate cheap IPv4 Header Checksum
    let ip_hdr_bytes = &buf[ip_offset..ip_offset + ip_hdr_len];
    if calculate_checksum(ip_hdr_bytes) != 0 {
        return Err(ParseError::BadIpChecksum);
    }

    // 3. TCP Header Parsing (Minimum 20 bytes)
    let tcp_offset = ip_offset + ip_hdr_len;
    if buf.len() < tcp_offset + 20 {
        return Err(ParseError::BufferTooSmall);
    }
    let tcp =
        TcpHdr::ref_from(&buf[tcp_offset..tcp_offset + 20]).ok_or(ParseError::BufferTooSmall)?;

    // Validate port match
    if tcp.dst_port.get() != target_port {
        return Err(ParseError::WrongPort);
    }

    let data_offset = (tcp.data_offset_reserved_flags.get() >> 12) as usize;
    if data_offset < 5 {
        return Err(ParseError::BadTcpHdrLen);
    }
    let tcp_hdr_len = data_offset * 4;
    let payload_offset = tcp_offset + tcp_hdr_len;

    // 4. HTTP/2 Header Parsing (9 bytes)
    if buf.len() < payload_offset + 9 {
        return Err(ParseError::BufferTooSmall);
    }
    let http2 = Http2Hdr::ref_from(&buf[payload_offset..payload_offset + 9])
        .ok_or(ParseError::BadHttp2Hdr)?;

    // Check frame type (DATA frame is 0x0)
    if http2.frame_type != 0x0 {
        return Err(ParseError::NonHttp2Data);
    }

    // Parse 24-bit HTTP/2 payload length
    let http2_payload_len = ((http2.length[0] as usize) << 16)
        | ((http2.length[1] as usize) << 8)
        | (http2.length[2] as usize);

    // Bounds check HTTP/2 payload
    if buf.len() < payload_offset + 9 + http2_payload_len {
        return Err(ParseError::PayloadOverflow);
    }

    // 5. gRPC Header Parsing (5 bytes, inside HTTP/2 DATA payload)
    let grpc_offset = payload_offset + 9;
    if http2_payload_len < 5 {
        return Err(ParseError::BadGrpcHdr);
    }
    let grpc =
        GrpcHdr::ref_from(&buf[grpc_offset..grpc_offset + 5]).ok_or(ParseError::BadGrpcHdr)?;

    // Check bounds: gRPC message length must fit inside HTTP/2 DATA payload
    let grpc_message_len = grpc.message_len.get() as usize;
    if http2_payload_len < 5 + grpc_message_len {
        return Err(ParseError::PayloadOverflow);
    }

    Ok(ParsedGrpc {
        eth,
        ip,
        tcp,
        http2,
        grpc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_valid_packet() -> (Vec<u8>, u16) {
        let mut buf = vec![0u8; 100];

        let eth = EtherHdr {
            dst_mac: [0u8; 6],
            src_mac: [0u8; 6],
            ether_type: U16::new(0x0800),
        };
        buf[0..14].copy_from_slice(eth.as_bytes());

        let mut ip = IpHdr {
            version_ihl: 0x45,
            tos: 0,
            total_len: U16::new(86),
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

        let tcp = TcpHdr {
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

        let http2 = Http2Hdr {
            length: [0, 0, 15],
            frame_type: 0x0,
            flags: 0,
            stream_id: U32::new(1),
        };
        buf[54..63].copy_from_slice(http2.as_bytes());

        let grpc = GrpcHdr {
            compression_flag: 0,
            message_len: U32::new(10),
        };
        buf[63..68].copy_from_slice(grpc.as_bytes());

        buf[68..78].copy_from_slice(b"MESSAGE123");

        (buf, 50051)
    }

    #[test]
    fn test_parse_valid_grpc() {
        let (buf, port) = build_valid_packet();
        let parsed = parse_grpc_packet(&buf, port).unwrap();
        assert_eq!(parsed.eth.ether_type.get(), 0x0800);
        assert_eq!(parsed.ip.proto, 6);
        assert_eq!(parsed.tcp.dst_port.get(), 50051);
        assert_eq!(parsed.http2.frame_type, 0);
        assert_eq!(parsed.grpc.message_len.get(), 10);
    }

    #[test]
    fn test_parse_non_ipv4() {
        let (mut buf, _) = build_valid_packet();
        buf[12..14].copy_from_slice(&[0x08, 0x06]);
        let err = parse_grpc_packet(&buf, 50051).unwrap_err();
        assert_eq!(err, ParseError::NonIPv4);
    }

    #[test]
    fn test_parse_non_tcp() {
        let (mut buf, _) = build_valid_packet();
        buf[23] = 17;
        let mut ip_hdr = [0u8; 20];
        ip_hdr.copy_from_slice(&buf[14..34]);
        ip_hdr[9] = 17;
        ip_hdr[10] = 0;
        ip_hdr[11] = 0;
        let csum = calculate_checksum(&ip_hdr);
        ip_hdr[10..12].copy_from_slice(&csum.to_be_bytes());
        buf[14..34].copy_from_slice(&ip_hdr);

        let err = parse_grpc_packet(&buf, 50051).unwrap_err();
        assert_eq!(err, ParseError::NonTCP);
    }

    #[test]
    fn test_parse_bad_ip_checksum() {
        let (mut buf, _) = build_valid_packet();
        buf[24] ^= 0xff;
        let err = parse_grpc_packet(&buf, 50051).unwrap_err();
        assert_eq!(err, ParseError::BadIpChecksum);
    }

    #[test]
    fn test_parse_wrong_port() {
        let (buf, _) = build_valid_packet();
        let err = parse_grpc_packet(&buf, 8080).unwrap_err();
        assert_eq!(err, ParseError::WrongPort);
    }

    #[test]
    fn test_parse_non_http2_data() {
        let (mut buf, _) = build_valid_packet();
        buf[57] = 0x1;
        let err = parse_grpc_packet(&buf, 50051).unwrap_err();
        assert_eq!(err, ParseError::NonHttp2Data);
    }

    #[test]
    fn test_parse_payload_overflow() {
        let (mut buf, _) = build_valid_packet();
        buf[64..68].copy_from_slice(&100u32.to_be_bytes());
        let err = parse_grpc_packet(&buf, 50051).unwrap_err();
        assert_eq!(err, ParseError::PayloadOverflow);
    }
}
