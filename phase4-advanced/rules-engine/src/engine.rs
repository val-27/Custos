use crate::policy::{DynamicPolicy, ShapeRule};
use custos_grpc_basic::parse_grpc_packet;
use custos_protobuf::{read_varint, skip_field, ProtoError};
use std::net::Ipv4Addr;

/// The outcome of evaluating a packet against the active policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchResult {
    /// The packet matches all policy constraints and is allowed.
    Allow,
    /// The packet violates a constraint and must be blocked.
    Block(BlockReason),
}

/// The specific reason why a packet was blocked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockReason {
    /// The packet is structurally invalid or truncated.
    InvalidPacket,
    /// The source or destination IP is in the blocked IP list.
    BlockedIP(Ipv4Addr),
    /// The destination port is not in the allowed ports list.
    BlockedPort(u16),
    /// A Protobuf field number was encountered that is not in the allow-list.
    DisallowedField(u32),
    /// The Protobuf wire format parsing failed.
    InvalidProto(ProtoError),
    /// The number of shape dimensions (rank) exceeded the maximum allowed limit.
    ShapeDimensionLimitExceeded {
        field: u32,
        got: usize,
        limit: usize,
    },
    /// The number of shape dimensions (rank) was below the minimum required.
    ShapeDimensionTooSmall {
        field: u32,
        got: usize,
        limit: usize,
    },
    /// The total number of elements in the tensor exceeded the limit.
    TensorSizeLimitExceeded { field: u32, got: u64, limit: u64 },
    /// The parsed shape did not match any of the allowed exact shapes.
    ExactShapeMismatch { field: u32 },
    /// A specific dimension index value violated the minimum or maximum bounds.
    DimensionBoundViolation {
        field: u32,
        index: usize,
        val: i64,
        min: Option<i64>,
        max: Option<i64>,
    },
}

/// Errors returned during the zero-copy Protobuf wire-format walker pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkError {
    Proto(ProtoError),
    DisallowedField(u32),
    ShapeRuleViolation {
        field_number: u32,
        reason: RuleViolationReason,
    },
}

/// Reasons why a shape constraint check failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleViolationReason {
    DimensionTooSmall {
        got: usize,
        limit: usize,
    },
    DimensionTooLarge {
        got: usize,
        limit: usize,
    },
    TensorSizeExceeded {
        got: u64,
        limit: u64,
    },
    ExactShapeMismatch,
    DimensionBoundViolation {
        index: usize,
        val: i64,
        min: Option<i64>,
        max: Option<i64>,
    },
}

/// Validates a parsed shape array against a specific `ShapeRule`.
fn validate_shape(shape: &[i64], rule: &ShapeRule) -> Result<(), WalkError> {
    let shape_len = shape.len();

    // 1. Validate rank lower bound
    if let Some(min_dims) = rule.min_dimensions {
        if shape_len < min_dims {
            return Err(WalkError::ShapeRuleViolation {
                field_number: rule.field_number,
                reason: RuleViolationReason::DimensionTooSmall {
                    got: shape_len,
                    limit: min_dims,
                },
            });
        }
    }

    // 2. Validate rank upper bound
    if let Some(max_dims) = rule.max_dimensions {
        if shape_len > max_dims {
            return Err(WalkError::ShapeRuleViolation {
                field_number: rule.field_number,
                reason: RuleViolationReason::DimensionTooLarge {
                    got: shape_len,
                    limit: max_dims,
                },
            });
        }
    }

    // 3. Validate total tensor element size (product of dimensions)
    if let Some(max_elements) = rule.max_tensor_elements {
        if shape_len > 0 {
            let mut product = 1u64;
            for &dim in shape {
                product = product.checked_mul(dim as u64).ok_or_else(|| {
                    WalkError::ShapeRuleViolation {
                        field_number: rule.field_number,
                        reason: RuleViolationReason::TensorSizeExceeded {
                            got: u64::MAX,
                            limit: max_elements,
                        },
                    }
                })?;
            }
            if product > max_elements {
                return Err(WalkError::ShapeRuleViolation {
                    field_number: rule.field_number,
                    reason: RuleViolationReason::TensorSizeExceeded {
                        got: product,
                        limit: max_elements,
                    },
                });
            }
        }
    }

    // 4. Validate exact shapes list matching
    if let Some(ref exact_shapes) = rule.exact_shapes {
        let matched = exact_shapes.iter().any(|exact| exact == shape);
        if !matched {
            return Err(WalkError::ShapeRuleViolation {
                field_number: rule.field_number,
                reason: RuleViolationReason::ExactShapeMismatch,
            });
        }
    }

    // 5. Validate specific dimension value ranges
    if let Some(ref bounds) = rule.dimension_bounds {
        for bound in bounds {
            if bound.index < shape_len {
                let val = shape[bound.index];
                if let Some(min) = bound.min {
                    if val < min {
                        return Err(WalkError::ShapeRuleViolation {
                            field_number: rule.field_number,
                            reason: RuleViolationReason::DimensionBoundViolation {
                                index: bound.index,
                                val,
                                min: bound.min,
                                max: bound.max,
                            },
                        });
                    }
                }
                if let Some(max) = bound.max {
                    if val > max {
                        return Err(WalkError::ShapeRuleViolation {
                            field_number: rule.field_number,
                            reason: RuleViolationReason::DimensionBoundViolation {
                                index: bound.index,
                                val,
                                min: bound.min,
                                max: bound.max,
                            },
                        });
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Clone, Copy)]
struct ShapeAccumulator {
    field_number: u32,
    shape: [i64; 16],
    len: usize,
    seen: bool,
}

fn append_shape_dim(acc: &mut ShapeAccumulator, dim: i64) -> Result<(), WalkError> {
    if acc.len >= acc.shape.len() {
        return Err(WalkError::Proto(ProtoError::ShapeDimensionLimit));
    }
    if dim <= 0 {
        return Err(WalkError::Proto(ProtoError::ShapeValueInvalid));
    }
    acc.shape[acc.len] = dim;
    acc.len += 1;
    Ok(())
}

fn shape_accumulator<'a>(
    accumulators: &'a mut [ShapeAccumulator; 16],
    field_number: u32,
) -> Result<&'a mut ShapeAccumulator, WalkError> {
    if let Some(index) = accumulators
        .iter()
        .position(|acc| acc.seen && acc.field_number == field_number)
    {
        return Ok(&mut accumulators[index]);
    }

    if let Some(index) = accumulators.iter().position(|acc| !acc.seen) {
        let acc = &mut accumulators[index];
        acc.field_number = field_number;
        acc.len = 0;
        acc.seen = true;
        return Ok(acc);
    }

    Err(WalkError::Proto(ProtoError::ShapeDimensionLimit))
}

/// Recursively walks a Protobuf message, enforcing allow-lists and evaluating shape constraints.
pub fn walk_message_with_policy(
    buf: &[u8],
    offset: &mut usize,
    end_offset: usize,
    depth: usize,
    policy: &DynamicPolicy,
) -> Result<(), WalkError> {
    if depth > policy.max_recursion_depth {
        return Err(WalkError::Proto(ProtoError::RecursionLimit));
    }
    if end_offset > buf.len() {
        return Err(WalkError::Proto(ProtoError::BufferUnderflow));
    }

    let mut shape_accumulators = [ShapeAccumulator {
        field_number: 0,
        shape: [0; 16],
        len: 0,
        seen: false,
    }; 16];

    while *offset < end_offset {
        let tag = read_varint(&buf[..end_offset], offset, policy.max_varint_bytes)
            .map_err(WalkError::Proto)?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;

        // Enforce field allow-lists at the top level (depth == 0) to avoid false positives
        // on arbitrary byte patterns inside speculative string/bytes fields.
        if depth == 0 {
            if let Some(ref allow_list) = policy.field_allow_list {
                if !allow_list.contains(&field_number) {
                    return Err(WalkError::DisallowedField(field_number));
                }
            }
        }

        // Evaluate shape rules if a rule exists for this field
        if policy.shape_rules.contains_key(&field_number) {
            let acc = shape_accumulator(&mut shape_accumulators, field_number)?;

            if wire_type == 2 {
                let len = read_varint(&buf[..end_offset], offset, policy.max_varint_bytes)
                    .map_err(WalkError::Proto)? as usize;
                let Some(pack_end) = (*offset).checked_add(len) else {
                    return Err(WalkError::Proto(ProtoError::BufferUnderflow));
                };
                if pack_end > end_offset {
                    return Err(WalkError::Proto(ProtoError::BufferUnderflow));
                }
                while *offset < pack_end {
                    let dim = read_varint(&buf[..pack_end], offset, policy.max_varint_bytes)
                        .map_err(WalkError::Proto)? as i64;
                    append_shape_dim(acc, dim)?;
                }
            } else if wire_type == 0 {
                let dim = read_varint(&buf[..end_offset], offset, policy.max_varint_bytes)
                    .map_err(WalkError::Proto)? as i64;
                append_shape_dim(acc, dim)?;
            } else {
                return Err(WalkError::Proto(ProtoError::InvalidWireType));
            }
        } else {
            // No shape rule matches.
            // Speculatively walk inside wire type 2 as a sub-message.
            if wire_type == 2 {
                let len = read_varint(&buf[..end_offset], offset, policy.max_varint_bytes)
                    .map_err(WalkError::Proto)? as usize;
                let Some(sub_end) = (*offset).checked_add(len) else {
                    return Err(WalkError::Proto(ProtoError::BufferUnderflow));
                };
                if sub_end > end_offset {
                    return Err(WalkError::Proto(ProtoError::BufferUnderflow));
                }
                let mut sub_offset = *offset;

                // Attempt to recursively parse.
                match walk_message_with_policy(buf, &mut sub_offset, sub_end, depth + 1, policy) {
                    Ok(()) => {
                        *offset = sub_end;
                    }
                    Err(err @ WalkError::Proto(ProtoError::RecursionLimit)) => {
                        return Err(err);
                    }
                    Err(_) => {
                        // On structural/policy parse errors inside speculative fields,
                        // roll back and skip (the field is likely a normal string or byte array).
                        *offset = sub_end;
                    }
                }
            } else {
                skip_field(
                    &buf[..end_offset],
                    offset,
                    wire_type,
                    policy.max_varint_bytes,
                )
                .map_err(WalkError::Proto)?;
            }
        }
    }

    for acc in shape_accumulators.iter().filter(|acc| acc.seen) {
        let Some(rule) = policy.shape_rules.get(&acc.field_number) else {
            return Err(WalkError::Proto(ProtoError::InvalidWireType));
        };
        validate_shape(&acc.shape[..acc.len], rule)?;
    }

    Ok(())
}

/// Evaluates a raw packet buffer against the active policy.
/// Parses Layer 2-5 headers and executes zero-copy walker checks.
pub fn match_packet(buf: &[u8], policy: &DynamicPolicy) -> MatchResult {
    // 1. Basic length and EtherType validation
    if buf.len() < 34 {
        return MatchResult::Block(BlockReason::InvalidPacket);
    }
    let ether_type = u16::from_be_bytes([buf[12], buf[13]]);
    if ether_type != 0x0800 {
        return MatchResult::Block(BlockReason::InvalidPacket);
    }

    // 2. Parse IP addresses and validate against blocked IPs list
    let src_ip = Ipv4Addr::new(buf[26], buf[27], buf[28], buf[29]);
    let dst_ip = Ipv4Addr::new(buf[30], buf[31], buf[32], buf[33]);

    if policy.blocked_ips.contains(&src_ip) {
        return MatchResult::Block(BlockReason::BlockedIP(src_ip));
    }
    if policy.blocked_ips.contains(&dst_ip) {
        return MatchResult::Block(BlockReason::BlockedIP(dst_ip));
    }

    let has_rules = policy.field_allow_list.is_some() || !policy.shape_rules.is_empty();
    let needs_tcp = policy.allowed_ports.is_some() || has_rules;
    let tcp_info = if needs_tcp {
        if buf[23] != 6 {
            return MatchResult::Block(BlockReason::InvalidPacket);
        }
        let ihl = (buf[14] & 0x0F) as usize;
        if ihl < 5 {
            return MatchResult::Block(BlockReason::InvalidPacket);
        }
        let ip_hdr_len = ihl * 4;
        let tcp_offset = 14 + ip_hdr_len;
        if buf.len() < tcp_offset + 4 {
            return MatchResult::Block(BlockReason::InvalidPacket);
        }

        let dst_port = u16::from_be_bytes([buf[tcp_offset + 2], buf[tcp_offset + 3]]);
        Some((tcp_offset, dst_port))
    } else {
        None
    };

    if let Some(ref allowed_ports) = policy.allowed_ports {
        let Some((_, dst_port)) = tcp_info else {
            return MatchResult::Block(BlockReason::InvalidPacket);
        };
        if !allowed_ports.contains(&dst_port) {
            return MatchResult::Block(BlockReason::BlockedPort(dst_port));
        }
    }

    if has_rules {
        let Some((tcp_offset, dst_port)) = tcp_info else {
            return MatchResult::Block(BlockReason::InvalidPacket);
        };
        // Parse L2-L5 using zero-copy custos-grpc-basic parser
        let parsed = match parse_grpc_packet(buf, dst_port) {
            Ok(p) => p,
            Err(_) => return MatchResult::Block(BlockReason::InvalidPacket),
        };

        // Locate the Protobuf payload offset and bounds
        let data_offset = (parsed.tcp.data_offset_reserved_flags.get() >> 12) as usize;
        let tcp_hdr_len = data_offset * 4;
        let payload_offset = tcp_offset + tcp_hdr_len;

        // Skip 9-byte HTTP/2 header and 5-byte gRPC header
        let proto_start = payload_offset + 9 + 5;
        let http2_payload_len = ((parsed.http2.length[0] as usize) << 16)
            | ((parsed.http2.length[1] as usize) << 8)
            | (parsed.http2.length[2] as usize);
        let message_len = parsed.grpc.message_len.get() as usize;
        let Some(proto_end) = proto_start.checked_add(message_len) else {
            return MatchResult::Block(BlockReason::InvalidProto(ProtoError::BufferUnderflow));
        };

        if proto_start > payload_offset + 9 + http2_payload_len
            || proto_end > payload_offset + 9 + http2_payload_len
            || proto_end > buf.len()
        {
            return MatchResult::Block(BlockReason::InvalidProto(ProtoError::BufferUnderflow));
        }

        let mut offset = proto_start;
        match walk_message_with_policy(buf, &mut offset, proto_end, 0, policy) {
            Ok(_) => {}
            Err(WalkError::Proto(e)) => {
                return MatchResult::Block(BlockReason::InvalidProto(e));
            }
            Err(WalkError::DisallowedField(f)) => {
                return MatchResult::Block(BlockReason::DisallowedField(f));
            }
            Err(WalkError::ShapeRuleViolation {
                field_number,
                reason,
            }) => {
                return MatchResult::Block(match reason {
                    RuleViolationReason::DimensionTooSmall { got, limit } => {
                        BlockReason::ShapeDimensionTooSmall {
                            field: field_number,
                            got,
                            limit,
                        }
                    }
                    RuleViolationReason::DimensionTooLarge { got, limit } => {
                        BlockReason::ShapeDimensionLimitExceeded {
                            field: field_number,
                            got,
                            limit,
                        }
                    }
                    RuleViolationReason::TensorSizeExceeded { got, limit } => {
                        BlockReason::TensorSizeLimitExceeded {
                            field: field_number,
                            got,
                            limit,
                        }
                    }
                    RuleViolationReason::ExactShapeMismatch => BlockReason::ExactShapeMismatch {
                        field: field_number,
                    },
                    RuleViolationReason::DimensionBoundViolation {
                        index,
                        val,
                        min,
                        max,
                    } => BlockReason::DimensionBoundViolation {
                        field: field_number,
                        index,
                        val,
                        min,
                        max,
                    },
                });
            }
        }
    }

    MatchResult::Allow
}
