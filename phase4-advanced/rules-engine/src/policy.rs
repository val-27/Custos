use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

/// Serializable representation of the configuration policy.
/// Used for parsing TOML or JSON config files.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Policy {
    /// Version of the policy (e.g. "1.0.0"). Used for versioning checks.
    pub version: String,
    /// Optional human-readable description.
    pub description: Option<String>,
    /// Optional set of allowed destination ports. If None, all ports are allowed.
    pub allowed_ports: Option<HashSet<u16>>,
    /// Optional set of blocked IPv4 addresses.
    pub blocked_ips: Option<HashSet<Ipv4Addr>>,
    /// Optional protobuf/shape validation rules.
    pub protobuf_rules: Option<ProtobufRules>,
}

/// Serializable representation of Protobuf validation rules.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtobufRules {
    /// Maximum bytes allowed for a single varint (limits memory usage, default 9).
    pub max_varint_bytes: Option<usize>,
    /// Maximum recursion depth for nested messages (default 3).
    pub max_recursion_depth: Option<usize>,
    /// Optional allow-list of field numbers at the top level.
    pub field_allow_list: Option<HashSet<u32>>,
    /// Optional list of shape constraints on specific fields.
    pub shape_rules: Option<Vec<ShapeRule>>,
}

/// Serializable representation of shape rules on a specific field number.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ShapeRule {
    /// The Protobuf field number that contains the tensor shape.
    pub field_number: u32,
    /// Minimum allowed number of dimensions (rank).
    pub min_dimensions: Option<usize>,
    /// Maximum allowed number of dimensions (rank).
    pub max_dimensions: Option<usize>,
    /// Maximum allowed total elements in tensor (product of shape dimensions).
    pub max_tensor_elements: Option<u64>,
    /// List of exact shapes allowed. If specified, the shape must match one of these exactly.
    pub exact_shapes: Option<Vec<Vec<i64>>>,
    /// Specific bounds for individual dimension indices.
    pub dimension_bounds: Option<Vec<DimensionBound>>,
}

/// Specific bounds constraint on a dimension index.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DimensionBound {
    /// The index of the dimension (0-indexed).
    pub index: usize,
    /// Minimum value allowed for this dimension.
    pub min: Option<i64>,
    /// Maximum value allowed for this dimension.
    pub max: Option<i64>,
}

/// Preprocessed, read-only structure optimized for fast path matching.
#[derive(Debug, Clone)]
pub struct DynamicPolicy {
    pub version: String,
    pub allowed_ports: Option<HashSet<u16>>,
    pub blocked_ips: HashSet<Ipv4Addr>,
    pub max_varint_bytes: usize,
    pub max_recursion_depth: usize,
    pub field_allow_list: Option<HashSet<u32>>,
    pub shape_rules: HashMap<u32, ShapeRule>,
}

/// Validates a `Policy` configuration structure for logical correctness.
pub fn validate_policy(policy: &Policy) -> Result<(), String> {
    if policy.version.trim().is_empty() {
        return Err("Policy version cannot be empty".to_string());
    }

    if let Some(ref proto) = policy.protobuf_rules {
        if let Some(max_varint) = proto.max_varint_bytes {
            if max_varint == 0 || max_varint > 10 {
                return Err("max_varint_bytes must be between 1 and 10".to_string());
            }
        }
        if let Some(max_depth) = proto.max_recursion_depth {
            if max_depth > 100 {
                return Err("max_recursion_depth cannot exceed 100".to_string());
            }
        }
        if let Some(ref shape_rules) = proto.shape_rules {
            for rule in shape_rules {
                if let (Some(min), Some(max)) = (rule.min_dimensions, rule.max_dimensions) {
                    if min > max {
                        return Err(format!(
                            "Shape rule for field {}: min_dimensions ({}) cannot exceed max_dimensions ({})",
                            rule.field_number, min, max
                        ));
                    }
                }
                if let Some(ref bounds) = rule.dimension_bounds {
                    for bound in bounds {
                        if bound.index >= 16 {
                            return Err(format!(
                                "Dimension bound index {} for field {} exceeds maximum supported dimensions (16)",
                                bound.index, rule.field_number
                            ));
                        }
                        if let (Some(min), Some(max)) = (bound.min, bound.max) {
                            if min > max {
                                return Err(format!(
                                    "Dimension bound for field {} index {}: min ({}) cannot exceed max ({})",
                                    rule.field_number, bound.index, min, max
                                ));
                            }
                        }
                    }
                }
                if let Some(ref exacts) = rule.exact_shapes {
                    for shape in exacts {
                        if shape.len() > 16 {
                            return Err(format!(
                                "Exact shape {:?} for field {} exceeds maximum supported dimensions (16)",
                                shape, rule.field_number
                            ));
                        }
                        if shape.iter().any(|&d| d <= 0) {
                            return Err(format!(
                                "Exact shape {:?} for field {} contains non-positive dimensions",
                                shape, rule.field_number
                            ));
                        }
                    }
                }
            }
        }
    }

    Ok(())
}

impl Policy {
    /// Parses a policy from TOML format.
    pub fn from_toml(content: &str) -> Result<Self, String> {
        toml::from_str(content).map_err(|e| format!("TOML parse error: {}", e))
    }

    /// Parses a policy from JSON format.
    pub fn from_json(content: &str) -> Result<Self, String> {
        serde_json::from_str(content).map_err(|e| format!("JSON parse error: {}", e))
    }
}

impl TryFrom<Policy> for DynamicPolicy {
    type Error = String;

    fn try_from(p: Policy) -> Result<Self, Self::Error> {
        validate_policy(&p)?;

        let mut shape_rules_map = HashMap::new();
        let mut max_varint_bytes = 9;
        let mut max_recursion_depth = 3;
        let mut field_allow_list = None;

        if let Some(proto) = p.protobuf_rules {
            if let Some(mv) = proto.max_varint_bytes {
                max_varint_bytes = mv;
            }
            if let Some(md) = proto.max_recursion_depth {
                max_recursion_depth = md;
            }
            field_allow_list = proto.field_allow_list;
            if let Some(rules) = proto.shape_rules {
                for rule in rules {
                    shape_rules_map.insert(rule.field_number, rule);
                }
            }
        }

        Ok(Self {
            version: p.version,
            allowed_ports: p.allowed_ports,
            blocked_ips: p.blocked_ips.unwrap_or_default(),
            max_varint_bytes,
            max_recursion_depth,
            field_allow_list,
            shape_rules: shape_rules_map,
        })
    }
}
