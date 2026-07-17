//! # Custos Rules Engine Crate
//!
//! Provides a high-performance, dynamic policy rules engine with hot-reloading.
//! It supports TOML and JSON configurations to enforce IP blocking, destination port
//! validation, field allow-lists, and tensor shape constraints.
//!
//! ## Purpose
//! This crate is the core policy enforcement mechanism for Phase 4 of Custos.
//! It validates ingress and egress packets against a set of security rules (e.g. for AI model security)
//! before allowing them to be forwarded by the AF_XDP processing loops.
//!
//! ## Safety Invariants
//! This library uses safe Rust abstractions. The `PolicyManager` employs `std::sync::RwLock` combined
//! with `std::sync::Arc` to enable safe configuration swaps without blocking or data races.
//! Readers in the hot path clone the `Arc` pointer under a brief read lock, meaning the underlying
//! policy memory remains valid even if a reload occurs concurrently.
//!
//! ## Performance Rationale
//! 1. **Zero-Copy Parsing**: Leverages the `custos-grpc-basic` and `custos-protobuf` concepts to walk
//!    the payload zero-copy, extracting and validating fields directly from the network buffer.
//! 2. **Zero Hot-Path Allocations**: The Protobuf walker works on stack-allocated buffers (e.g. `[i64; 16]`)
//!    and checks shape dimension rules inline as fields are parsed, avoiding heap allocations completely.
//! 3. **O(1) Policy Lookups**: The policy rules are preprocessed into `HashSet` and `HashMap` structures
//!    during loading/reloading, ensuring that port, IP, and shape checks are evaluated in constant time.

pub mod engine;
pub mod manager;
pub mod policy;

pub use engine::{
    match_packet, walk_message_with_policy, BlockReason, MatchResult, RuleViolationReason,
    WalkError,
};
pub use manager::{load_policy_from_file, PolicyManager};
pub use policy::{
    validate_policy, DimensionBound, DynamicPolicy, Policy, ProtobufRules, ShapeRule,
};
