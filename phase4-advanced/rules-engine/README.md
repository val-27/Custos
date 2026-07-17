# Custos Phase 4 Rules Engine

A high-performance, dynamic policy rules engine designed for network security and AI model protection. It supports TOML and JSON policies to restrict ports, block IPs, validate Protobuf fields, and enforce dynamic tensor shape limits zero-copy.

## Features

- **TOML & JSON Policies**: Standardized structure with versioning support.
- **Hot-Reloading**: Built-in background file watcher and control channel listeners that swap policy instances atomically via a lock-free-style read path without blocking the packet loop or dropping packets.
- **Zero-Copy & Zero-Allocation**: Zero heap allocations in the hot path. Walks the packet payload zero-copy using stack-allocated buffers.
- **Dynamic Tensor Shape Constraints**: Min/max dimensions (rank), max tensor elements, exact shape sets, and bounds on specific dimension indices.
- **Protobuf Field Allow-lists**: Enforces strict allow-lists of field numbers at the message boundary to block unauthorized metadata.

---

## Policy Syntax Examples

### TOML Policy (`examples/ai_security_policy.toml`)

```toml
# AI Inference Security Gateway Policy Configuration
version = "1.0.0"
description = "Enforces limits on input tensor dimensions to prevent DoS and limits allowed gRPC fields."

# Only allow traffic to Triton/vLLM gRPC ports
allowed_ports = [50051, 8001]

# Block malicious IPs
blocked_ips = ["192.168.10.25", "10.0.99.1"]

[protobuf_rules]
max_varint_bytes = 9
max_recursion_depth = 4

# Allow only standard Triton Inference Request field numbers
# 1: model_name, 2: model_version, 3: inputs, 4: outputs
field_allow_list = [1, 2, 3, 4]

# Shape constraints for input tensors (field number 3)
[[protobuf_rules.shape_rules]]
field_number = 3
min_dimensions = 2
max_dimensions = 4
max_tensor_elements = 1048576 # Max 1M elements (e.g. 1x3x512x512 image)

# Restrict Batch Size (index 0) to [1, 8] and Channels (index 1) to exactly 3
[[protobuf_rules.shape_rules.dimension_bounds]]
index = 0
min = 1
max = 8

[[protobuf_rules.shape_rules.dimension_bounds]]
index = 1
min = 3
max = 3
```

### JSON Policy (`examples/ai_security_policy.json`)

```json
{
  "version": "1.0.0",
  "description": "JSON representation of the AI Inference Security Gateway Policy",
  "allowed_ports": [50051, 8001],
  "blocked_ips": ["192.168.10.25", "10.0.99.1"],
  "protobuf_rules": {
    "max_varint_bytes": 9,
    "max_recursion_depth": 4,
    "field_allow_list": [1, 2, 3, 4],
    "shape_rules": [
      {
        "field_number": 3,
        "min_dimensions": 2,
        "max_dimensions": 4,
        "max_tensor_elements": 1048576,
        "dimension_bounds": [
          {
            "index": 0,
            "min": 1,
            "max": 8
          },
          {
            "index": 1,
            "min": 3,
            "max": 3
          }
        ]
      }
    ]
  }
}
```

---

## Architectural Design

### Double-Buffering & Atomic Swapping

The `PolicyManager` stores the active policy in `arc_swap::ArcSwap<DynamicPolicy>` behind a shared `std::sync::Arc`:

- **Hot Path**: The packet processing thread uses `ArcSwap::load_full()` to clone the active `Arc<DynamicPolicy>` without taking a lock.
- **Reload Path**: The file watcher or control channel stores a new `Arc<DynamicPolicy>` atomically. The old policy remains allocated for threads actively reading it, and is cleanly deallocated as soon as their references go out of scope.

---

## Building and Testing (Docker Container)

Since the `custos-grpc-basic` and `custos-protobuf` dependencies compile on Linux (because of Linux AF_XDP `xsk-rs` / `libbpf-sys`), build and run the test suite using the provided Docker environment.

### Compile Crate
```bash
docker exec -e CARGO_TARGET_DIR=/tmp/target custos-echo cargo check --manifest-path phase4-advanced/rules-engine/Cargo.toml
```

### Run Tests
```bash
docker exec -e CARGO_TARGET_DIR=/tmp/target custos-echo cargo test --manifest-path phase4-advanced/rules-engine/Cargo.toml
```

### Run Hot-Reload Demo
```bash
docker exec -e CARGO_TARGET_DIR=/tmp/target custos-echo cargo run --example demo --manifest-path phase4-advanced/rules-engine/Cargo.toml
```
