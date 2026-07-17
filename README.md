# Project Custos

Project Custos is a high-performance, user-space network security appliance built in Rust using Linux AF_XDP (`socket(AF_XDP)`) sockets. It is designed to inspect and validate gRPC and Protobuf payloads in the fast path with zero heap allocations and ultra-low latency.

For a detailed high-level design, feature roadmap, and production guides, see [PROJECT-OVERVIEW.md](PROJECT-OVERVIEW.md).
For test coverage analysis and testing instructions, see [TESTING.md](TESTING.md).

---

## Directory Structure

*   [common/](common/) - Shared utility libraries, including core affinity and CPU thread pinning.
*   [phase1-echo/](phase1-echo/) - Phase 1: Single-core packet loop (drop, forward, or echo MAC swap) over AF_XDP.
*   [phase2-grpc-basic/](phase2-grpc-basic/) - Phase 2: In-place gRPC & HTTP/2 protocol parser with zero heap allocations.
*   [phase3-protobuf/](phase3-protobuf/) - Phase 3: Zero-copy Protobuf wire-format speculative tag walker and shape validator.
*   [phase4-advanced/](phase4-advanced/) - Phase 4: Production-scale sharding and deployment:
    *   [multi-queue-sharding/](phase4-advanced/multi-queue-sharding/) - Multi-core RSS steered poller.
    *   [k8s-integration/](phase4-advanced/k8s-integration/) - DaemonSet privilege separation with UNIX FD passing (`SCM_RIGHTS`).
    *   [rules-engine/](phase4-advanced/rules-engine/) - Dynamic TOML/JSON policy hot-reloader.
    *   [tx-optimizations/](phase4-advanced/tx-optimizations/) - Batching and CPU prefetching.
*   [tests/](tests/) - Integration, VM simulation, and traffic generation scripts.
*   [agents.md](agents.md) - Coding conventions and style rules for AI development agents.

---

## Build and Run

Project Custos uses two separate workspaces:

### 1. Root Workspace (Phases 1–3)
To compile and test the core crates:
```bash
cargo build --release
cargo test
```

### 2. Advanced Workspace (Phase 4)
To compile the production-scale tooling:
```bash
cd phase4-advanced
cargo build --release
cargo test
```

For examples on running individual daemons and setting up hardware RSS queues, please consult the [PROJECT-OVERVIEW.md](PROJECT-OVERVIEW.md) guide.

---

## Contribution & Code Standards

All code contributions must adhere to the conventions defined in [agents.md](agents.md), specifically:
*   Maintain zero heap allocations in the hot path.
*   Provide safety invariants (`// SAFETY: <reason>`) for every `unsafe` block.
*   Log via the `tracing` library using correct log levels.

