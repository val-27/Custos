# Project Custos

Project Custos is a high-performance, user-space network security appliance built in Rust using Linux AF_XDP (`socket(AF_XDP)`) sockets. It is designed to inspect and validate gRPC and Protobuf payloads in the fast path with zero heap allocations and ultra-low latency.

## Directory Structure

- [common/](file:///Users/jpvalent/.treehouse/Custos-1475d5/1/Custos/common) - Shared utility libraries, including core affinity settings and ring buffers.
- [echo/](file:///Users/jpvalent/.treehouse/Custos-1475d5/1/Custos/echo) - Phase 1: A single-core loop that receives and echoes/forwards ethernet packets over AF_XDP.
- [grpc-basic/](file:///Users/jpvalent/.treehouse/Custos-1475d5/1/Custos/grpc-basic) - Phase 2: Inspects TCP packets to validate HTTP/2 framing, parses gRPC metadata, and performs header stripping.
- [protobuf/](file:///Users/jpvalent/.treehouse/Custos-1475d5/1/Custos/protobuf) - Phase 3: Deep packet inspection of Protobuf messages via zero-copy tag walking, enforcing security boundaries.
- [tests/](file:///Users/jpvalent/.treehouse/Custos-1475d5/1/Custos/tests) - Integration, validation, and performance test suites.
- [agents.md](file:///Users/jpvalent/.treehouse/Custos-1475d5/1/Custos/agents.md) - Guidelines and coding conventions for coding agents.

## Build and Run

To compile the entire workspace:
```bash
cargo build --release
```

To run a specific sub-crate (e.g., the Phase 1 Echo daemon):
```bash
cd echo
cargo run --release -- --interface eth0 --core 1
```
