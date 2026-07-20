# Project Custos

Project Custos is a high-performance, user-space network security appliance built in Rust using Linux AF_XDP (`socket(AF_XDP)`) sockets. It is designed to inspect and validate gRPC and Protobuf payloads in the fast path with zero heap allocations and ultra-low latency.

## Directory Structure

- [common/](common/) - Shared utility libraries, including core affinity settings.
- [phase1-echo/](phase1-echo/) - Phase 1: A single-core loop that receives and drops, forwards, or echoes Ethernet packets over AF_XDP.
- [grpc-basic/](grpc-basic/) - Phase 2 scaffold for HTTP/2 and gRPC validation.
- [protobuf/](protobuf/) - Phase 3 scaffold for Protobuf tag walking and security guards.
- [tests/](tests/) - Integration, validation, and performance test suites.
- [agents.md](agents.md) - Guidelines and coding conventions for coding agents.

## Build and Run

To compile the entire workspace:
```bash
cargo build --release
```

To run a specific sub-crate (e.g., the Phase 1 Echo daemon):
```bash
cd phase1-echo
cargo run --release -- --interface eth0 --core 1
```
