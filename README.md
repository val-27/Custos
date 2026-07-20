# Project Custos

Project Custos is a high-performance, user-space network security appliance built in Rust using Linux AF_XDP (`socket(AF_XDP)`) sockets. It is designed to inspect and validate gRPC and Protobuf payloads in the fast path with zero heap allocations and ultra-low latency.

## Directory Structure

- [common/](common/) - Shared utility libraries, thread pinning, and Prometheus HTTP metrics exporter.
- [phase1-echo/](phase1-echo/) - Phase 1: Single-core AF_XDP loop.
- [phase2-grpc-basic/](phase2-grpc-basic/) - Phase 2: Basic HTTP/2 & gRPC validation.
- [phase3-protobuf/](phase3-protobuf/) - Phase 3: Protobuf wire-format parser & shape validation rules.
- [phase4-advanced/](phase4-advanced/) - Phase 4: Multi-queue sharding daemon, Kubernetes integration, rules engine, and TX optimizations.
- [docs/prometheus-grafana.md](docs/prometheus-grafana.md) - Prometheus metrics exposition and Grafana setup guide.
- [tests/](tests/) - Integration, validation, and performance test suites.
- [AGENTS.md](AGENTS.md) - Guidelines and coding conventions for coding agents.

## Build and Run

To compile the workspace:
```bash
cargo build --release
```

To run Phase 4 multi-queue sharding daemon with Prometheus metrics enabled (`http://localhost:9090/metrics`):
```bash
./target/release/custos-multi-queue-sharding --interface veth0 --queues 2 --metrics --metrics-port 9090
```

To run the full stack (Custos + Prometheus + Grafana):
```bash
docker-compose up -d
```
Access Prometheus at `http://localhost:9091` and Grafana at `http://localhost:3000` (login: `admin` / `admin`).
