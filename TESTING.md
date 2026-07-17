# Project Custos Testing & Verification Framework

This document outlines the testing strategy, current coverage, gap analysis, and instructions for verifying the safety and performance of Project Custos.

---

## 1. Testing Strategy Overview

Project Custos employs a multi-tiered validation approach designed to enforce extreme safety, absolute correctness in parsing, and high packet rates.

```
       +---------------------------------------------+
       |   Fuzz Testing (Cargo Fuzz / libFuzzer)     |
       |  - Validates Protobuf and HTTP/2 Parser    |
       +---------------------------------------------+
                              |
       +---------------------------------------------+
       |   Performance & Line-Rate Benchmarks       |
       |  - bench_tx, Packet Hammer, TRex PCAP play  |
       +---------------------------------------------+
                              |
       +---------------------------------------------+
       |   Integration / Namespace Tests             |
       |  - AF_XDP Veth pair emulation, FD passing   |
       +---------------------------------------------+
                              |
       +---------------------------------------------+
       |   Unit & Robustness Tests                   |
       |  - Rules Engine, Checksum, Tag Walking      |
       +---------------------------------------------+
```

*   **Unit Tests**: Written in safe Rust to validate specific components like TCP checksumming, HTTP/2 frame structure, and Protobuf varint decoding.
*   **Integration Tests**: Run in simulated Linux network namespaces (using `veth` pairs) or containerized environments (using Colima VM/Docker Compose) to test actual AF_XDP socket lifecycle.
*   **Performance Benchmarks**: Dedicated binary runners (e.g. `bench_tx`) and traffic generators (e.g. Python hammer, TRex) to verify throughput and microsecond-scale latencies.

---

## 2. Current Test Coverage Summary

### A. Core Workspace Unit Tests
Located within each crate (`phase2-grpc-basic`, `phase3-protobuf`, `phase4-advanced/rules-engine`, `phase4-advanced/k8s-integration`):
*   **Protocol Parser**: Verifies Ethernet parsing, IPv4 checksum calculation, TCP port verification, HTTP/2 DATA frame parsing, and gRPC message length bounds.
*   **Protobuf Tag Walker**: Validates varint decoding limits, nested shape parsing, speculative tag rollback, and size calculation overflows.
*   **Rules Engine**: Validates IP and port validation policies, field allowlists, dimension index constraints, and TOML/JSON parsing.

### B. Integration Tests
*   `tests/basic_tests.rs`: Implements simulated network endpoints to verify:
    *   `test_af_xdp_echo_and_leak_detection`: Echo server swapping MAC addresses.
    *   `test_af_xdp_grpc_validation_and_drop_simulation`: Correctly identifies valid vs malformed gRPC/TCP packets over AF_XDP.
    *   `test_af_xdp_protobuf_shape_validation`: Validates tensor shapes over AF_XDP queues.
*   `k8s-integration`:
    *   `passes_multiple_file_descriptors_over_unix_socket`: Verifies passing AF_XDP socket and memfd file descriptors via `SCM_RIGHTS` ancillary data.

### C. Performance Benchmarks
*   `bench_tx`: Compares baseline unoptimized TX loop throughput against optimized batching (`TxBatcher`) and cacheline prefetching (`prfm` / `_mm_prefetch`).

---

## 3. Test Gap Analysis & Key Improvements

We audited the entire codebase for edge-case vulnerabilities and implemented several high-priority robustness tests to cover potential gaps.

### Gap 1: Stack Exhaustion / Deep Recursion Attacks
*   **Vulnerability**: Attackers can construct deeply nested length-delimited protobuf fields designed to exceed the thread stack space, triggering a crash (DoS).
*   **Mitigation**: Custos enforces `max_recursion_depth` on the wire walker.
*   **Status**: **RESOLVED**. We added `test_deep_recursion_attack` to rules-engine tests. It constructs a payload nested 20 levels deep and asserts that the parser blocks it safely rather than crashing the stack.

### Gap 2: Malformed Varints & Buffer Boundary Overflows
*   **Vulnerability**: Redundant leading zero bytes in varints (e.g. over 10 bytes) or unexpected end-of-buffer (EOF) while parsing can crash the parser.
*   **Mitigation**: Custos parses varints byte-by-byte with strict limit checks.
*   **Status**: **RESOLVED**. We added `test_malformed_varint_and_buffer_underflow_edge_cases` to rules-engine tests. It tests:
    1.  Varints exceeding 10 bytes (standard u64 limit).
    2.  Varints truncated in the middle of a byte sequence.
    3.  Length-delimited fields where length overflows arithmetic bounds.

### Gap 3: Lock-Free Policy Reloading under High Concurrent Load
*   **Vulnerability**: Hot-swapping the active policy using `ArcSwap` while packet polling loops are loading pointers concurrently could lead to data races or segfaults if lifetimes are mismanaged.
*   **Status**: **RESOLVED**. We added `test_concurrent_policy_reload_under_load` to rules-engine tests. It spawns 4 reader threads continuously processing packets while a writer thread reloads new policies 200+ times, verifying zero memory errors or throughput pauses.

---

## 4. Prioritized List of Recommended Tests to Add

We recommend introducing the following tests to harden the system:

| Priority | Test Name / Area | Description | Target Crate |
| :--- | :--- | :--- | :--- |
| **P1** | `test_umem_descriptor_leak` | Simulates a long-running poller that drops/recycles 1,000,000 packets. Asserts that the final free descriptor count matches initial allocation, verifying zero leaks. | `phase1-echo` / `tests` |
| **P1** | `test_k8s_socket_reconnection` | Simulates a worker pod crash or temporary UDS disconnect. Verifies that the worker reconnects to the host daemon, re-binds, and maps new FDs without packet loss. | `k8s-integration` |
| **P2** | `test_numa_affinity_mapping` | Programmatically mocks NIC NUMA node paths (`/sys/class/net/.../device/numa_node`) and checks that the thread-pinning routine maps the polling thread to the correct local CPU core. | `common` |
| **P2** | `test_completion_ring_pressure` | Forces the TX path to submit packets under heavy load without reclaiming completions immediately. Verifies that the queue handles ring backpressure and doesn't drop descriptors. | `tx-optimizations` |
| **P3** | `cargo-fuzz` targets | Implements continuous fuzzing targets using `libFuzzer` for the `walk_message_with_policy` and `parse_grpc_packet` functions to discover edge-case panics. | `rules-engine` / `protobuf` |

---

## 5. How to Run Tests

### Running Unit and Rules Tests (All Environments)
The unit tests (including rules engine policies and security guards) can be run on any host OS:
```bash
# In the phase4 workspace
cd phase4-advanced
cargo test
```

### Running Linux AF_XDP Namespace Emulation
AF_XDP socket tests require Linux and root privileges to set up virtual ethernet interfaces (`veth` pairs):
```bash
# Run in a Linux container/environment
sudo cargo test -- --ignored
```

### Running Colima Integration Tests (macOS Developer Loop)
If you are developing on macOS, use the provided Docker-in-Colima test runner:
```bash
# Compile dependencies and trigger python packet hammer
./tests/run_tests.sh
```

### Running Local Kubernetes SCM_RIGHTS Simulator
To simulate Kubernetes privilege separation on your Linux dev box:
```bash
cd phase4-advanced/k8s-integration
sudo ./sim-test.sh
```
