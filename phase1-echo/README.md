# Custos Phase 1: AF_XDP Single-Core Echo & Forward

This sub-crate implements the Phase 1 high-performance packet forwarding/echo appliance. It uses a single Linux AF_XDP socket bound to a shared UMEM region, utilizing a busy-poll packet processing loop.

## Architecture

- **UMEM & Frames**: Uses a single UMEM with 2048-byte frames. All frames are pre-allocated and loaded into the Fill Ring at initialization.
- **Queue Buffering**: Double-buffered rings using Fill, RX, TX, and Completion rings.
- **Zero Heap Allocations**: Pre-allocates descriptor batches on the stack/outside the hot path to avoid runtime memory overhead.
- **Zero-Copy Forwarding**: Incoming frame descriptors are modified in-place and submitted directly to the TX ring, cycling back to the Fill ring via the Completion ring.
- **Thread Pinning**: Utilizes `sched_setaffinity` via `custos-common` to pin the poller thread to isolated CPU core 0.

## Build and Run

To compile and check locally (on a Linux environment with `libxdp-dev` and `libbpf-dev` installed):
```bash
cargo build --release
```

To run the binary:
```bash
sudo ./target/release/custos-phase1-echo --interface veth0 --queue-id 0 --frame-count 2048 --mode echo --verbose
```

### CLI Arguments

- `-i, --interface`: Name of the network interface (e.g. `veth0`).
- `-c, --core`: CPU core ID to pin the thread to (default: `0`).
- `-q, --queue-id`: Queue index of the network interface (default: `0`).
- `-f, --frame-count`: Number of UMEM frames (default: `2048`, must be a power of 2).
- `-m, --mode`: Mode of operation (`drop`, `forward`, or `echo`).
  - `drop`: Drops all incoming packets, immediately recycling descriptors back into the Fill ring.
  - `forward`: Zero-copy forwards all packets to the TX ring.
  - `echo`: Swaps packet Ethernet source and destination MAC addresses in-place before forwarding.
- `-v, --verbose`: Enables verbose debugging logs to monitor packet batches.

## Performance Expectations

On virtual network interfaces (like `veth` pairs) under containerized setups (e.g., Colima VM), the throughput is limited by the kernel's network stack traversal since packets still traverse Linux software bridges.
- **Generic (SKB) Mode**: Typically yields **100k - 250k PPS** on standard developer machines due to network stack copy overhead.
- **Native (DRV) Mode**: (Requires compatible network hardware NIC) Can achieve **5M - 12M+ PPS** per core in zero-copy mode.

## Measurement Method

PPS (packets per second) and throughput (MB/s) are measured dynamically in the poll loop. Every 1 second, the loop calculates the elapsed time since the last metrics print, computes the current packet rates, resets the counters, and prints the statistics via structured logs.
