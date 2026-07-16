# Custos Transmit (TX) Optimizations

This directory contains the high-performance transmit optimizations for Project Custos, a safety-critical network security appliance built in Rust using AF_XDP.

## Overview of Focus Areas & Techniques

To maximize throughput and minimize latency in the packet processing fast paths, the following key optimizations have been implemented:

### 1. Batch Submissions to the TX Ring (`TxBatcher`)
In standard packet processing, submitting packets to the NIC ring individually requires frequent memory-barriers, atomic pointer updates, and kernel syscalls (`sendto`). 
- **Solution**: We implemented the `TxBatcher` struct. It accumulates `FrameDesc` descriptors in userspace buffers and submits them in batches (default size `64`). This amortizes syscall overhead and ring pointer synchronization costs.

### 2. Prefetch-Driven Completion Ring Processing
When packets are transmitted, the kernel places their descriptors on the Completion Queue (`cq`). Consuming descriptors from this queue and returning them to the Fill Queue (`fq`) can cause cache misses when the drivers or userspace loops access the recycled buffers.
- **Solution**: The `reclaim_completed` workflow batch-reclaims descriptors and applies CPU prefetch hints (`prefetch_cacheline`).
- **Cache Prefetch hints**: We implemented platform-specific hardware assembly hints:
  - `x86_64`: Using `_mm_prefetch` with `_MM_HINT_T0` (L1 cache prefetch).
  - `aarch64` / `arm64`: Using inline assembly `prfm pldl1keep, [addr]` to load the packet data cache line into the L1 cache.

### 3. True Zero-Copy Forwarding (UMEM Frame Reuse)
Instead of allocating a separate buffer or copying packet data from the RX ring to the TX ring, Custos implements true zero-copy forwarding.
- **Solution**: The `OptimizedForwarder` receives a `FrameDesc` from the RX ring, modifies the packet (e.g., swapping MAC addresses or applying rules) in-place within the shared UMEM frame, and submits the exact same descriptor directly to the TX batcher. Once transmitted, the completion descriptor is reclaimed and recycled back to the receiving queue's Fill Queue.

### 4. NUMA Alignment & Core Affinity
Memory access across socket boundaries (NUMA nodes) introduces substantial latency and memory bus bottlenecks.
- **Solution**: We implemented NUMA node resolution by parsing interface device node paths on Linux:
  - `get_interface_numa_node`: Reads `/sys/class/net/{interface}/device/numa_node` to find the preferred NUMA node.
  - `get_numa_cores`: Parses `/sys/devices/system/node/node{numa_node}/cpulist` to extract the corresponding CPU cores.
  - `pin_thread_to_numa_node_core`: Automatically pins the polling thread to a core local to the network card's NUMA domain using `sched_setaffinity`.

### 5. Multi-Queue Sharding Integration
To scale horizontally, `multi-queue-sharding` assigns dedicated, shared-nothing Fast Path worker loops to individual RSS queues.
- **Solution**: `spawn_sharded_worker` instantiates independent, lock-free `OptimizedForwarder` loops pinned to the interface's local NUMA cores, completely eliminating cache bouncing and locks in the data plane.

---

## Before / After Benchmarks

A high-resolution benchmark has been developed to compare the performance of the optimized batching and prefetching path against a baseline unoptimized path.

### Benchmark Setup
- **Total Packets**: 10,000,000 packets.
- **Optimized Batch Size**: 64 descriptors.
- **System**: macOS (Darwin Kernel arm64/aarch64 via virtualized memory and mock ring cycle).

### Performance Results

```text
==========================================================
          CUSTOS TX OPTIMIZATION BENCHMARK RUNNER         
==========================================================
Total Packets to process: 10000000
Optimized Batch Size:     64
----------------------------------------------------------
Running Baseline Benchmark (Unoptimized)...
Baseline:  41.44 Mpps (Duration: 241.30ms)
----------------------------------------------------------
Running Optimized Benchmark (Batch size = 64 + Prefetch)...
Optimized: 61.95 Mpps (Duration: 161.42ms)
----------------------------------------------------------
==========================================================
                    BENCHMARK RESULTS                     
==========================================================
Mode                  | Throughput (Mpps) | Latency / Packet
----------------------------------------------------------
Unoptimized (Base)    | 41.44             | 24.1298 ns
Optimized (Batch+Pref)| 61.95             | 16.1421 ns
----------------------------------------------------------
Performance Uplift: 1.49x Speedup
==========================================================
```

### Analysis
- **Throughput uplift**: Throughput increased from **41.44 Mpps** to **61.95 Mpps**, representing a **1.49x speedup** (approx. **49.5% increase**).
- **Latency reduction**: Per-packet latency dropped from **24.13 ns** to **16.14 ns**, validating the benefit of batching and cache prefetching under heavy packet rates.

---

## How to Run the Benchmarks

You can compile and run the benchmark program locally on both macOS and Linux.

1. Navigate to the `phase4-advanced` directory:
   ```bash
   cd phase4-advanced
   ```

2. Run the benchmark binary in release mode:
   ```bash
   cargo run --release --bin bench_tx
   ```
