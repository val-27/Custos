# Custos Benchmark & Monitoring Tool (`custos-bench`)

`custos-bench` is a high-performance traffic generation, benchmarking, and real-time visualization tool designed specifically for the Custos AF_XDP network security appliance. It allows developers and operators to stress-test the validation pipeline with realistic gRPC/Protobuf payloads and monitor active multi-queue daemons via interactive dashboards.

---

## Key Features

1. **Dual Modes**:
   - **`bench` Mode**: Spawns traffic injection loops (in-memory or raw sockets) simulating valid and malicious shape validation payloads, measures performance, and exports comprehensive HTML/JSON reports.
   - **`monitor` Mode**: Attaches to a running Custos daemon (polling its atomic metrics export `/tmp/custos_metrics.json`), displays real-time statistics, and hosts the web interface.
2. **Stress Testing Engine**:
   - **Custom Rust Generator**: Construct valid and invalid HTTP/2 + gRPC + Protobuf packets containing tensor shapes dynamically.
   - **Predefined Profiles**: Choose from `light` (simple verification), `heavy-burst` (spiky high-rate traffic with multiple anomaly types), or `sustained` (continuous high-rate load).
   - **PCAP Exporter**: Save generated traffic directly to standard `.pcap` captures for replay via `tcpreplay` or Cisco TRex.
   - **L2 Raw Socket Injector**: Inject packets directly onto a Linux network interface card (NIC) or virtual interface (`veth`).
3. **Rich Visualizations**:
   - **Real-time TUI**: Crossterm & Ratatui based terminal UI featuring live sparklines, per-core CPU%, drop causes breakdown, and latency histograms.
   - **Interactive Web Portal**: HTMX-enabled modern web dashboard served over Axum, with real-time throughput/latency charts rendered dynamically to SVG using Plotters.
   - **Prometheus Metrics**: Inbuilt scrape target exposing standard Prometheus counters and gauges.
   - **HTML Reports**: Auto-generated print-ready reports containing inline CSS styles and embedded SVG charts.

---

## Installation & Setup

Ensure you compile the phase 4 workspace:

```bash
cd phase4-advanced/
cargo build --release
```

The compiled binary will be located at `target/release/custos-bench`.

---

## CLI Usage Reference

Run the binary with `--help` to view all available CLI parameters:

```text
Usage: custos-bench [OPTIONS] [MODE]

Arguments:
  [MODE]  Operational Mode [default: bench] [possible values: bench, monitor]

Options:
  -p, --profile <PROFILE>        Predefined test profile [default: light] [possible values: light, heavy-burst, sustained]
  -d, --duration <DURATION>      Duration of the benchmark test in seconds [default: 10]
  -i, --interface <INTERFACE>    Interface name to inject raw socket traffic (Linux only)
      --pps <PPS>                Target packet injection rate (Packets Per Second)
      --pcap-out <PCAP_OUT>      Export the simulated traffic to a PCAP file at this path
      --web-port <WEB_PORT>      Port to serve the interactive web dashboard on [default: 8080]
      --report-out <REPORT_OUT>  Output path for the HTML/PDF printable report [default: custos_bench_report.html]
      --json-out <JSON_OUT>      Output path for the raw JSON metrics report [default: custos_bench_metrics.json]
      --mock-target              Use in-memory simulator target instead of physical interface
      --metrics-json <PATH>      Path to read Custos metrics JSON from in monitor mode [default: /tmp/custos_metrics.json]
  -h, --help                     Print help
```

---

## Example Usage Scenarios

### 1. Run an In-Memory Stress Test (Portability Mode)
Execute a 30-second sustained stress test in memory. This measures how fast the parser can walk the Protobuf schemas on your current hardware without requiring network root access:
```bash
./target/release/custos-bench bench --profile sustained --duration 30 --mock-target --web-port 8080
```
Then open `http://localhost:8080` in your browser to view the live HTMX dashboard.

### 2. Export realistic gRPC/Protobuf test traffic to PCAP
Generate 50,000 packets representing a heavy burst scenario (with invalid TCP checksums, recursion limit violations, and bad shapes) and write them to a PCAP file:
```bash
./target/release/custos-bench bench --profile heavy-burst --pcap-out test_grpc_traffic.pcap
```

### 3. Monitor a Live Custos AF_XDP Daemon
Attach the dashboard to a running instance of `custos-multi-queue-sharding` to monitor live traffic rates:
```bash
./target/release/custos-bench monitor --metrics-json /tmp/custos_metrics.json --web-port 8080
```

---

## Understanding the Visualization Dashboards

### Real-time TUI Layout
```text
┌──────────────────────────────── CUSTOS MONITOR & BENCHMARK TOOL ─────────────────────────────────┐
│ CUSTOS MONITOR & BENCHMARK TOOL  |  Active Profile: [Sustained]  |  Mode: BENCHMARK  |  Web: 8080 │
├──────────────────────────────────────────────────────────────────────────────────────────────────┤
│ ┌─ Live Core Traffic Performance ──────────────────────────────────────────────────────────────┐ │
│ │  RX Packet Rate:    500000.00    pps    Throughput: 0.272 Gbps                               │ │
│ │  TX Packet Rate:    450000.00    pps    Throughput: 0.245 Gbps                               │ │
│ │  Validation Drops:  50000.00     pps    Total Dropped: 150000                                │ │
│ │                                                                                              │ │
│ │  Latency percentiles:                                                                        │ │
│ │  p50: 2.10 us  |  p90: 4.50 us  |  p99: 8.90 us  |  p99.9: 18.20 us                          │ │
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │
│ ┌─ Traffic Load History (Peak Rate: 500120.0 pps) ─────────────────────────────────────────────┐ │
│ │  ▂▃▄▅▆▇████████████████████████████████████████████████████████████████████████████████████  │ │
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │
│ ┌─ Worker Core CPU Utilization ────────────────────────────────────────────────────────────────┐ │
│ │ Core  0: [45.2%]  Core  1: [48.1%]  Core  2: [44.9%]  Core  3: [46.7%]                       │ │
│ └──────────────────────────────────────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────────────────────────────────────┘
```

### Web Portal Dashboard
Served at `http://localhost:8080`:
- **Rates Grid**: Large metrics badges showing live PPS and Bandwidth (Gbps) with visual color alerts (Green for forwarding, Red for validation drops).
- **Line-Rate Throughput Line Graph**: Rendered using a 60-second sliding history window.
- **Latency Distribution Histogram**: Displays p50, p90, p99, and p99.9 validation latencies.
- **Deep Packet Parsing Statistics**: Live counts of matches at each network layer (IPv4, TCP, HTTP/2, gRPC, Protobuf).
- **Security Drops Breakdown Table**: Detailed counters mapping drop decisions to validation criteria failures (such as Wrong Target Port, Bad HTTP/2 frame, Shape Value Invalid, etc.).

---

## Hardware Interpretation Guide

When running benchmarks, pay attention to the packet rate (PPS) and bandwidth (Gbps) metrics. Here is what performance numbers look like on different setups:

| Deployment Tier | Mode | Throughput per CPU Core | 8-Core Aggregate Target | Latency (p99) | Notes |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Virtual Ethernet (veth)** | SKB/Copy Mode | ~1.85 Mpps (~1.25 Gbps) | ~14.8 Mpps (~10 Gbps) | ~15 microseconds | Typical local VM or container setups |
| **Physical 10GbE NIC** | XDP Copy Mode | ~3.5 Mpps (~2.4 Gbps) | ~28.0 Mpps (~19.2 Gbps) | ~12 microseconds | Safe fallback when Zero-Copy is unavailable |
| **Physical 40/100GbE NIC** | Native Zero-Copy | ~14.8 Mpps (~10.0 Gbps) | ~118 Mpps (~80 Gbps) | < 8 microseconds | Production hardware with aligned NUMA and Hugepages |

### What to check if PPS numbers are low:
1. **CPU Pinning**: Ensure worker threads are pinned to dedicated physical cores (avoid hyperthreads/SMT cores).
2. **NUMA Alignment**: Verify that the CPU cores designated to process the interface queues belong to the same NUMA node as the PCIe slot of the NIC. Running traffic across the NUMA interconnect (QPI/UPI) drops throughput by up to 30%.
3. **Hugepages**: Ensure 2MB or 1GB hugepages are allocated and mounted for UMEM rings. Without hugepages, TLB cache misses severely bottleneck memory-mapping.
4. **NIC RSS Configuration**: Ensure receive-side scaling is distributing incoming streams evenly across all active CPU queues. Check this using `ethtool -S <interface>`.
