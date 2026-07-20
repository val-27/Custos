# Prometheus Metrics & Grafana Observability for Custos

Project Custos includes a lightweight, zero-overhead Prometheus HTTP metrics exporter (`/metrics`) built with `axum`.

## Architecture & Zero Impact Guarantee

- **Lock-free hot path**: Packet processing threads update cache-line aligned (`#[repr(align(64))]`) `ThreadStats` atomic counters using `Ordering::Relaxed`. No locks, heap allocations, or I/O take place inside the packet processing loop.
- **Dedicated serving thread**: An isolated background thread hosts an asynchronous `axum` HTTP server on port `9090` (configurable via `--metrics-port`).
- **Exposition format**: Serves standard Prometheus text format (`text/plain; version=0.0.4; charset=utf-8`).

---

## Configuration & Usage

### CLI Options

When running `custos-multi-queue-sharding` (or other Custos daemons):

```bash
./target/release/custos-multi-queue-sharding \
  --interface eth0 \
  --queues 4 \
  --metrics \
  --metrics-port 9090
```

- `--metrics`: Enables the Prometheus HTTP server (default: `true`).
- `--metrics-port <PORT>`: Specifies HTTP listening port (default: `9090`).

### Endpoint Verification

Query the endpoint directly via `curl`:

```bash
curl http://localhost:9090/metrics
```

Example response:

```text
# HELP custos_up Appliance status (1 for running).
# TYPE custos_up gauge
custos_up 1

# HELP custos_rx_packets_total Total packets received across all cores.
# TYPE custos_rx_packets_total counter
custos_rx_packets_total 1250320

# HELP custos_core_rx_packets_total Received packets per CPU core.
# TYPE custos_core_rx_packets_total counter
custos_core_rx_packets_total{core="0"} 625160
custos_core_rx_packets_total{core="1"} 625160

# HELP custos_dropped_packets_total Total dropped packets by drop reason.
# TYPE custos_dropped_packets_total counter
custos_dropped_packets_total{reason="validation_failed"} 12

# HELP custos_protocol_packets_total Total packets inspected by protocol.
# TYPE custos_protocol_packets_total counter
custos_protocol_packets_total{protocol="ipv4"} 1250320
custos_protocol_packets_total{protocol="tcp"} 1250320
custos_protocol_packets_total{protocol="http2"} 1250000
custos_protocol_packets_total{protocol="grpc"} 1250000
custos_protocol_packets_total{protocol="protobuf"} 1250000

# HELP custos_parser_errors_total Total L2-L5 parser errors by reason.
# TYPE custos_parser_errors_total counter
custos_parser_errors_total{reason="too_small"} 0
custos_parser_errors_total{reason="non_ipv4"} 0
custos_parser_errors_total{reason="bad_ip_len"} 0
...

# HELP custos_processing_latency_seconds Packet processing latency histogram in seconds.
# TYPE custos_processing_latency_seconds histogram
custos_processing_latency_seconds_bucket{le="0.0000001"} 500000
custos_processing_latency_seconds_bucket{le="0.0000005"} 1200000
custos_processing_latency_seconds_bucket{le="0.000001"} 1250000
custos_processing_latency_seconds_bucket{le="+Inf"} 1250000
custos_processing_latency_seconds_sum 0.000512000
custos_processing_latency_seconds_count 1250000
```

---

## Prometheus Scrape Config (`prometheus.yml`)

Add the following scrape configuration to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'custos'
    metrics_path: '/metrics'
    scrape_interval: 5s
    static_configs:
      - targets: ['localhost:9090']
        labels:
          app: 'custos'
          env: 'production'
```

---

## Docker Compose Stack

Run the full Custos + Prometheus + Grafana stack with a single command:

```bash
docker-compose up -d
```

Services in the stack:
- **Custos Appliance**: `http://localhost:9090/metrics`
- **Prometheus UI**: `http://localhost:9090`
- **Grafana Dashboard**: `http://localhost:3000` (User: `admin`, Password: `admin`)

The Grafana instance automatically loads the pre-configured Prometheus data source and imports [`deploy/grafana/dashboard.json`](file:///Users/jpvalent/.treehouse/Custos-1475d5/1/Custos/deploy/grafana/dashboard.json).
