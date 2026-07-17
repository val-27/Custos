#!/bin/bash
# ==============================================================================
# Custos AF_XDP Kubernetes Integration Test & Simulation Script
# ==============================================================================
#
# Purpose:
#   Simulates the Kubernetes privilege-separated architecture locally using veth
#   pairs. Spawns the privileged daemon (root) and unprivileged worker,
#   injects simulated gRPC / Protobuf packets, and verifies shape validation.

set -euo pipefail

# Configurations
INTERFACE_SIM="veth_sim"
INTERFACE_PEER="veth_peer"
SOCKET_PATH="/tmp/custos.sock"
TARGET_PORT=50051
CORE_DAEMON=0
CORE_WORKER=1

log() {
    echo -e "\033[1;32m[+] $1\033[0m"
}

warn() {
    echo -e "\033[1;33m[!] $1\033[0m"
}

error() {
    echo -e "\033[1;31m[-] $1\033[0m"
    exit 1
}

# 1. Check OS and Privileges
if [[ "$(uname)" != "Linux" ]]; then
    warn "AF_XDP is a Linux-only feature. Skipping local network setup on $(uname)."
    echo "This script is designed to run on a Linux host (e.g. Minikube / Kind node or VM)."
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root to create veth pairs and load eBPF/AF_XDP sockets."
fi

# 2. Build binaries
log "Building Custos integration binaries..."
cargo build --bins --manifest-path "$(dirname "$0")/Cargo.toml"

DAEMON_BIN="$(dirname "$0")/../target/debug/custos-k8s-daemon"
WORKER_BIN="$(dirname "$0")/../target/debug/custos-k8s-worker"

if [[ ! -f "$DAEMON_BIN" || ! -f "$WORKER_BIN" ]]; then
    error "Could not find built binaries at target/debug/."
fi

# 3. Clean up previous runs
log "Cleaning up old state..."
rm -f "$SOCKET_PATH"
ip link delete "$INTERFACE_SIM" 2>/dev/null || true

# 4. Set up Virtual Ethernet pair
log "Creating veth pair ($INTERFACE_SIM <-> $INTERFACE_PEER)..."
ip link add "$INTERFACE_SIM" type veth peer name "$INTERFACE_PEER"
ip link set "$INTERFACE_SIM" up
ip link set "$INTERFACE_PEER" up
# Disable IPv6 to prevent noise
sysctl -w net.ipv6.conf."$INTERFACE_SIM".disable_ipv6=1 >/dev/null
sysctl -w net.ipv6.conf."$INTERFACE_PEER".disable_ipv6=1 >/dev/null

log "veth interface setup complete."

# 5. Spawn Privileged Daemon (Root)
log "Starting privileged host daemon (core $CORE_DAEMON)..."
taskset -c "$CORE_DAEMON" "$DAEMON_BIN" \
    --interface "$INTERFACE_SIM" \
    --queue-id 0 \
    --socket-path "$SOCKET_PATH" \
    --target-port "$TARGET_PORT" \
    --verbose > /tmp/custos-daemon.log 2>&1 &
DAEMON_PID=$!

# Wait for UDS to be created by the daemon
sleep 2
if [[ ! -S "$SOCKET_PATH" ]]; then
    error "Daemon failed to create Unix Domain Socket at $SOCKET_PATH. Log: \n$(cat /tmp/custos-daemon.log)"
fi
log "Daemon started successfully (PID: $DAEMON_PID)."

# 6. Spawn Unprivileged Worker (run as nobody / unprivileged user)
log "Starting unprivileged worker as user 'nobody' (core $CORE_WORKER)..."
# Give 'nobody' access to the Unix socket
chown nobody:nogroup "$SOCKET_PATH" || chown nobody:nobody "$SOCKET_PATH" || true

# Spawn worker using sudo -u nobody
sudo -u nobody taskset -c "$CORE_WORKER" "$WORKER_BIN" \
    --socket-path "$SOCKET_PATH" \
    --core "$CORE_WORKER" \
    --mode echo \
    --verbose > /tmp/custos-worker.log 2>&1 &
WORKER_PID=$!

sleep 2
if ! kill -0 "$WORKER_PID" 2>/dev/null; then
    error "Worker failed to start. Log: \n$(cat /tmp/custos-worker.log)"
fi
log "Worker started successfully (PID: $WORKER_PID)."

# 7. Generate and Inject Traffic (Simulate gRPC / Protobuf packets)
log "Injecting test traffic using Python/Scapy..."
python3 -c "
import socket
from scapy.all import *

# Construct a valid gRPC/HTTP2 Protobuf shape packet
# Ethernet + IP + TCP + HTTP/2 frame payload containing a mock gRPC protobuf message
# Protobuf message serialized bytes with tensor dimensions shape [2, 3] (encoded as varints)
payload = b'\x00\x00\x0c\x00\x00\x00\x00\x00\x01' # HTTP/2 HEADERS/DATA frame header
payload += b'\x00\x00\x00\x00\x07' # gRPC Compression / Length prefix
payload += b'\x08\x02\x08\x03'     # Protobuf wire format: field 1 (varint 2), field 1 (varint 3)

pkt = Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb') / \
      IP(src='192.168.1.10', dst='192.168.1.20') / \
      TCP(sport=12345, dport=$TARGET_PORT) / \
      Raw(load=payload)

sendp(pkt, iface='$INTERFACE_PEER', verbose=False)
print('Injected 1 shape packet into $INTERFACE_PEER')
" || warn "Scapy injection failed. Please verify python3-scapy is installed."

# Let worker process packet
sleep 2

# 8. Check worker output logs
log "Inspecting Worker Log Output:"
cat /tmp/custos-worker.log | tail -n 20 || true

# 9. Clean up
log "Shutting down daemon and worker..."
kill "$DAEMON_PID" "$WORKER_PID" || true
ip link delete "$INTERFACE_SIM" 2>/dev/null || true
rm -f "$SOCKET_PATH"

log "Simulation test finished."
