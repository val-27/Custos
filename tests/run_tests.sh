#!/usr/bin/env bash
# Integration test runner for Custos Phase 1.
# Spins up Colima VM, creates veth pairs, runs docker-compose, and triggers packet hammer.

set -e

# Define workspace directory on host and VM (they match due to mounts)
WORKSPACE_DIR="/Users/jpvalent/.treehouse/Custos-1475d5/1/Custos"

echo "=========================================================="
echo "          CUSTOS PHASE 1 INTEGRATION TEST RUNNER          "
echo "=========================================================="

# 1. Ensure Colima is running
echo ">>> [1/6] Checking Colima VM status..."
if colima status >/dev/null 2>&1; then
    echo "Colima is running."
else
    echo "Colima is not running. Starting Colima..."
    colima start --cpu 2 --memory 4
fi

# 2. Setup Veth interfaces inside the Colima Linux kernel
echo ">>> [2/6] Configuring virtual network interfaces in Colima..."
colima ssh -- bash -c "
if ! ip link show veth0 >/dev/null 2>&1; then
    echo 'veth0/veth1 not found. Creating veth pair...'
    sudo ip link add veth0 type veth peer name veth1
    sudo ip link set veth0 up
    sudo ip link set veth1 up
    echo 'Veth pair veth0 <-> veth1 created and set UP.'
else
    echo 'Veth pair veth0 <-> veth1 already exists. Ensuring they are UP...'
    sudo ip link set veth0 up
    sudo ip link set veth1 up
fi
"

# 3. Pre-build the Rust binary to avoid startup delay in docker-compose
echo ">>> [3/6] Compiling Custos Phase 1 echo appliance in release mode..."
docker run --rm -v "${WORKSPACE_DIR}":/workspace custos-builder:latest cargo build --release -p custos-phase1-echo

# 4. Spin up Custos container via docker-compose
echo ">>> [4/6] Deploying Custos Phase 1 echo container..."
colima ssh -- bash -c "cd ${WORKSPACE_DIR} && docker compose up -d custos"

echo "Waiting 4 seconds for AF_XDP socket initialization and thread pinning..."
sleep 4

# 5. Run the packet hammer
echo ">>> [5/6] Executing Python scapy packet hammer..."
colima ssh -- bash -c "cd ${WORKSPACE_DIR} && docker compose run --rm hammer python3 tests/hammer.py --interface veth1 --count 150000"

echo "Waiting 3 seconds for processing and stats window..."
sleep 3

# 6. Retrieve metrics and tear down
echo ">>> [6/6] Displaying Custos processing logs and pps statistics..."
echo "------------------- CUSTOS LOGS -------------------"
colima ssh -- bash -c "cd ${WORKSPACE_DIR} && docker compose logs custos"
echo "---------------------------------------------------"

echo ">>> Tearing down Docker Compose containers..."
colima ssh -- bash -c "cd ${WORKSPACE_DIR} && docker compose down"

echo "=========================================================="
echo "             INTEGRATION TEST COMPLETE                    "
echo "=========================================================="
