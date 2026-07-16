FROM rust:latest

# Install build dependencies, network utilities, and python for testing
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    m4 \
    libelf-dev \
    libpcap-dev \
    build-essential \
    pkg-config \
    libxdp-dev \
    libbpf-dev \
    iproute2 \
    python3 \
    python3-pip \
    iputils-ping \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Install scapy for the packet hammer python script
RUN pip3 install --break-system-packages scapy

WORKDIR /workspace
