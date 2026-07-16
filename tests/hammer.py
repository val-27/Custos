#!/usr/bin/env python3
import argparse
from scapy.all import sendp, Ether, IP, UDP

def main():
    parser = argparse.ArgumentParser(description="Custos Packet Hammer")
    parser.add_argument("--interface", default="veth1", help="Interface to send packets on")
    parser.add_argument("--count", type=int, default=50000, help="Number of packets to send")
    args = parser.parse_args()

    print(f"Hammering {args.interface} with {args.count} packets...")
    
    # Construct a template UDP packet
    # Dest MAC: broadcast (ff:ff:ff:ff:ff:ff)
    # Src MAC: virtual NIC (02:42:ac:11:00:02)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="02:42:ac:11:00:02") / \
          IP(dst="192.168.1.1", src="192.168.1.2") / \
          UDP(dport=12345, sport=54321) / \
          ("A" * 64)
          
    # Transmit packets
    sendp(pkt, iface=args.interface, count=args.count, verbose=False)
    print(f"Finished sending {args.count} packets.")

if __name__ == "__main__":
    main()
