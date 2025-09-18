#!/usr/bin/env python3
"""Analyze a PCAP file using Pyshark (tshark backend).
Requires: tshark installed and accessible, and `pip install pyshark`.
Usage: python3 analyze_pcap_pyshark.py traffic.pcap
"""
import sys
from collections import Counter

try:
    import pyshark
except ImportError:
    print("Pyshark is not installed. Install with: pip install pyshark")
    sys.exit(1)

def analyze_pcap(path: str):
    cap = pyshark.FileCapture(path, use_json=True)  # JSON speeds up parsing a bit
    proto_count = Counter()
    ip_count = Counter()

    print(f"[*] Reading {path} ...")
    try:
        for pkt in cap:
            # Highest layer as a proxy to protocol
            proto = getattr(pkt.highest_layer, 'layer_name', 'UNKNOWN')
            proto_count[proto] += 1
            # IP sources if available
            try:
                src = pkt.ip.src
                ip_count[src] += 1
            except AttributeError:
                pass
    finally:
        cap.close()

    print("[*] Packets by highest layer/protocol:")
    for k, v in proto_count.most_common():
        print(f"  {k}: {v}")
    print("[*] Top 10 source IPs:")
    for ip, cnt in ip_count.most_common(10):
        print(f"  {ip}: {cnt}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_pcap_pyshark.py <file.pcap>")
        sys.exit(2)
    analyze_pcap(sys.argv[1])
