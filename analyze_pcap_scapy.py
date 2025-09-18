#!/usr/bin/env python3
"""Analyze a PCAP file using Scapy.
Requires: `pip install scapy`.
Usage: python3 analyze_pcap_scapy.py traffic.pcap
"""
import sys
from collections import Counter

try:
    from scapy.all import rdpcap, TCP, UDP, IP, ICMP
except ImportError:
    print("Scapy is not installed. Install with: pip install scapy")
    sys.exit(1)

def analyze_pcap(path: str):
    print(f"[*] Reading {path} ...")
    pkts = rdpcap(path)
    counts = Counter()
    talkers = Counter()

    for p in pkts:
        if IP in p:
            talkers[p[IP].src] += 1
            if TCP in p:
                counts['TCP'] += 1
            elif UDP in p:
                counts['UDP'] += 1
            elif ICMP in p:
                counts['ICMP'] += 1
            else:
                counts['OTHER'] += 1
        else:
            counts['NON-IP'] += 1

    total = len(pkts)
    print(f"Total packets: {total}")
    for k in ['TCP', 'UDP', 'ICMP', 'OTHER', 'NON-IP']:
        if counts[k]:
            print(f"{k}: {counts[k]}")
    print("Top 10 sources:")
    for ip, cnt in talkers.most_common(10):
        print(f"  {ip}: {cnt}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze_pcap_scapy.py <file.pcap>")
        sys.exit(2)
    analyze_pcap(sys.argv[1])
