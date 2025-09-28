#!/usr/bin/env python3
"""Analyze a PCAP file using Scapy.
Usage:
  python3 analyze_pcap_scapy.py traffic.pcap [--csv]
Creates (if --csv): protocols.csv, top_ips.csv
"""
import sys
import argparse
import csv
from collections import Counter

try:
    from scapy.all import rdpcap, TCP, UDP, IP, ICMP
except ImportError:
    print("Scapy is not installed. Install with: pip install scapy")
    sys.exit(1)

def analyze_pcap(path: str, write_csv: bool):
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
    top_ips = list(talkers.most_common(10))
    for ip, cnt in top_ips:
        print(f"  {ip}: {cnt}")

    if write_csv:
        # protocols.csv
        with open('protocols.csv', 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['protocol','count'])
            for k in ['TCP','UDP','ICMP','OTHER','NON-IP']:
                if counts[k]:
                    w.writerow([k, counts[k]])

        # top_ips.csv
        with open('top_ips.csv', 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['ip','packets'])
            for ip, cnt in top_ips:
                w.writerow([ip, cnt])

        print("[*] CSV written: protocols.csv, top_ips.csv")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('pcap', help='Input PCAP file')
    parser.add_argument('--csv', action='store_true', help='Write CSV outputs')
    args = parser.parse_args()

    analyze_pcap(args.pcap, write_csv=args.csv)
