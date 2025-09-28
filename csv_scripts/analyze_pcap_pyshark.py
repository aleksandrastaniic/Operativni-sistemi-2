#!/usr/bin/env python3
import sys
import argparse
import csv
from collections import Counter

try:
    import pyshark
except ImportError:
    print("Pyshark is not installed. Install with: pip install pyshark")
    sys.exit(1)

def analyze_pcap(path: str, write_csv: bool):
    cap = pyshark.FileCapture(path, use_json=True)
    proto_count = Counter()
    ip_count = Counter()

    print(f"[*] Reading {path} ...")
    try:
        for pkt in cap:
            # highest layer as protocol-ish label
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
    top_ips = list(ip_count.most_common(10))
    for ip, cnt in top_ips:
        print(f"  {ip}: {cnt}")

    if write_csv:
        with open('protocols.csv', 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['protocol','count'])
            for k, v in proto_count.most_common():
                w.writerow([k, v])

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
