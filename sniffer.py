#!/usr/bin/env python3
"""Basic packet sniffer using a raw socket (Linux).
Requires sudo privileges and a Linux host (uses AF_PACKET).
Usage (Linux): sudo python3 sniffer.py
"""
import socket
import struct

ETH_P_IP = 0x0800  # IPv4

def parse_ipv4_header(data: bytes):
    ver_ihl = data[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    ttl = data[8]
    proto = data[9]
    src = data[12:16]
    dst = data[16:20]
    src_ip = ".".join(map(str, src))
    dst_ip = ".".join(map(str, dst))
    return version, ihl, ttl, proto, src_ip, dst_ip

def parse_tcp_header(data: bytes):
    (sport, dport, seq, ack, offset_reserved_flags) = struct.unpack("!HHLLH", data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flags = offset_reserved_flags & 0x01FF
    return sport, dport, seq, ack, offset, flags

def parse_udp_header(data: bytes):
    sport, dport, length, checksum = struct.unpack("!HHHH", data[:8])
    return sport, dport, length, checksum

def main():
    # Raw socket on Linux capturing all protocols (EtherType in host byte order via ntohs(0x0003))
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    print("[sniffer] capturing IPv4 packets. Press Ctrl+C to stop.")
    try:
        while True:
            raw, addr = s.recvfrom(65535)
            eth_proto = struct.unpack("!H", raw[12:14])[0]
            if eth_proto != ETH_P_IP:
                continue
            version, ihl, ttl, proto, src, dst = parse_ipv4_header(raw[14:34])
            payload = raw[14+ihl:]
            if proto == 6:  # TCP
                sport, dport, *_ = parse_tcp_header(payload)
                print(f"TCP {src}:{sport} -> {dst}:{dport} TTL={ttl}")
            elif proto == 17:  # UDP
                sport, dport, length, _ = parse_udp_header(payload)
                print(f"UDP {src}:{sport} -> {dst}:{dport} len={length} TTL={ttl}")
            elif proto == 1:  # ICMP
                print(f"ICMP {src} -> {dst} TTL={ttl}")
            else:
                print(f"IPv4 proto={proto} {src} -> {dst} TTL={ttl}")
    except KeyboardInterrupt:
        print("\n[sniffer] stopped.")

if __name__ == "__main__":
    main()
