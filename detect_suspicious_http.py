import sys
from collections import Counter
import pyshark

ALLOWLIST = {'example.com','intranet.local'} #ovo bi trebalo svako da prilagodi svojoj mrezi

def analyze_http(pcap):
    cap = pyshark.FileCapture(pcap, display_filter='http')
    hosts = Counter()
    suspicious = []
    for pkt in cap:
        try:
            host = pkt.http.host
            method = pkt.http.request_method
            uri = pkt.http.request_uri
            size = int(pkt.length)
            hosts[host] += 1
            if host not in ALLOWLIST:
                suspicious.append((host, method, uri, size))
        except Exception:
            continue
    cap.close()
    return hosts, suspicious

if __name__ == "__main__":
    pcap = sys.argv[1]
    hosts, suspicious = analyze_http(pcap)
    print("Top hosts (HTTP):")
    for h,c in hosts.most_common(20):
        print(h, c)
    print("\nSuspicious requests (sample):")
    for s in suspicious[:30]:
        print(s)
