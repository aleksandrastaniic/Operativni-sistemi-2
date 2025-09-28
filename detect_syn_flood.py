import sys
from collections import defaultdict
from scapy.all import rdpcap, TCP, IP

def analyze_syn(pcap):
    pkts = rdpcap(pcap)
    stats = defaultdict(lambda: {'SYN':0, 'SYN-ACK':0, 'ACK':0})
    for p in pkts:
        if IP in p and TCP in p:
            flags = p[TCP].flags
            dst = (p[IP].dst, p[TCP].dport)
            src = (p[IP].src, p[TCP].sport)
            if flags & 0x02:
                if flags & 0x10:  
                    stats[dst]['SYN-ACK'] += 1
                else:
                    stats[dst]['SYN'] += 1
            elif flags & 0x10:  
                stats[dst]['ACK'] += 1
    return stats

if __name__ == "__main__":
    pcap=sys.argv[1]
    s=analyze_syn(pcap)
    for dst, st in sorted(s.items(), key=lambda kv: kv[1]['SYN'], reverse=True)[:30]:
        syn, synack, ack = st['SYN'], st['SYN-ACK'], st['ACK']
        ratio = syn / (synack+1)
        print(f"{dst[0]}:{dst[1]:5} SYN={syn:5} SYN-ACK={synack:5} ACK={ack:5} syn/synack={ratio:.1f}")
