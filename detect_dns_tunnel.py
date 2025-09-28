import sys
from collections import defaultdict, Counter
from math import log2
from scapy.all import rdpcap, DNSQR, DNS, UDP, IP

def entropy(s: str) -> float:
    cnt = Counter(s)
    L = len(s)
    if L == 0:
        return 0.0
    return -sum((v/L) * log2(v/L) for v in cnt.values())

def analyze_dns(pcap_path):
    pkts = rdpcap(pcap_path)
    domain_stats = defaultdict(lambda: {'count':0, 'labels':[], 'types':Counter(), 'timestamps':[]})
    for p in pkts:
        if DNS in p and p.haslayer(DNSQR):
            qname = p[DNSQR].qname.decode().rstrip('.')
            qtype = p[DNSQR].qtype
            ts = p.time
            domain = '.'.join(qname.split('.')[-2:]) if len(qname.split('.'))>=2 else qname
            labels = qname.split('.')
            domain_stats[domain]['count'] += 1
            domain_stats[domain]['labels'].append(labels[0]) 
            domain_stats[domain]['types'][qtype] += 1
            domain_stats[domain]['timestamps'].append(ts)
    results = []
    for dom, st in domain_stats.items():
        labels = st['labels']
        avg_label_len = sum(len(l) for l in labels)/len(labels)
        avg_entropy = sum(entropy(l) for l in labels)/len(labels)
        rate_per_min = len(labels) / ((max(st['timestamps']) - min(st['timestamps']) + 1e-6) / 60.0)
        results.append((dom, st['count'], st['types'], avg_label_len, avg_entropy, rate_per_min))
    return sorted(results, key=lambda x: x[1], reverse=True)

if __name__ == "__main__":
    pcap = sys.argv[1]
    for dom, cnt, types, avg_len, avg_ent, rpm in analyze_dns(pcap):
        print(f"{dom:35} count={cnt:5} types={dict(types)} avg_label_len={avg_len:.1f} avg_entropy={avg_ent:.2f} qpm={rpm:.1f}")
