#!/usr/bin/env python3
import csv
import matplotlib.pyplot as plt

protos, counts = [], []
with open('protocols.csv') as f:
    r = csv.DictReader(f)
    for row in r:
        protos.append(row['protocol'])
        counts.append(int(row['count']))

plt.figure()
plt.bar(protos, counts)
plt.title('Raspodela paketa po protokolima')
plt.xlabel('Protokol')
plt.ylabel('Broj paketa')
plt.tight_layout()
plt.savefig('protocols_bar.png')
plt.close()

ips, pkts = [], []
with open('top_ips.csv') as f:
    r = csv.DictReader(f)
    for row in r:
        ips.append(row['ip'])
        pkts.append(int(row['packets']))

plt.figure()
plt.barh(ips, pkts)
plt.title('Top IP adrese po broju paketa')
plt.xlabel('Broj paketa')
plt.tight_layout()
plt.savefig('top_ips.png')
plt.close()

print("[*] Saved: protocols_bar.png, top_ips.png")
