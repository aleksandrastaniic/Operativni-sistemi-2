# Network Traffic Analysis (OS2)
Praktični primeri za programsko analiziranje mrežnog saobraćaja u Python-u (Operativni sistemi 2).

## Sadržaj repozitorijuma
- `netcat_server.py` / `netcat_client.py`: mini "netcat" primer (TCP server/klijent).
- `sniffer.py`: osnovni sniffer sa raw soketom (Linux, `sudo`).
- `analyze_pcap_pyshark.py`: analiza PCAP pomoću Pyshark-a (`tshark` backend).
- `analyze_pcap_scapy.py`: analiza PCAP pomoću Scapy-ja.
- `requirements.txt`: Python zavisnosti.

## Brzi start
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Pyshark zahtevi
Instalirajte `tshark` (npr. na Ubuntu/Debian):
```bash
sudo apt update && sudo apt install -y tshark
```

## Korišćenje
### Mini "netcat"
U jednom terminalu:
```bash
python3 netcat_server.py
```
U drugom terminalu:
```bash
python3 netcat_client.py
```

### Sniffer (Linux)
Potrebne su `sudo` privilegije:
```bash
sudo python3 sniffer.py
```
Pritisnite `Ctrl+C` za prekid.

### Analiza PCAP-a (Pyshark)
```bash
python3 analyze_pcap_pyshark.py traffic.pcap
```

### Analiza PCAP-a (Scapy)
```bash
python3 analyze_pcap_scapy.py traffic.pcap
```

## Gde naći PCAP fajlove za testiranje?
Možete koristiti javno dostupne uzorke, npr. Wireshark Sample Captures (potražite `http.cap`, `dns.cap`, `icmp.pcap` i sl.).
Ako želite sopstveni snimak:
```bash
# Primer snimanja prvih ~100 paketa na interfejsu eth0 (Linux)
sudo tcpdump -i eth0 -c 100 -w mycapture.pcap
```

## Napomene
- `sniffer.py` koristi `AF_PACKET` i radi na Linux-u.
- Za Pyshark je potreban `tshark` u PATH-u.
- Izlaz programa možete preusmeriti u fajl:
```bash
python3 analyze_pcap_scapy.py traffic.pcap > results.txt
```

## Licenca
MIT
