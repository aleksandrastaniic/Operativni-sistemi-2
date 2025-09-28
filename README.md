# Network Traffic Analysis (OS2)
Praktični primeri za programsko analiziranje mrežnog saobraćaja u Python-u (Operativni sistemi 2).

## 📂 Sadržaj repozitorijuma
- `netcat_server.py` / `netcat_client.py` – mini "netcat" primer (TCP server/klijent).
- `sniffer.py` – osnovni sniffer sa raw soketom (Linux, `sudo`).
- `analyze_pcap_pyshark.py` – analiza PCAP pomoću Pyshark-a (`tshark` backend).
- `analyze_pcap_scapy.py` – analiza PCAP pomoću Scapy-ja.
- `plot_results.py` – skripta koja čita CSV i crta grafikone (`protocols_bar.png`, `top_ips.png`).
- `detect_dns_tunnel.py`, `detect_syn_flood.py`, `detect_suspicious_http.py` – bezbednosne detekcije (DNS tunneling, SYN flood, sumnjivi HTTP hostovi).
- `komande.txt` – pregled komandnog toka (redosled pokretanja) i primeri.
- `requirements.txt` – Python zavisnosti (preporučeno).

---

## ⚙️ Instalacija i priprema okruženja (detaljno)

### 1) Kreiranje Python virtuelnog okruženja
```bash
# u root folderu repozitorijuma
python3 -m venv .venv
# aktiviraj
source .venv/bin/activate            # Linux/macOS
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
# Windows CMD:
# .venv\Scripts\activate.bat
```

### 2) Instalacija Python zavisnosti
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

Ako `requirements.txt` ne sadrži scapy/pyshark, instaliraj posebno:

```bash
pip install scapy
pip install pyshark
```

### 3) Sistemski paket za Pyshark (tshark)
Pyshark koristi tshark (wireshark backend). Na Debian/Ubuntu:

```bash
sudo apt update
sudo apt install -y tshark
# prva upotreba može zahtevati potvrdu privilegija
```

## 🚀 Kompletan workflow (redosled komandi — step-by-step)
Savet: otvori tri terminala/tabs i prati redosled dole — server, sniffer/tcpdump, klijent/testovi.

### A) Pokretanje mini "netcat" (test generator)
**Terminal 1** — server

```bash
python3 netcat_server.py
# server binduje 127.0.01:42424 i čeka konekcije
```

**Terminal 2** — klijent

```bash
python3 netcat_client.py
# klijent se poveže na 127.0.0.1:42424 i pošalje test poruku
```

### B) Sirovo preslušavanje sa sniffer.py (Linux only)
**Terminal 3** — sniffer (potreban sudo, AF_PACKET)

```bash
sudo python3 sniffer.py >> izlaz.txt
# sniffer će raditi dok ne pritisneš Ctrl+C; izlaz se upisuje u izlaz.txt
```

filtriranje izlaza:

```bash
# primer: prikaži linije koje sadrže klijentski ephemeral port (npr. 46376)
grep "46376" izlaz.txt
```

### C) Snimanje PCAP fajla sa tcpdump
Koristi tcpdump da zabeležiš PCAP koji će se analizirati:

**Samo loopback i naš port (lokalni test):**

```bash
sudo tcpdump -i lo -c 200 -w mycapture.pcap 'tcp port 42424 or udp port 42424'
```

**Snimanje na svim interfejsima (uključuje i sistemski promet):**

```bash
sudo tcpdump -i any -c 200 -w mycapture_any.pcap
```

Ako želiš snimiti dok radiš više akcija:

```bash
# u jednom terminalu
sudo tcpdump -i any -w mycapture_full.pcap
# u drugom terminalu izvodi testove (curl, ping, netcat...), pa Ctrl+C za prekid
```

### D) Analiza PCAP fajla → CSV
Možeš birati Scapy ili Pyshark varijantu. Primeri:

**Scapy (brzo, Python-only):**

```bash
python3 analyze_pcap_scapy.py mycapture.pcap --csv
# izlazi: protocols.csv, top_ips.csv
```

**Pyshark (tshark backend, detaljnije polje-layer izvlačenje):**

```bash
python3 analyze_pcap_pyshark.py mycapture.pcap --csv
# izlazi: protocols.csv, top_ips.csv
```

### E) Pravljenje grafikona iz CSV-a
Ako imaš `protocols.csv` i `top_ips.csv`, pokreni:

```bash
python3 plot_results.py
# izlazi: protocols_bar.png, top_ips.png
```

### F) Bezbednosne detekcije (opciono)
Pokreni detekcione skripte nad istim PCAP-om:

```bash
python3 detect_dns_tunnel.py mycapture.pcap      # -> dns_summary.csv
python3 detect_syn_flood.py mycapture.pcap       # -> syn_report.csv
python3 detect_suspicious_http.py mycapture.pcap # -> http_hosts.csv, http_suspicious_samples.csv
```

## 📄 Šta te skripte rade i koje fajlove generišu

### analyze_pcap_scapy.py / analyze_pcap_pyshark.py

Parsiraju `mycapture.pcap`, broj paketa po tipu (TCP/UDP/ICMP/OTHER/NON-IP), broje pakete po izvornoj IP adresi.

Opcija `--csv` piše:
- `protocols.csv` (protocol,count)
- `top_ips.csv` (ip,packets)

### plot_results.py

Učita `protocols.csv` i `top_ips.csv` i napravi:
- `protocols_bar.png` (bar chart)
- `top_ips.png` (horizontal bar chart)

### detect_dns_tunnel.py

Analizuje DNS upite: broji upite po domenima, računa prosečnu dužinu leve label-e, Shannon entropiju labela, query rate (qpm).

Ispisuje `dns_summary.csv` sa kolonama:
- `domain,count,types,avg_label_len,avg_entropy,queries_per_min`

### detect_syn_flood.py

Broji TCP flagove (SYN, SYN-ACK, ACK) po destinaciji (dst_ip:dst_port).

Ispisuje `syn_report.csv` sa kolonama:
- `dst_ip,dst_port,SYN,SYN-ACK,ACK,syn_synack_ratio`

### detect_suspicious_http.py

Heuristički pretražuje HTTP zahteve u plaintextu (GET/POST/HEAD...), ekstraktuje Host zaglavlje.

Ispisuje:
- `http_hosts.csv` (host_or_ip,count)
- `http_suspicious_samples.csv` (host,dst_ip,sample_request_line)

## 🧾 Primer interpretacija (što staviti u rad / prezentaciju)

- **protocols_bar.png** — prikazuje raspodelu paketa po protokolima (npr. TCP dominira → normalno za web/git/ssh).
- **top_ips.png** — pokazuje najaktivnije IP adrese (127.0.0.1 ako je lokalni test; spoljni IP-ovi za internet saobraćaj).
- **dns_summary.csv** — domeni sa visokim `avg_label_len` i `avg_entropy` su kandidati za DNS tunneling.
- **syn_report.csv** — destinacije sa visokim SYN i visokim `syn_synack_ratio` su sumnjive (potencijalni SYN flood ili skeniranje).
- **http_suspicious_samples.csv** — primeri HTTP zahteva koji nisu u allowlisti (za ručnu proveru).

U radu prikaži: (1) komandu kojom si snimila PCAP, (2) tačnu skriptu koja je generisala CSV, (3) grafikon i kratak komentar (1–2 rečenice) šta grafikon pokazuje i zašto je to relevantno.

## 🛠️ Troubleshooting (često greške i rešenja)

- `ModuleNotFoundError: No module named 'scapy'` → aktiviraj venv i `pip install scapy`.
- `tshark: not found` → instaliraj tshark sistemski (`sudo apt install tshark`).
- `Permission denied` kod tcpdump → koristi sudo.
- Prazni CSV-ovi → PCAP ne sadrži ciljani promet (proveri filter, interfejs i da li si pokrenuo test klijenta).
- Ako radiš u WSL/Windows: loopback/WSL i Windows mreže ponekad se ponašaju drugačije; za lokalni test koristi `-i lo` unutar WSL-a.

## 🧾 Kompletan primer sesije (copy-paste)

```bash
# 1. Aktiviraj venv i instaliraj
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
sudo apt update && sudo apt install -y tshark   # opciono, za pyshark

# 2. Pokreni server
python3 netcat_server.py

# 3. (u drugom terminalu) pokreni sniffer za debug (opcioni)
sudo python3 sniffer.py >> izlaz.txt &

# 4. (u trećem terminalu) pokreni klijenta/test
python3 netcat_client.py

# 5. Snimi PCAP (u novom terminalu) dok radiš više akcija
sudo tcpdump -i any -c 200 -w mycapture_any.pcap

# 6. Analiziraj i izvezi CSV
python3 analyze_pcap_scapy.py mycapture_any.pcap --csv

# 7. Napravi grafike
python3 plot_results.py

# 8. Pokreni detekcije (opciono)
python3 detect_dns_tunnel.py mycapture_any.pcap
python3 detect_syn_flood.py mycapture_any.pcap
python3 detect_suspicious_http.py mycapture_any.pcap
```

## 📄 Gde naći PCAP fajlove za testiranje

- **Wireshark Sample Captures**: https://wiki.wireshark.org/SampleCaptures
- Možete koristiti sopstvene: `tcpdump -i <iface> -c N -w out.pcap` dok radite testove (curl, ping, nc...).

## 📄 Licenca
MIT