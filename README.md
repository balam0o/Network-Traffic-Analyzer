# Network Traffic Analyzer

Analyze PCAP files and capture live traffic to get:
- Protocol distribution (TCP/UDP/Other)
- Top 10 IPs (src+dst)
- Top 10 destination ports (per protocol)

## Setup
python -m venv .venv
# Windows:
.venv\Scripts\activate
pip install -r requirements.txt

## Analyze a pcap
python -m src.main pcap --pcap captures/test.pcap

## Capture live traffic (may require admin/root)
python -m src.main capture --out captures/test.pcap --count 200 --timeout 10 --iface "Wi-Fi"
python -m src.main capture --out captures/http.pcap --count 200 --timeout 10 --iface "Wi-Fi" --bpf "tcp port 80"

## Notes (Windows)
- Install Npcap (WinPcap-compatible mode recommended)
- Run terminal as Administrator for capture

## Example output
Protocol statistics:
UDP: 3246
TCP: 2344
OTHER: 324

Top 10 IPs (src+dst):
192.168.100.38: 1187
...

Top 10 destination ports:
UDP/443: 910
TCP/443: 552
...