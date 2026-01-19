![tests](https://github.com/balam0o/Network-Traffic-Analyzer/actions/workflows/tests.yml/badge.svg)

# Network Traffic Analyzer

Analyze PCAP files and capture live traffic to get:
- Protocol distribution (TCP/UDP/Other)
- Top 10 IPs (src+dst)
- Top 10 destination ports (per protocol)
- Throughput (bytes/sec, 1s windows)
- TCP RTT (SYN and data ACK-based)
- TCP loss estimate (retransmissions)

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

Throughput summary (window=1s):
Buckets: 38
Avg bps: 108408.16
Max bps: 453323.00

TCP RTT summary (ms):
SYN count: 70
SYN min: 0.255000
SYN avg: 11.025542857142857
SYN max: 109.360000
DATA count: 1308
DATA min: 0.044000
DATA avg: 67.68564373088685
DATA max: 24101.198000

TCP loss estimate:
Retransmissions: 56
Total segments: 1613
Loss rate: 0.0347

## Output paths
Output paths are not created automatically.
If you want to organize results in folders, create them explicitly:

mkdir captures reports

python -m src.main capture --out captures/live.pcap
python -m src.main pcap --pcap captures/test.pcap --json reports/report.json

## Testing
python -m pytest
