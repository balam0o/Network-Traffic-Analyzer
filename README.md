## Setup
python -m venv .venv

# Windows
.venv\Scripts\activate

pip install -r requirements.txt


## Analyze a pcap
python -m src.main pcap --pcap captures/example.pcap

## Capture live traffic (may require admin/root)
python -m src.main capture --out captures/live.pcap --count 200 --iface "Wi-Fi"

python -m src.main capture --out captures/http.pcap --count 200 --iface "Wi-Fi" --bpf "tcp port 80"

## Notes
- Live capture on Windows requires Npcap and running the terminal as Administrator.
- PCAP files are ignored by git; generate your own captures locally.
