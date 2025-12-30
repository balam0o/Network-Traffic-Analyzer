import argparse
from .pcap_reader import load_pcap
from .stats import protocol_stats
from .capture import capture_to_pcap

def run_pcap(pcap_path: str):
    packets = load_pcap(pcap_path)
    stats = protocol_stats(packets)

    print("Protocol statistics:")
    for proto, count in stats.items():
        print(f"{proto}: {count}")

def run_capture(out: str, count: int, iface: str | None, bpf: str | None, timeout: int | None):
    n = capture_to_pcap(out, count=count, iface=iface, bpf_filter=bpf, timeout=timeout)
    print(f"Captured {n} packets -> {out}")
    run_pcap(out)

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    pcap_cmd = sub.add_parser("pcap", help="Analyze an existing pcap file")
    pcap_cmd.add_argument("--pcap", required=True, help="Path to pcap file")

    cap_cmd = sub.add_parser("capture", help="Capture live traffic and analyze it")
    cap_cmd.add_argument("--out", required=True, help="Output pcap path, e.g. captures/out.pcap")
    cap_cmd.add_argument("--count", type=int, default=100, help="Number of packets to capture")
    cap_cmd.add_argument("--iface", default=None, help="Interface, e.g. eth0, wlan0")
    cap_cmd.add_argument("--bpf", default=None, help="BPF filter, e.g. 'tcp port 80'")
    cap_cmd.add_argument("--timeout", type=int, default=None, help="Seconds to capture")

    args = parser.parse_args()

    if args.cmd == "pcap":
        run_pcap(args.pcap)
    elif args.cmd == "capture":
        run_capture(args.out, args.count, args.iface, args.bpf, args.timeout)

if __name__ == "__main__":
    main()
