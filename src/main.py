import argparse
from .pcap_reader import load_pcap
from .capture import capture_to_pcap
from .stats import (
    protocol_stats,
    top_src_ips,
    top_dst_ips,
    top_src_ports,
    top_dst_ports,
)

def print_counter(title: str, items, top: int):
    print(f"\n{title} (Top {top}):")
    if not items:
        print("No data found.")
        return
    for key, count in items:
        print(f"{key}: {count}")

def run_pcap(pcap_path: str, top: int):
    packets = load_pcap(pcap_path)

    proto = protocol_stats(packets)           #Counter
    src_ips = top_src_ips(packets, n=top)     #list[(key,count)]
    dst_ips = top_dst_ips(packets, n=top)
    src_ports = top_src_ports(packets, n=top)
    dst_ports = top_dst_ports(packets, n=top)

    print(f"Analyzing: {pcap_path}")
    print(f"Total packets: {len(packets)}")

    print("\nProtocol statistics:")
    for k, v in proto.most_common():
        print(f"{k}: {v}")

    print_counter("Source IPs", src_ips, top)
    print_counter("Destination IPs", dst_ips, top)
    print_counter("Source ports", src_ports, top)
    print_counter("Destination ports", dst_ports, top)

def run_capture(out: str, count: int, iface: str | None, bpf: str | None, timeout: int | None, top: int):
    n = capture_to_pcap(out, count=count, iface=iface, bpf_filter=bpf, timeout=timeout)
    print(f"Captured {n} packets -> {out}")
    run_pcap(out, top=top)

def build_parser():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    #PCAP mode
    pcap_cmd = sub.add_parser("pcap", help="Analyze an existing pcap file")
    pcap_cmd.add_argument("--pcap", required=True, help="Path to pcap file")
    pcap_cmd.add_argument("--top", type=int, default=10, help="Top N entries to show for IPs/ports")

    #Capture mode
    cap_cmd = sub.add_parser("capture", help="Capture live traffic and analyze it")
    cap_cmd.add_argument("--out", required=True, help="Output pcap path, e.g. captures/out.pcap")
    cap_cmd.add_argument("--count", type=int, default=100, help="Number of packets to capture")
    cap_cmd.add_argument("--iface", default=None, help="Interface name, e.g. 'Wi-Fi', 'eth0', 'wlan0'")
    cap_cmd.add_argument("--bpf", default=None, help="BPF filter, e.g. 'tcp port 80'")
    cap_cmd.add_argument("--timeout", type=int, default=None, help="Seconds to capture")
    cap_cmd.add_argument("--top", type=int, default=10, help="Top N entries to show for IPs/ports")

    return parser

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "pcap":
        run_pcap(args.pcap, top=args.top)
    elif args.cmd == "capture":
        run_capture(args.out, args.count, args.iface, args.bpf, args.timeout, top=args.top)

if __name__ == "__main__":
    main()
