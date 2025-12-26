import argparse
from pcap_reader import load_pcap
from stats import protocol_stats

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("--pcap", required=True, help="Path to pcap file")
    args = parser.parse_args()

    packets = load_pcap(args.pcap)
    stats = protocol_stats(packets)

    print("Protocol statistics:")
    for proto, count in stats.items():
        print(f"{proto}: {count}")

if __name__ == "__main__":
    main()
