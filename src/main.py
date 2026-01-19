import json
import argparse
from .pcap_reader import load_pcap
from .capture import capture_to_pcap
from .stats import (
    protocol_stats,
    top_src_ips,
    top_dst_ips,
    top_src_ports,
    top_dst_ports,
    throughput_timeseries,  
    tcp_latency_rtt,  
    tcp_loss_stats, 
)

def print_counter(title: str, items, top: int):
    print(f"\n{title} (Top {top}):")
    if not items:
        print("No data found.")
        return
    for key, count in items:
        print(f"{key}: {count}")

def summarize_rtts(rtts_ms): 
    if not rtts_ms: 
        return {"count": 0, "min_ms": None, "max_ms": None, "avg_ms": None} 
    total = sum(rtts_ms)  
    count = len(rtts_ms) 
    return { 
        "count": count,  
        "min_ms": min(rtts_ms),  
        "max_ms": max(rtts_ms),  
        "avg_ms": total / count,  
    } 
def summarize_throughput(series):  
    if not series: 
        return {"buckets": 0, "avg_bps": 0.0, "max_bps": 0.0}  
    bps_values = [item["bps"] for item in series]
    return { 
        "buckets": len(series),  
        "avg_bps": sum(bps_values) / len(bps_values), 
        "max_bps": max(bps_values),
    }  
def build_report(packets, top: int):
    proto = protocol_stats(packets)
    throughput = throughput_timeseries(packets) 
    latency = tcp_latency_rtt(packets)  
    loss = tcp_loss_stats(packets) 
    return {
        "total_packets": len(packets),
        "protocols": dict(proto.most_common()),

        "top_src_ips": pairs_to_objects(top_src_ips(packets, n=top)),
        "top_dst_ips": pairs_to_objects(top_dst_ips(packets, n=top)),

        "top_src_ports": pairs_to_objects(top_src_ports(packets, n=top)),
        "top_dst_ports": pairs_to_objects(top_dst_ports(packets, n=top)),
        "throughput_window_s": 1.0, 
        "throughput": throughput,
        "throughput_summary": summarize_throughput(throughput),
        "tcp_latency_ms": latency, 
        "tcp_latency_summary": {  
            "syn": summarize_rtts(latency["syn_rtt_ms"]), 
            "data": summarize_rtts(latency["data_rtt_ms"]), 
        },  
        "tcp_loss": loss,  
    }

def run_pcap(pcap_path: str, top: int, json_out: str | None):
    packets = load_pcap(pcap_path)

    proto = protocol_stats(packets)
    src_ips_raw = top_src_ips(packets, n=top)
    dst_ips_raw = top_dst_ips(packets, n=top)
    src_ports_raw = top_src_ports(packets, n=top)
    dst_ports_raw = top_dst_ports(packets, n=top)
    throughput = throughput_timeseries(packets) 
    latency = tcp_latency_rtt(packets)  
    loss = tcp_loss_stats(packets)  

    report = {
        "total_packets": len(packets),
        "protocols": dict(proto.most_common()),
        "top_src_ips": pairs_to_objects(src_ips_raw),
        "top_dst_ips": pairs_to_objects(dst_ips_raw),
        "top_src_ports": pairs_to_objects(src_ports_raw),
        "top_dst_ports": pairs_to_objects(dst_ports_raw),
        "throughput_window_s": 1.0, 
        "throughput": throughput,  
        "throughput_summary": summarize_throughput(throughput), 
        "tcp_latency_ms": latency,  
        "tcp_latency_summary": {  
            "syn": summarize_rtts(latency["syn_rtt_ms"]), 
            "data": summarize_rtts(latency["data_rtt_ms"]),  
        }, 
        "tcp_loss": loss, 
    }

    print(f"Analyzing: {pcap_path}")
    print(f"Total packets: {report['total_packets']}")

    print("\nProtocol statistics:")
    for k, v in proto.most_common():
        print(f"{k}: {v}")

    print_counter("Source IPs", src_ips_raw, top)
    print_counter("Destination IPs", dst_ips_raw, top)
    print_counter("Source ports", src_ports_raw, top)
    print_counter("Destination ports", dst_ports_raw, top)
    tp_summary = report["throughput_summary"]  
    print("\nThroughput summary (window=1s):")
    print(f"Buckets: {tp_summary['buckets']}")  
    print(f"Avg bps: {tp_summary['avg_bps']:.2f}")  
    print(f"Max bps: {tp_summary['max_bps']:.2f}")  
    lat_summary = report["tcp_latency_summary"]  
    print("\nTCP RTT summary (ms):")  
    print(f"SYN count: {lat_summary['syn']['count']}")  
    print(f"SYN min: {lat_summary['syn']['min_ms']}")  
    print(f"SYN avg: {lat_summary['syn']['avg_ms']}") 
    print(f"SYN max: {lat_summary['syn']['max_ms']}") 
    print(f"DATA count: {lat_summary['data']['count']}") 
    print(f"DATA min: {lat_summary['data']['min_ms']}")  
    print(f"DATA avg: {lat_summary['data']['avg_ms']}")  
    print(f"DATA max: {lat_summary['data']['max_ms']}") 
    print("\nTCP loss estimate:")  
    print(f"Retransmissions: {report['tcp_loss']['retransmissions']}") 
    print(f"Total segments: {report['tcp_loss']['total_segments']}") 
    print(f"Loss rate: {report['tcp_loss']['loss_rate']:.4f}")

    if json_out:
        with open(json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nSaved JSON report -> {json_out}")

def run_capture(out: str, count: int, iface: str | None, bpf: str | None, timeout: int | None, top: int, json_out: str | None):
    n = capture_to_pcap(out, count=count, iface=iface, bpf_filter=bpf, timeout=timeout)
    print(f"Captured {n} packets -> {out}")
    run_pcap(out, top=top, json_out=json_out)

def build_parser():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    sub = parser.add_subparsers(dest="cmd", required=True)

    #PCAP mode
    pcap_cmd = sub.add_parser("pcap", help="Analyze an existing pcap file")
    pcap_cmd.add_argument("--pcap", required=True, help="Path to pcap file")
    pcap_cmd.add_argument("--top", type=int, default=10, help="Top N entries to show for IPs/ports")
    pcap_cmd.add_argument("--json", default=None, help="Save report to JSON file (e.g. report.json)")

    #Capture mode
    cap_cmd = sub.add_parser("capture", help="Capture live traffic and analyze it")
    cap_cmd.add_argument("--out", required=True, help="Output pcap path, e.g. captures/out.pcap")
    cap_cmd.add_argument("--count", type=int, default=100, help="Number of packets to capture")
    cap_cmd.add_argument("--iface", default=None, help="Interface name, e.g. 'Wi-Fi', 'eth0', 'wlan0'")
    cap_cmd.add_argument("--bpf", default=None, help="BPF filter, e.g. 'tcp port 80'")
    cap_cmd.add_argument("--timeout", type=int, default=None, help="Seconds to capture")
    cap_cmd.add_argument("--top", type=int, default=10, help="Top N entries to show for IPs/ports")
    cap_cmd.add_argument("--json", default=None, help="Save report to JSON file (e.g. report.json)")

    return parser

def pairs_to_objects(pairs):
    return [{"value": k, "count": v} for k, v in pairs]

def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "pcap":
        run_pcap(args.pcap, top=args.top, json_out=args.json)
    elif args.cmd == "capture":
        run_capture(args.out, args.count, args.iface, args.bpf, args.timeout, top=args.top, json_out=args.json)


if __name__ == "__main__":
    main()
