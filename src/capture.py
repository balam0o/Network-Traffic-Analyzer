from scapy.all import sniff, wrpcap

def capture_to_pcap(output_path: str, count: int = 100, iface: str | None = None, bpf_filter: str | None = None, timeout: int | None = None):
    packets = sniff(count=count, iface=iface, filter=bpf_filter, timeout=timeout)
    wrpcap(output_path, packets)
    return len(packets)
