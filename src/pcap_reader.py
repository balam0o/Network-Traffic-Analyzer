from scapy.all import rdpcap

def load_pcap(path):
    packets = rdpcap(path)
    return packets
