from scapy.all import sniff

def capture_packets(count=10):
    packets = sniff(count=count)
    return packets
