from collections import Counter
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.inet6 import IPv6

def protocol_stats(packets):
    counter = Counter()

    for pkt in packets:
        if TCP in pkt:
            counter["TCP"] += 1
        elif UDP in pkt:
            counter["UDP"] += 1
        elif ICMP in pkt:
            counter["ICMP"] += 1
        else:
            counter["OTHER"] += 1

    return counter

def top_src_ips(packets, n=10):
    c = Counter()
    for pkt in packets:
        if IP in pkt:
            c[pkt[IP].src] += 1
        elif IPv6 in pkt:
            c[pkt[IPv6].src] += 1
    return c.most_common(n)

def top_dst_ips(packets, n=10):
    c = Counter()
    for pkt in packets:
        if IP in pkt:
            c[pkt[IP].dst] += 1
        elif IPv6 in pkt:
            c[pkt[IPv6].dst] += 1
    return c.most_common(n)

def top_src_ports(packets, n=10):
    c = Counter()
    for pkt in packets:
        if TCP in pkt:
            c[f"TCP/{pkt[TCP].sport}"] += 1
        elif UDP in pkt:
            c[f"UDP/{pkt[UDP].sport}"] += 1
    return c.most_common(n)

def top_dst_ports(packets, n=10):
    c = Counter()
    for pkt in packets:
        if TCP in pkt:
            c[f"TCP/{pkt[TCP].dport}"] += 1
        elif UDP in pkt:
            c[f"UDP/{pkt[UDP].dport}"] += 1
    return c.most_common(n)
