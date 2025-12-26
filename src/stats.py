from collections import Counter
from scapy.layers.inet import TCP, UDP, ICMP

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
