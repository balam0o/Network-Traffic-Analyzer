from collections import Counter, defaultdict  
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

def _flow_key(pkt):  
    if IP in pkt:  
        src = (pkt[IP].src, pkt[TCP].sport)  
        dst = (pkt[IP].dst, pkt[TCP].dport) 
    elif IPv6 in pkt:  
        src = (pkt[IPv6].src, pkt[TCP].sport)  
        dst = (pkt[IPv6].dst, pkt[TCP].dport)  
    else:  
        return None  
    return (src, dst)  
def _pkt_time(pkt):  
    return float(pkt.time)  
def throughput_timeseries(packets, window_s=1.0):  
    series = defaultdict(int)  
    if not packets:  
        return []  
    for pkt in packets:  
        if not hasattr(pkt, "time"):
            continue  
        t = _pkt_time(pkt)  
        bucket = int(t // window_s)  
        series[bucket] += len(pkt)  
    return sorted(  
        ({"bucket": k, "bytes": v, "bps": float(v / window_s)} for k, v in series.items()),  
        key=lambda x: x["bucket"],  
    )  
def tcp_latency_rtt(packets):  
    syn_times = {}  
    data_times = {}  
    rtts_syn = []  
    rtts_data = []  
    for pkt in packets:  
        if TCP not in pkt:  
            continue  
        key = _flow_key(pkt)  
        if key is None:  
            continue  
        t = _pkt_time(pkt)  
        tcp = pkt[TCP]  
        if (tcp.flags & 0x02) and not (tcp.flags & 0x10):
            syn_times[key] = t  
        elif (tcp.flags & 0x12) == 0x12:  
            rev_key = (key[1], key[0])  
            if rev_key in syn_times:  
                rtts_syn.append(float(t - syn_times[rev_key])) 
        payload_len = len(tcp.payload)  
        if payload_len > 0: 
            seg_key = (key, tcp.seq, payload_len)  
            data_times[seg_key] = t  
        elif tcp.flags & 0x10:  
            ack = tcp.ack  
            for seg_key, sent_t in list(data_times.items()): 
                skey, seq, plen = seg_key  
                if skey == (key[1], key[0]) and ack >= seq + plen:  
                    rtts_data.append(float(t - sent_t)) 
                    del data_times[seg_key]  
    return {  
        "syn_rtt_ms": [float(r * 1000) for r in rtts_syn],  
        "data_rtt_ms": [float(r * 1000) for r in rtts_data],  
    }  
def tcp_loss_stats(packets):  
    seen = set() 
    retrans = 0  
    total_data = 0  
    for pkt in packets:  
        if TCP not in pkt:  
            continue  
        key = _flow_key(pkt)  
        if key is None:  
            continue  
        tcp = pkt[TCP]  
        payload_len = len(tcp.payload)  
        if payload_len == 0: 
            continue 
        total_data += 1 
        seg_id = (key, tcp.seq, payload_len)  
        if seg_id in seen: 
            retrans += 1 
        else:  
            seen.add(seg_id)  
    loss_rate = (retrans / total_data) if total_data else 0.0 
    return {"retransmissions": retrans, "total_segments": total_data, "loss_rate": loss_rate}
