from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet

from src.stats import protocol_stats


def make_packet(proto):
    pkt = IP(src="1.1.1.1", dst="2.2.2.2")
    if proto == "TCP":
        return pkt / TCP()
    if proto == "UDP":
        return pkt / UDP()
    return pkt


def test_protocol_stats_counts():
    packets = [
        make_packet("TCP"),
        make_packet("TCP"),
        make_packet("UDP"),
        make_packet("OTHER"),
    ]

    stats = protocol_stats(packets)

    assert stats["TCP"] == 2
    assert stats["UDP"] == 1
    assert stats["OTHER"] == 1

from src.stats import top_src_ips, top_dst_ips


def test_top_src_and_dst_ips():
    packets = [
        IP(src="10.0.0.1", dst="8.8.8.8") / TCP(),
        IP(src="10.0.0.1", dst="8.8.8.8") / TCP(),
        IP(src="10.0.0.2", dst="1.1.1.1") / UDP(),
    ]

    src = dict(top_src_ips(packets, n=2))
    dst = dict(top_dst_ips(packets, n=2))

    assert src["10.0.0.1"] == 2
    assert src["10.0.0.2"] == 1

    assert dst["8.8.8.8"] == 2
    assert dst["1.1.1.1"] == 1

from src.stats import top_dst_ports


def test_top_dst_ports():
    packets = [
        IP() / TCP(dport=80),
        IP() / TCP(dport=80),
        IP() / TCP(dport=443),
        IP() / UDP(dport=53),
    ]

    ports = dict(top_dst_ports(packets, n=3))

    assert ports["TCP/80"] == 2
    assert ports["TCP/443"] == 1
    assert ports["UDP/53"] == 1
