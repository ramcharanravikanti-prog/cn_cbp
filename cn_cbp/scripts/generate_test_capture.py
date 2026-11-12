"""
Synthetic Test Capture Generator.
Generates an RFC-compliant test PCAP capture containing varied DNS queries, responses,
errors (NXDOMAIN, SERVFAIL), CNAME chains, retransmissions, and non-DNS packets
strictly for automated testing and test-bench validation.

NOTE: This capture is synthetic and is clearly designated for automated software testing.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap


def generate_synthetic_pcap(output_path: Path) -> Path:
    """
    Builds a synthetic PCAP with realistic DNS scenarios for test suites.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    packets = []
    base_time = 1700000000.0  # reference epoch

    client_ip = "192.168.1.105"
    dns_server = "8.8.8.8"
    client_port = 54321
    dns_port = 53

    # 1. Standard A Query & Response (example.com -> 93.184.216.34)
    # Query
    q1 = Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=client_port, dport=dns_port) / DNS(
        id=0x1001, qr=0, rd=1, qd=DNSQR(qname="example.com", qtype="A")
    )
    q1.time = base_time + 0.100
    packets.append(q1)

    # Response (latency = 18.5 ms)
    r1 = Ether() / IP(src=dns_server, dst=client_ip) / UDP(sport=dns_port, dport=client_port) / DNS(
        id=0x1001, qr=1, rd=1, ra=1, rcode=0,
        qd=DNSQR(qname="example.com", qtype="A"),
        an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=300)
    )
    r1.time = base_time + 0.1185
    packets.append(r1)

    # 2. AAAA (IPv6) Query & Response (wikipedia.org -> 2620:0:862:ed1a::1)
    q2 = Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=client_port + 1, dport=dns_port) / DNS(
        id=0x1002, qr=0, rd=1, qd=DNSQR(qname="wikipedia.org", qtype="AAAA")
    )
    q2.time = base_time + 0.200
    packets.append(q2)

    r2 = Ether() / IP(src=dns_server, dst=client_ip) / UDP(sport=dns_port, dport=client_port + 1) / DNS(
        id=0x1002, qr=1, rd=1, ra=1, rcode=0,
        qd=DNSQR(qname="wikipedia.org", qtype="AAAA"),
        an=DNSRR(rrname="wikipedia.org", type="AAAA", rdata="2620:0:862:ed1a::1", ttl=600)
    )
    r2.time = base_time + 0.2240  # latency = 24.0 ms
    packets.append(r2)

    # 3. CNAME Chain Query & Response (github.com)
    q3 = Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=client_port + 2, dport=dns_port) / DNS(
        id=0x1003, qr=0, rd=1, qd=DNSQR(qname="cdn.github.com", qtype="A")
    )
    q3.time = base_time + 0.300
    packets.append(q3)

    cname_rr = DNSRR(rrname="cdn.github.com", type="CNAME", rdata="github.map.fastly.net", ttl=120)
    a_rr = DNSRR(rrname="github.map.fastly.net", type="A", rdata="140.82.121.4", ttl=120)
    cname_rr.payload = a_rr

    r3 = Ether() / IP(src=dns_server, dst=client_ip) / UDP(sport=dns_port, dport=client_port + 2) / DNS(
        id=0x1003, qr=1, rd=1, ra=1, rcode=0,
        qd=DNSQR(qname="cdn.github.com", qtype="A"),
        an=cname_rr
    )
    r3.time = base_time + 0.3350  # latency = 35.0 ms
    packets.append(r3)

    # 4. MX Query (gmail.com)
    q4 = Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=client_port + 3, dport=dns_port) / DNS(
        id=0x1004, qr=0, rd=1, qd=DNSQR(qname="gmail.com", qtype="MX")
    )
    q4.time = base_time + 0.400
    packets.append(q4)

    r4 = Ether() / IP(src=dns_server, dst=client_ip) / UDP(sport=dns_port, dport=client_port + 3) / DNS(
        id=0x1004, qr=1, rd=1, ra=1, rcode=0,
        qd=DNSQR(qname="gmail.com", qtype="MX"),
        an=DNSRR(rrname="gmail.com", type="MX", rdata="gmail-smtp-in.l.google.com", ttl=3600)
    )
    r4.time = base_time + 0.4120  # latency = 12.0 ms
    packets.append(r4)

    # 5. Non-Existent Domain (NXDOMAIN: RCODE=3)
    q5 = Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=client_port + 4, dport=dns_port) / DNS(
        id=0x1005, qr=0, rd=1, qd=DNSQR(qname="nonexistent-domain-847291.example", qtype="A")
    )
    q5.time = base_time + 0.500
    packets.append(q5)

    r5 = Ether() / IP(src=dns_server, dst=client_ip) / UDP(sport=dns_port, dport=client_port + 4) / DNS(
        id=0x1005, qr=1, rd=1, ra=1, rcode=3,  # NXDOMAIN
        qd=DNSQR(qname="nonexistent-domain-847291.example", qtype="A")
    )
    r5.time = base_time + 0.5450  # latency = 45.0 ms
    packets.append(r5)

    # 6. Server Failure (SERVFAIL: RCODE=2)
    q6 = Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=client_port + 5, dport=dns_port) / DNS(
        id=0x1006, qr=0, rd=1, qd=DNSQR(qname="internal-failed-resolver.test", qtype="A")
    )
    q6.time = base_time + 0.600
    packets.append(q6)

    r6 = Ether() / IP(src=dns_server, dst=client_ip) / UDP(sport=dns_port, dport=client_port + 5) / DNS(
        id=0x1006, qr=1, rd=1, ra=0, rcode=2,  # SERVFAIL
        qd=DNSQR(qname="internal-failed-resolver.test", qtype="A")
    )
    r6.time = base_time + 0.6800  # latency = 80.0 ms
    packets.append(r6)

    # 7. Unanswered Query (Timeout / response dropped)
    q7 = Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=client_port + 6, dport=dns_port) / DNS(
        id=0x1007, qr=0, rd=1, qd=DNSQR(qname="unanswered-timeout.example", qtype="A")
    )
    q7.time = base_time + 0.700
    packets.append(q7)

    # 8. Unmatched Response (Response observed without preceding query in capture)
    r8 = Ether() / IP(src=dns_server, dst=client_ip) / UDP(sport=dns_port, dport=client_port + 7) / DNS(
        id=0x9999, qr=1, rd=1, ra=1, rcode=0,
        qd=DNSQR(qname="unsolicited-reply.example", qtype="A"),
        an=DNSRR(rrname="unsolicited-reply.example", type="A", rdata="198.51.100.42", ttl=300)
    )
    r8.time = base_time + 0.800
    packets.append(r8)

    # 9. Retransmitted Query (Client re-sends query before answer arrives)
    q9_a = Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=client_port + 8, dport=dns_port) / DNS(
        id=0x1009, qr=0, rd=1, qd=DNSQR(qname="slow-service.example", qtype="A")
    )
    q9_a.time = base_time + 1.000
    packets.append(q9_a)

    q9_b = Ether() / IP(src=client_ip, dst=dns_server) / UDP(sport=client_port + 8, dport=dns_port) / DNS(
        id=0x1009, qr=0, rd=1, qd=DNSQR(qname="slow-service.example", qtype="A")
    )
    q9_b.time = base_time + 1.200  # retransmission after 200ms
    packets.append(q9_b)

    r9 = Ether() / IP(src=dns_server, dst=client_ip) / UDP(sport=dns_port, dport=client_port + 8) / DNS(
        id=0x1009, qr=1, rd=1, ra=1, rcode=0,
        qd=DNSQR(qname="slow-service.example", qtype="A"),
        an=DNSRR(rrname="slow-service.example", type="A", rdata="203.0.113.1", ttl=60)
    )
    r9.time = base_time + 1.350  # latency from initial query = 350 ms
    packets.append(r9)

    # 10. Non-DNS Packets (e.g. TCP SYN handshake)
    non_dns_pkt = Ether() / IP(src=client_ip, dst="140.82.121.4") / TCP(sport=55555, dport=443, flags="S")
    non_dns_pkt.time = base_time + 1.500
    packets.append(non_dns_pkt)

    # 11. DNS over TCP
    tcp_q = Ether() / IP(src=client_ip, dst=dns_server) / TCP(sport=50000, dport=53, flags="PA") / DNS(
        id=0x2001, qr=0, rd=1, qd=DNSQR(qname="tcp-dns-lookup.org", qtype="TXT")
    )
    tcp_q.time = base_time + 2.000
    packets.append(tcp_q)

    tcp_r = Ether() / IP(src=dns_server, dst=client_ip) / TCP(sport=53, dport=50000, flags="PA") / DNS(
        id=0x2001, qr=1, rd=1, ra=1, rcode=0,
        qd=DNSQR(qname="tcp-dns-lookup.org", qtype="TXT"),
        an=DNSRR(rrname="tcp-dns-lookup.org", type="TXT", rdata="v=spf1 include:_spf.google.com ~all", ttl=3600)
    )
    tcp_r.time = base_time + 2.040  # latency = 40.0 ms
    packets.append(tcp_r)

    # Write out to file
    wrpcap(str(output_path), packets)
    print(f"Generated synthetic test PCAP with {len(packets)} packets at: {output_path}")
    return output_path


if __name__ == "__main__":
    target = Path(__file__).resolve().parent.parent / "captures" / "synthetic_test_capture.pcap"
    generate_synthetic_pcap(target)
