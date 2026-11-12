"""
Unit tests for DNS packet parsing functionality.
Covers queries, responses, record types (A, AAAA, CNAME), RCODEs (NXDOMAIN, SERVFAIL),
capitalization normalization, non-DNS packets, and multi-record payloads.
"""

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from src.dns_parser import DNSParser
from src.utils import normalize_domain


def test_normalize_domain():
    """Test 11: Repeated domain names with different capitalization and trailing dots."""
    assert normalize_domain("Example.COM.") == "example.com"
    assert normalize_domain(b"WikiPedia.ORG.") == "wikipedia.org"
    assert normalize_domain("  sub.DOMAIN.co.uk.  ") == "sub.domain.co.uk"
    assert normalize_domain("") == ""
    assert normalize_domain(None) == ""


def test_valid_dns_query_a():
    """Test 1 & 3: Valid DNS query for A record."""
    pkt = Ether() / IP(src="192.168.1.50", dst="8.8.8.8") / UDP(sport=50001, dport=53) / DNS(
        id=0x1234, qr=0, qd=DNSQR(qname="example.com", qtype="A")
    )
    pkt.time = 1000.0

    msg = DNSParser.parse_packet(pkt, frame_number=1)
    assert msg is not None
    assert msg.frame_number == 1
    assert msg.is_response is False
    assert msg.qr_flag == 0
    assert msg.transaction_id == 0x1234
    assert msg.src_ip == "192.168.1.50"
    assert msg.dst_ip == "8.8.8.8"
    assert msg.src_port == 50001
    assert msg.dst_port == 53
    assert msg.transport_protocol == "UDP"
    assert msg.primary_qname == "example.com"
    assert msg.primary_qtype == "A"
    assert msg.qdcount == 1
    assert msg.ancount == 0


def test_valid_dns_response_aaaa():
    """Test 2 & 4: Valid DNS response for AAAA record."""
    pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=50001) / DNS(
        id=0x1234, qr=1, rcode=0,
        qd=DNSQR(qname="ipv6.example.com", qtype="AAAA"),
        an=DNSRR(rrname="ipv6.example.com", type="AAAA", rdata="2001:db8::1", ttl=3600)
    )
    pkt.time = 1000.025

    msg = DNSParser.parse_packet(pkt, frame_number=2)
    assert msg is not None
    assert msg.is_response is True
    assert msg.qr_flag == 1
    assert msg.rcode == 0
    assert msg.rcode_name == "NOERROR"
    assert msg.primary_qname == "ipv6.example.com"
    assert msg.primary_qtype == "AAAA"
    assert msg.ancount == 1
    assert len(msg.answers) == 1
    assert msg.answers[0]["rdata"] == "2001:db8::1"
    assert msg.answers[0]["ttl"] == 3600


def test_cname_answer_chain():
    """Test 5: CNAME alias record resolution."""
    cname_rr = DNSRR(rrname="alias.example.com", type="CNAME", rdata="target.example.com", ttl=300)
    a_rr = DNSRR(rrname="target.example.com", type="A", rdata="192.0.2.10", ttl=300)
    cname_rr.payload = a_rr

    pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=50002) / DNS(
        id=0x1235, qr=1, rcode=0,
        qd=DNSQR(qname="alias.example.com", qtype="A"),
        an=cname_rr
    )
    pkt.time = 1000.050

    msg = DNSParser.parse_packet(pkt, frame_number=3)
    assert msg is not None
    assert "CNAME" in msg.answer_types
    assert "A" in msg.answer_types
    assert len(msg.answers) == 2
    assert msg.answers[0]["rdata"] == "target.example.com"
    assert msg.answers[1]["rdata"] == "192.0.2.10"


def test_nxdomain_response():
    """Test 6: Non-Existent Domain (NXDOMAIN: RCODE 3)."""
    pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=50003) / DNS(
        id=0x1236, qr=1, rcode=3,
        qd=DNSQR(qname="missing-domain.invalid", qtype="A")
    )
    pkt.time = 1000.080

    msg = DNSParser.parse_packet(pkt, frame_number=4)
    assert msg is not None
    assert msg.rcode == 3
    assert msg.rcode_name == "NXDOMAIN"
    assert msg.ancount == 0


def test_servfail_response():
    """Test 7: Server Failure (SERVFAIL: RCODE 2)."""
    pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=50004) / DNS(
        id=0x1237, qr=1, rcode=2,
        qd=DNSQR(qname="broken-zone.example", qtype="A")
    )
    pkt.time = 1000.100

    msg = DNSParser.parse_packet(pkt, frame_number=5)
    assert msg is not None
    assert msg.rcode == 2
    assert msg.rcode_name == "SERVFAIL"


def test_non_dns_packet():
    """Test 12: Packet without DNS layer returns None."""
    pkt = Ether() / IP(src="192.168.1.50", dst="140.82.121.4") / TCP(sport=54321, dport=443, flags="S")
    msg = DNSParser.parse_packet(pkt, frame_number=6)
    assert msg is None
    assert DNSParser.is_dns_packet(pkt) is False


def test_multiple_questions_and_answers():
    """Test 15: Multiple DNS questions or answers handled safely."""
    q1 = DNSQR(qname="first.example.com", qtype="A")
    q2 = DNSQR(qname="second.example.com", qtype="AAAA")
    q1.payload = q2

    ans1 = DNSRR(rrname="first.example.com", type="A", rdata="1.2.3.4", ttl=60)
    ans2 = DNSRR(rrname="second.example.com", type="AAAA", rdata="::1", ttl=60)
    ans1.payload = ans2

    pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.50") / UDP(sport=53, dport=50005) / DNS(
        id=0x1238, qr=1, rcode=0,
        qdcount=2, ancount=2,
        qd=q1, an=ans1
    )
    pkt.time = 1000.150

    msg = DNSParser.parse_packet(pkt, frame_number=7)
    assert msg is not None
    assert len(msg.questions) >= 1
    assert len(msg.answers) == 2
