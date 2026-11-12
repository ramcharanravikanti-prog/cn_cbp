"""
Unit tests for DNS query-response correlation.
Covers matching pairs, unanswered queries, unsolicited responses,
transaction ID reuse/collision handling, millisecond latency precision,
and prevention of negative latency anomalies.
"""

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from src.dns_parser import DNSParser
from src.query_correlator import QueryCorrelator


def create_query(frame: int, ts: float, txid: int, qname: str, qtype: str = "A", sport: int = 50000):
    pkt = Ether() / IP(src="192.168.1.10", dst="8.8.8.8") / UDP(sport=sport, dport=53) / DNS(
        id=txid, qr=0, qd=DNSQR(qname=qname, qtype=qtype)
    )
    pkt.time = ts
    return DNSParser.parse_packet(pkt, frame_number=frame)


def create_response(frame: int, ts: float, txid: int, qname: str, qtype: str = "A", dport: int = 50000, rcode: int = 0):
    pkt = Ether() / IP(src="8.8.8.8", dst="192.168.1.10") / UDP(sport=53, dport=dport) / DNS(
        id=txid, qr=1, rcode=rcode,
        qd=DNSQR(qname=qname, qtype=qtype),
        an=DNSRR(rrname=qname, type=qtype, rdata="93.184.216.34", ttl=300)
    )
    pkt.time = ts
    return DNSParser.parse_packet(pkt, frame_number=frame)


def test_valid_correlation_and_latency():
    """Test 16: Accurate pairing and latency in milliseconds."""
    correlator = QueryCorrelator()
    q = create_query(frame=1, ts=100.000, txid=0x1111, qname="example.com")
    r = create_response(frame=2, ts=100.0255, txid=0x1111, qname="example.com")  # 25.5 ms

    matched, un_q, un_r, retx = correlator.correlate([q, r])
    assert len(matched) == 1
    assert len(un_q) == 0
    assert len(un_r) == 0
    assert matched[0].transaction_id == 0x1111
    assert matched[0].qname == "example.com"
    # Latency should be 25.5 ms
    assert pytest.approx(matched[0].latency_ms, rel=1e-2) == 25.5


def test_unanswered_query():
    """Test 8: Query without a response in capture window."""
    correlator = QueryCorrelator()
    q = create_query(frame=1, ts=100.000, txid=0x2222, qname="dropped-host.example")

    matched, un_q, un_r, retx = correlator.correlate([q])
    assert len(matched) == 0
    assert len(un_q) == 1
    assert len(un_r) == 0
    assert un_q[0].primary_qname == "dropped-host.example"


def test_unmatched_response():
    """Test 9: Response without a preceding query."""
    correlator = QueryCorrelator()
    r = create_response(frame=1, ts=100.050, txid=0x3333, qname="stray-reply.example")

    matched, un_q, un_r, retx = correlator.correlate([r])
    assert len(matched) == 0
    assert len(un_q) == 0
    assert len(un_r) == 1
    assert un_r[0].primary_qname == "stray-reply.example"


def test_transaction_id_collision():
    """Test 10: Two unrelated queries with same transaction ID must match their own response."""
    correlator = QueryCorrelator()
    # Query 1 for site-a on sport 50001 with txid 0xABCD
    q1 = create_query(frame=1, ts=100.000, txid=0xABCD, qname="site-a.example", sport=50001)
    # Query 2 for site-b on sport 50002 with same txid 0xABCD
    q2 = create_query(frame=2, ts=100.010, txid=0xABCD, qname="site-b.example", sport=50002)

    # Response for Query 2 arrives first
    r2 = create_response(frame=3, ts=100.025, txid=0xABCD, qname="site-b.example", dport=50002)
    # Response for Query 1 arrives later
    r1 = create_response(frame=4, ts=100.040, txid=0xABCD, qname="site-a.example", dport=50001)

    matched, un_q, un_r, retx = correlator.correlate([q1, q2, r2, r1])
    assert len(matched) == 2
    assert len(un_q) == 0
    assert len(un_r) == 0

    tx_a = next(t for t in matched if t.qname == "site-a.example")
    tx_b = next(t for t in matched if t.qname == "site-b.example")

    assert tx_a.client_port == 50001
    assert pytest.approx(tx_a.latency_ms, rel=1e-2) == 40.0

    assert tx_b.client_port == 50002
    assert pytest.approx(tx_b.latency_ms, rel=1e-2) == 15.0


def test_prevention_of_negative_latency():
    """Test 17: Response timestamp before query timestamp must never be matched."""
    correlator = QueryCorrelator()
    # Query at 100.050
    q = create_query(frame=2, ts=100.050, txid=0x4444, qname="anomaly.example")
    # A response with same txid at 100.010 (before query!)
    r = create_response(frame=1, ts=100.010, txid=0x4444, qname="anomaly.example")

    matched, un_q, un_r, retx = correlator.correlate([r, q])
    # The response occurred before query, so it cannot be a valid response to this query
    assert len(matched) == 0
    assert len(un_q) == 1
    assert len(un_r) == 1
