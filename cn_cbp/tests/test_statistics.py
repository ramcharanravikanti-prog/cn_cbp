"""
Unit tests for DNS statistics and visualization helpers.
Verifies domain frequency aggregation (excluding responses), query type distributions,
response code counts, latency statistics, and empty dataset handling.
"""

import pytest
import pandas as pd

from src.dns_parser import ParsedDNSMessage
from src.query_correlator import MatchedDNSTransaction
from src.statistics import DNSStatistics
from src.visualizations import (
    plot_latency_distribution,
    plot_outcome_breakdown,
    plot_query_types,
    plot_query_volume_over_time,
    plot_response_codes,
    plot_top_domains,
)


def make_test_message(frame: int, is_resp: bool, qname: str, qtype: str = "A", rcode: int = 0, rcode_name: str = "NOERROR"):
    return ParsedDNSMessage(
        frame_number=frame,
        timestamp=100.0 + frame * 0.1,
        timestamp_iso="2026-01-01 00:00:00 UTC",
        src_ip="192.168.1.10" if not is_resp else "8.8.8.8",
        dst_ip="8.8.8.8" if not is_resp else "192.168.1.10",
        src_port=50000 if not is_resp else 53,
        dst_port=53 if not is_resp else 50000,
        ip_version=4,
        transport_protocol="UDP",
        transaction_id=frame,
        is_response=is_resp,
        qr_flag=1 if is_resp else 0,
        opcode=0,
        aa=0,
        tc=0,
        rd=1,
        ra=1 if is_resp else 0,
        rcode=rcode if is_resp else 0,
        rcode_name=rcode_name if is_resp else "NOERROR",
        qdcount=1,
        ancount=1 if is_resp else 0,
        nscount=0,
        arcount=0,
        questions=[{"qname": qname, "qtype": qtype}],
        primary_qname=qname,
        primary_qtype=qtype,
        answers=[],
        answer_types=[],
        answer_ttls=[]
    )


def test_domain_frequency_excludes_responses():
    """Domain frequencies must strictly count queries and ignore response packets."""
    msgs = [
        make_test_message(1, is_resp=False, qname="example.com"),
        make_test_message(2, is_resp=False, qname="example.com"),
        make_test_message(3, is_resp=False, qname="wikipedia.org"),
        # Response messages for other domains must NOT be counted as queries
        make_test_message(4, is_resp=True, qname="unwanted-response.org"),
        make_test_message(5, is_resp=True, qname="another-response.net"),
    ]

    items, total_q, unique_d = DNSStatistics.compute_domain_frequencies(msgs)
    assert total_q == 3
    assert unique_d == 2
    assert len(items) == 2
    assert items[0].domain == "example.com"
    assert items[0].query_count == 2
    assert items[0].percentage == 66.67
    assert items[1].domain == "wikipedia.org"
    assert items[1].query_count == 1
    assert items[1].percentage == 33.33


def test_query_and_response_distributions():
    """Verify query type and response code statistical breakdown."""
    queries = [
        make_test_message(1, is_resp=False, qname="a.com", qtype="A"),
        make_test_message(2, is_resp=False, qname="b.com", qtype="A"),
        make_test_message(3, is_resp=False, qname="c.com", qtype="AAAA"),
    ]
    responses = [
        make_test_message(4, is_resp=True, qname="a.com", rcode=0, rcode_name="NOERROR"),
        make_test_message(5, is_resp=True, qname="b.com", rcode=3, rcode_name="NXDOMAIN"),
    ]

    df_qtypes = DNSStatistics.compute_query_type_distribution(queries)
    assert len(df_qtypes) == 2
    a_row = df_qtypes[df_qtypes["Query Type"] == "A"].iloc[0]
    assert a_row["Count"] == 2
    assert pytest.approx(a_row["Percentage (%)"], rel=1e-1) == 66.7

    df_rcodes = DNSStatistics.compute_response_code_distribution(responses)
    assert len(df_rcodes) == 2
    nx_row = df_rcodes[df_rcodes["Name"] == "NXDOMAIN"].iloc[0]
    assert nx_row["Count"] == 1
    assert nx_row["Percentage (%)"] == 50.0


def test_latency_statistics():
    """Verify mean, median, min, max, p95 calculation."""
    tx1 = MatchedDNSTransaction(
        transaction_id=1, query_frame=1, response_frame=2,
        query_timestamp=10.0, response_timestamp=10.010, latency_ms=10.0,
        client_ip="1.1.1.1", server_ip="8.8.8.8", client_port=1, server_port=53,
        transport_protocol="UDP", qname="a.com", qtype="A", rcode=0, rcode_name="NOERROR"
    )
    tx2 = MatchedDNSTransaction(
        transaction_id=2, query_frame=3, response_frame=4,
        query_timestamp=10.0, response_timestamp=10.020, latency_ms=20.0,
        client_ip="1.1.1.1", server_ip="8.8.8.8", client_port=2, server_port=53,
        transport_protocol="UDP", qname="b.com", qtype="A", rcode=0, rcode_name="NOERROR"
    )
    tx3 = MatchedDNSTransaction(
        transaction_id=3, query_frame=5, response_frame=6,
        query_timestamp=10.0, response_timestamp=10.030, latency_ms=30.0,
        client_ip="1.1.1.1", server_ip="8.8.8.8", client_port=3, server_port=53,
        transport_protocol="UDP", qname="c.com", qtype="A", rcode=0, rcode_name="NOERROR"
    )

    stats = DNSStatistics.calculate_latency_stats([tx1, tx2, tx3])
    assert stats.count == 3
    assert stats.mean_ms == 20.0
    assert stats.median_ms == 20.0
    assert stats.min_ms == 10.0
    assert stats.max_ms == 30.0
    assert stats.p95_ms == 29.0


def test_empty_chart_datasets():
    """Test 18: An empty chart dataset must render cleanly without exceptions."""
    empty_df = pd.DataFrame()
    fig1, cap1 = plot_top_domains(empty_df)
    assert fig1 is not None

    fig2, cap2 = plot_query_types(empty_df)
    assert fig2 is not None

    fig3, cap3 = plot_response_codes(empty_df)
    assert fig3 is not None

    fig4, cap4 = plot_latency_distribution([])
    assert fig4 is not None

    fig5, cap5 = plot_query_volume_over_time(empty_df)
    assert fig5 is not None

    fig6, cap6 = plot_outcome_breakdown(0, 0, 0, 0)
    assert fig6 is not None
