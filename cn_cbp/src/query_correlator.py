"""
DNS Query-Response Correlation Engine.
Accurately pairs DNS query packets with corresponding responses using
5-tuple network addressing, transaction ID, domain name matching, and timestamp causality.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.dns_parser import ParsedDNSMessage
from src.utils import format_latency, format_timestamp

logger = logging.getLogger(__name__)


@dataclass
class MatchedDNSTransaction:
    """Represents a successfully correlated DNS Query-Response pair."""
    transaction_id: int
    query_frame: int
    response_frame: int
    query_timestamp: float
    response_timestamp: float
    latency_ms: float
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    transport_protocol: str
    qname: str
    qtype: str
    rcode: int
    rcode_name: str
    answers: List[Dict[str, Any]] = field(default_factory=list)
    answer_types: List[str] = field(default_factory=list)
    retransmission_count: int = 0
    is_authoritative: bool = False
    is_truncated: bool = False
    is_recursion_desired: bool = False
    is_recursion_available: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["query_time_iso"] = format_timestamp(self.query_timestamp)
        d["response_time_iso"] = format_timestamp(self.response_timestamp)
        d["latency_formatted"] = format_latency(self.latency_ms)
        return d


@dataclass
class CorrelationSummary:
    """Statistical summary of query-response correlation."""
    total_queries: int
    total_responses: int
    matched_transactions: int
    unmatched_queries: int
    unmatched_responses: int
    retransmissions_detected: int
    mean_latency_ms: Optional[float]
    median_latency_ms: Optional[float]
    min_latency_ms: Optional[float]
    max_latency_ms: Optional[float]
    p95_latency_ms: Optional[float]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class QueryCorrelator:
    """
    Correlates DNS queries with their corresponding responses.
    """

    def __init__(self, max_latency_window_seconds: float = 30.0):
        self.max_latency_window_seconds = max_latency_window_seconds

    def correlate(
        self,
        messages: List[ParsedDNSMessage]
    ) -> Tuple[List[MatchedDNSTransaction], List[ParsedDNSMessage], List[ParsedDNSMessage], List[ParsedDNSMessage]]:
        """
        Correlates a chronological sequence of ParsedDNSMessage items.

        Returns:
            - matched_transactions: list of MatchedDNSTransaction
            - unmatched_queries: list of queries with no response
            - unmatched_responses: list of responses with no matching query
            - retransmitted_queries: list of queries identified as retransmissions
        """
        # Sort chronologically by timestamp and frame number
        sorted_messages = sorted(messages, key=lambda m: (m.timestamp, m.frame_number))

        # Active pending queries map:
        # Key: (transaction_id, client_ip, server_ip, client_port, server_port, transport_protocol)
        # Value: list of ParsedDNSMessage
        pending_queries: Dict[Tuple[int, str, str, int, int, str], List[ParsedDNSMessage]] = defaultdict(list)
        retransmission_counts: Dict[int, int] = defaultdict(int)  # keyed by query frame_number

        matched_transactions: List[MatchedDNSTransaction] = []
        unmatched_responses: List[ParsedDNSMessage] = []
        retransmitted_queries: List[ParsedDNSMessage] = []

        total_queries = 0
        total_responses = 0

        for msg in sorted_messages:
            if not msg.is_response:
                # Query message
                total_queries += 1
                q_key = (
                    msg.transaction_id,
                    msg.src_ip,
                    msg.dst_ip,
                    msg.src_port,
                    msg.dst_port,
                    msg.transport_protocol
                )

                # Check if this exact query was already pending (same key and domain)
                is_retransmit = False
                for existing_q in pending_queries[q_key]:
                    if existing_q.primary_qname == msg.primary_qname and existing_q.primary_qtype == msg.primary_qtype:
                        is_retransmit = True
                        retransmission_counts[existing_q.frame_number] += 1
                        retransmitted_queries.append(msg)
                        break

                if not is_retransmit:
                    pending_queries[q_key].append(msg)

            else:
                # Response message
                total_responses += 1
                resp_key = (
                    msg.transaction_id,
                    msg.dst_ip,  # client ip in original query was query.src_ip
                    msg.src_ip,  # server ip in original query was query.dst_ip
                    msg.dst_port,  # client port
                    msg.src_port,  # server port
                    msg.transport_protocol
                )

                candidates = pending_queries.get(resp_key, [])
                matched_query: Optional[ParsedDNSMessage] = None
                matched_idx = -1

                for idx, cand in enumerate(candidates):
                    # Check domain name matching if present in response
                    domain_matches = True
                    if msg.primary_qname and cand.primary_qname:
                        domain_matches = (msg.primary_qname == cand.primary_qname)

                    # Time causality check: response must be after query
                    time_diff = msg.timestamp - cand.timestamp
                    if domain_matches and 0.0 <= time_diff <= self.max_latency_window_seconds:
                        matched_query = cand
                        matched_idx = idx
                        break

                if matched_query is not None and matched_idx >= 0:
                    # Remove from pending queue
                    candidates.pop(matched_idx)
                    if not candidates:
                        del pending_queries[resp_key]

                    latency_ms = max(0.0, (msg.timestamp - matched_query.timestamp) * 1000.0)
                    retx_count = retransmission_counts.get(matched_query.frame_number, 0)

                    # Determine primary qname and qtype from query or response
                    tx_qname = matched_query.primary_qname or msg.primary_qname
                    tx_qtype = matched_query.primary_qtype or msg.primary_qtype

                    transaction = MatchedDNSTransaction(
                        transaction_id=msg.transaction_id,
                        query_frame=matched_query.frame_number,
                        response_frame=msg.frame_number,
                        query_timestamp=matched_query.timestamp,
                        response_timestamp=msg.timestamp,
                        latency_ms=latency_ms,
                        client_ip=matched_query.src_ip,
                        server_ip=matched_query.dst_ip,
                        client_port=matched_query.src_port,
                        server_port=matched_query.dst_port,
                        transport_protocol=msg.transport_protocol,
                        qname=tx_qname,
                        qtype=tx_qtype,
                        rcode=msg.rcode,
                        rcode_name=msg.rcode_name,
                        answers=msg.answers,
                        answer_types=msg.answer_types,
                        retransmission_count=retx_count,
                        is_authoritative=bool(msg.aa),
                        is_truncated=bool(msg.tc),
                        is_recursion_desired=bool(matched_query.rd),
                        is_recursion_available=bool(msg.ra)
                    )
                    matched_transactions.append(transaction)
                else:
                    unmatched_responses.append(msg)

        # Collect all remaining pending queries as unmatched
        unmatched_queries: List[ParsedDNSMessage] = []
        for q_list in pending_queries.values():
            unmatched_queries.extend(q_list)

        # Sort results
        matched_transactions.sort(key=lambda t: t.query_timestamp)
        unmatched_queries.sort(key=lambda q: (q.timestamp, q.frame_number))
        unmatched_responses.sort(key=lambda r: (r.timestamp, r.frame_number))

        return matched_transactions, unmatched_queries, unmatched_responses, retransmitted_queries
