"""
DNS Analyzer Controller module.
Coordinates packet capture loading, message parsing, transaction correlation,
in-memory caching, and multi-criteria filtering.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Dict, List, Optional, Tuple, Union

import pandas as pd

from src.capture_manager import CaptureManager, CaptureMetadata
from src.dns_parser import ParsedDNSMessage
from src.query_correlator import MatchedDNSTransaction, QueryCorrelator
from src.statistics import DNSStatistics, DomainFrequencyItem, LatencyStatistics

logger = logging.getLogger(__name__)


@dataclass
class CaptureAnalysisResult:
    """Holds complete parsed and correlated data from a single capture."""
    metadata: CaptureMetadata
    messages: List[ParsedDNSMessage]
    transactions: List[MatchedDNSTransaction]
    unmatched_queries: List[ParsedDNSMessage]
    unmatched_responses: List[ParsedDNSMessage]
    retransmitted_queries: List[ParsedDNSMessage]
    latency_stats: LatencyStatistics
    narrative_summary: str

    @property
    def queries(self) -> List[ParsedDNSMessage]:
        return [m for m in self.messages if not m.is_response]

    @property
    def responses(self) -> List[ParsedDNSMessage]:
        return [m for m in self.messages if m.is_response]

    @property
    def available_qtypes(self) -> List[str]:
        types = set(m.primary_qtype for m in self.queries if m.primary_qtype)
        return sorted(list(types))

    @property
    def available_rcodes(self) -> List[str]:
        codes = set(m.rcode_name for m in self.responses if m.rcode_name)
        return sorted(list(codes))

    @property
    def available_protocols(self) -> List[str]:
        protos = set(m.transport_protocol for m in self.messages if m.transport_protocol)
        return sorted(list(protos))


class DNSAnalyzer:
    """
    Main analysis controller for DNS traffic.
    Loads captures and caches analysis data for instantaneous UI filtering.
    """

    def __init__(self, max_latency_window_seconds: float = 30.0):
        self.correlator = QueryCorrelator(max_latency_window_seconds=max_latency_window_seconds)
        self.current_result: Optional[CaptureAnalysisResult] = None

    def analyze_capture_file(
        self,
        file_path: Union[str, Path],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> CaptureAnalysisResult:
        """
        Loads and analyzes a capture from a file path.
        """
        metadata, messages = CaptureManager.load_from_path(
            file_path, progress_callback=progress_callback
        )
        return self._process_messages(metadata, messages)

    def analyze_capture_buffer(
        self,
        buffer: BinaryIO,
        filename: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> CaptureAnalysisResult:
        """
        Loads and analyzes an uploaded capture file buffer.
        """
        metadata, messages = CaptureManager.load_from_buffer(
            buffer, filename, progress_callback=progress_callback
        )
        return self._process_messages(metadata, messages)

    def _process_messages(
        self,
        metadata: CaptureMetadata,
        messages: List[ParsedDNSMessage]
    ) -> CaptureAnalysisResult:
        """
        Runs correlation, computes statistics, and packages result.
        """
        matched_tx, unmatched_q, unmatched_r, retx_q = self.correlator.correlate(messages)
        latency_stats = DNSStatistics.calculate_latency_stats(matched_tx)

        queries = [m for m in messages if not m.is_response]
        responses = [m for m in messages if m.is_response]
        _, total_q, unique_d = DNSStatistics.compute_domain_frequencies(queries)

        nxdomain_count = sum(1 for r in responses if r.rcode == 3)

        summary_text = DNSStatistics.generate_narrative_summary(
            total_queries=len(queries),
            unique_domains=unique_d,
            matched_pairs=len(matched_tx),
            median_latency=latency_stats.median_ms,
            nxdomain_count=nxdomain_count,
            unmatched_queries=len(unmatched_q),
            unmatched_responses=len(unmatched_r)
        )

        result = CaptureAnalysisResult(
            metadata=metadata,
            messages=messages,
            transactions=matched_tx,
            unmatched_queries=unmatched_q,
            unmatched_responses=unmatched_r,
            retransmitted_queries=retx_q,
            latency_stats=latency_stats,
            narrative_summary=summary_text
        )

        self.current_result = result
        return result

    @staticmethod
    def filter_messages(
        messages: List[ParsedDNSMessage],
        search_domain: str = "",
        selected_qtypes: Optional[List[str]] = None,
        selected_rcodes: Optional[List[str]] = None,
        selected_protocols: Optional[List[str]] = None,
        direction: str = "All",  # "All", "Queries Only", "Responses Only"
        start_time: Optional[float] = None,
        end_time: Optional[float] = None
    ) -> List[ParsedDNSMessage]:
        """
        Filters messages based on UI criteria.
        """
        filtered = messages

        # Direction filter
        if direction == "Queries Only":
            filtered = [m for m in filtered if not m.is_response]
        elif direction == "Responses Only":
            filtered = [m for m in filtered if m.is_response]

        # Domain search
        if search_domain:
            term = search_domain.strip().lower()
            filtered = [
                m for m in filtered
                if term in m.primary_qname.lower() or any(term in str(ans.get("rdata", "")).lower() for ans in m.answers)
            ]

        # Query type filter
        if selected_qtypes:
            qtypes_set = set(t.upper() for t in selected_qtypes)
            filtered = [m for m in filtered if m.primary_qtype.upper() in qtypes_set]

        # Response code filter
        if selected_rcodes:
            rcodes_set = set(r.upper() for r in selected_rcodes)
            filtered = [m for m in filtered if m.rcode_name.upper() in rcodes_set or not m.is_response]

        # Protocol filter
        if selected_protocols:
            proto_set = set(p.upper() for p in selected_protocols)
            filtered = [m for m in filtered if m.transport_protocol.upper() in proto_set]

        # Time range filter
        if start_time is not None:
            filtered = [m for m in filtered if m.timestamp >= start_time]
        if end_time is not None:
            filtered = [m for m in filtered if m.timestamp <= end_time]

        return filtered

    @staticmethod
    def build_explorer_dataframe(messages: List[ParsedDNSMessage]) -> pd.DataFrame:
        """
        Builds a high-performance tabular DataFrame for the DNS Traffic Explorer.
        """
        if not messages:
            return pd.DataFrame(columns=[
                "Frame", "Timestamp", "Direction", "Source", "Destination",
                "Protocol", "Tx ID", "Domain", "Type", "RCODE", "Answers Count"
            ])

        rows = []
        for m in messages:
            rows.append({
                "Frame": m.frame_number,
                "Timestamp": m.timestamp_iso,
                "Direction": "Response" if m.is_response else "Query",
                "Source": f"{m.src_ip}:{m.src_port}",
                "Destination": f"{m.dst_ip}:{m.dst_port}",
                "Protocol": m.transport_protocol,
                "Tx ID": f"0x{m.transaction_id:04x}" if m.transaction_id else "0x0000",
                "Domain": m.primary_qname or "<none>",
                "Type": m.primary_qtype or "-",
                "RCODE": m.rcode_name if m.is_response else "-",
                "Answers Count": m.ancount
            })

        return pd.DataFrame(rows)
