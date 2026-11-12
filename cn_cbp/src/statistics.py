"""
Statistical Analysis module for DNS traffic.
Computes latency metrics, domain query frequencies, record type breakdowns,
response code proportions, and generates analytical summaries.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
import pandas as pd

from src.dns_parser import ParsedDNSMessage
from src.query_correlator import MatchedDNSTransaction
from src.utils import get_rcode_description, get_rcode_name


@dataclass
class LatencyStatistics:
    """Detailed response latency statistics in milliseconds."""
    count: int
    mean_ms: Optional[float]
    median_ms: Optional[float]
    min_ms: Optional[float]
    max_ms: Optional[float]
    p95_ms: Optional[float]
    std_dev_ms: Optional[float]
    latencies: List[float] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("latencies", None)  # exclude raw array from small dict export
        return d


@dataclass
class DomainFrequencyItem:
    """Frequency stats for an individual domain."""
    domain: str
    query_count: int
    percentage: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class DNSStatistics:
    """
    Computes statistical distributions and summaries from DNS messages and transactions.
    """

    @staticmethod
    def calculate_latency_stats(transactions: List[MatchedDNSTransaction]) -> LatencyStatistics:
        """
        Calculates mean, median, min, max, p95, and std dev latency for matched transactions.
        """
        if not transactions:
            return LatencyStatistics(
                count=0,
                mean_ms=None,
                median_ms=None,
                min_ms=None,
                max_ms=None,
                p95_ms=None,
                std_dev_ms=None,
                latencies=[]
            )

        latencies = [t.latency_ms for t in transactions if t.latency_ms is not None and t.latency_ms >= 0]
        if not latencies:
            return LatencyStatistics(
                count=0,
                mean_ms=None,
                median_ms=None,
                min_ms=None,
                max_ms=None,
                p95_ms=None,
                std_dev_ms=None,
                latencies=[]
            )

        lat_arr = np.array(latencies, dtype=float)
        count = len(lat_arr)
        mean_val = float(np.mean(lat_arr))
        median_val = float(np.median(lat_arr))
        min_val = float(np.min(lat_arr))
        max_val = float(np.max(lat_arr))
        p95_val = float(np.percentile(lat_arr, 95))
        std_val = float(np.std(lat_arr)) if count > 1 else 0.0

        return LatencyStatistics(
            count=count,
            mean_ms=round(mean_val, 2),
            median_ms=round(median_val, 2),
            min_ms=round(min_val, 2),
            max_ms=round(max_val, 2),
            p95_ms=round(p95_val, 2),
            std_dev_ms=round(std_val, 2),
            latencies=latencies
        )

    @staticmethod
    def compute_domain_frequencies(
        queries: List[ParsedDNSMessage],
        top_n: int = 10
    ) -> Tuple[List[DomainFrequencyItem], int, int]:
        """
        Computes domain query frequencies strictly from query messages.
        Excludes responses.
        Returns:
            - top domains list of DomainFrequencyItem
            - total_queries
            - unique_domains_count
        """
        # Ensure only queries are counted
        valid_queries = [q for q in queries if not q.is_response and q.primary_qname]
        total_queries = len(valid_queries)

        if total_queries == 0:
            return [], 0, 0

        domain_counts = Counter(q.primary_qname for q in valid_queries)
        unique_domains_count = len(domain_counts)

        items: List[DomainFrequencyItem] = []
        for domain, count in domain_counts.most_common(top_n):
            pct = round((count / total_queries) * 100.0, 2)
            items.append(DomainFrequencyItem(domain=domain, query_count=count, percentage=pct))

        return items, total_queries, unique_domains_count

    @staticmethod
    def compute_all_domains_dataframe(queries: List[ParsedDNSMessage]) -> pd.DataFrame:
        """
        Returns a DataFrame of all queried domains with count and percentage.
        """
        valid_queries = [q for q in queries if not q.is_response and q.primary_qname]
        total_queries = len(valid_queries)
        if total_queries == 0:
            return pd.DataFrame(columns=["Domain", "Query Count", "Percentage (%)"])

        domain_counts = Counter(q.primary_qname for q in valid_queries)
        data = []
        for domain, count in domain_counts.most_common():
            pct = round((count / total_queries) * 100.0, 2)
            data.append({"Domain": domain, "Query Count": count, "Percentage (%)": pct})

        return pd.DataFrame(data)

    @staticmethod
    def compute_query_type_distribution(queries: List[ParsedDNSMessage]) -> pd.DataFrame:
        """
        Calculates distribution of requested DNS query types (A, AAAA, MX, etc.).
        """
        valid_queries = [q for q in queries if not q.is_response and q.primary_qtype]
        total = len(valid_queries)
        if total == 0:
            return pd.DataFrame(columns=["Query Type", "Count", "Percentage (%)"])

        type_counts = Counter(q.primary_qtype for q in valid_queries)
        data = []
        for qtype, count in type_counts.most_common():
            pct = round((count / total) * 100.0, 2)
            data.append({"Query Type": qtype, "Count": count, "Percentage (%)": pct})

        return pd.DataFrame(data)

    @staticmethod
    def compute_answer_type_distribution(responses: List[ParsedDNSMessage]) -> pd.DataFrame:
        """
        Calculates distribution of record types actually returned in DNS answers.
        """
        returned_types: List[str] = []
        for r in responses:
            if r.is_response and r.answer_types:
                returned_types.extend(r.answer_types)

        total = len(returned_types)
        if total == 0:
            return pd.DataFrame(columns=["Answer Record Type", "Count", "Percentage (%)"])

        type_counts = Counter(returned_types)
        data = []
        for atype, count in type_counts.most_common():
            pct = round((count / total) * 100.0, 2)
            data.append({"Answer Record Type": atype, "Count": count, "Percentage (%)": pct})

        return pd.DataFrame(data)

    @staticmethod
    def compute_response_code_distribution(responses: List[ParsedDNSMessage]) -> pd.DataFrame:
        """
        Calculates distribution of response codes across all DNS response packets.
        """
        resp_list = [r for r in responses if r.is_response]
        total = len(resp_list)
        if total == 0:
            return pd.DataFrame(columns=["Response Code", "Name", "Count", "Percentage (%)", "Description"])

        rcode_counts = Counter(r.rcode for r in resp_list)
        data = []
        for rcode, count in rcode_counts.most_common():
            name = get_rcode_name(rcode)
            pct = round((count / total) * 100.0, 2)
            desc = get_rcode_description(rcode)
            data.append({
                "Response Code": rcode,
                "Name": name,
                "Count": count,
                "Percentage (%)": pct,
                "Description": desc
            })

        return pd.DataFrame(data)

    @staticmethod
    def compute_transport_protocol_distribution(messages: List[ParsedDNSMessage]) -> pd.DataFrame:
        """
        Calculates distribution between UDP and TCP transport.
        """
        if not messages:
            return pd.DataFrame(columns=["Protocol", "Count", "Percentage (%)"])

        proto_counts = Counter(m.transport_protocol for m in messages)
        total = len(messages)
        data = []
        for proto, count in proto_counts.most_common():
            pct = round((count / total) * 100.0, 2)
            data.append({"Protocol": proto, "Count": count, "Percentage (%)": pct})

        return pd.DataFrame(data)

    @staticmethod
    def compute_time_series_volume(
        queries: List[ParsedDNSMessage],
        bin_seconds: Optional[float] = None
    ) -> pd.DataFrame:
        """
        Computes DNS query counts over time binned by seconds or minutes.
        """
        valid_queries = [q for q in queries if not q.is_response and q.timestamp > 0]
        if not valid_queries:
            return pd.DataFrame(columns=["Timestamp", "Query Count"])

        timestamps = [q.timestamp for q in valid_queries]
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        duration = max_ts - min_ts

        # Automatically determine bin size if not provided
        if bin_seconds is None:
            if duration <= 60:
                bin_seconds = 1.0  # 1-second bins
            elif duration <= 600:
                bin_seconds = 5.0  # 5-second bins
            elif duration <= 3600:
                bin_seconds = 30.0  # 30-second bins
            else:
                bin_seconds = 60.0  # 1-minute bins

        bins = np.arange(min_ts, max_ts + bin_seconds * 1.5, bin_seconds)
        hist, bin_edges = np.histogram(timestamps, bins=bins)

        data = []
        for count, edge in zip(hist, bin_edges[:-1]):
            dt = datetime.fromtimestamp(edge)
            data.append({"Timestamp": dt, "Query Count": int(count)})

        return pd.DataFrame(data)

    @staticmethod
    def generate_narrative_summary(
        total_queries: int,
        unique_domains: int,
        matched_pairs: int,
        median_latency: Optional[float],
        nxdomain_count: int,
        unmatched_queries: int,
        unmatched_responses: int
    ) -> str:
        """
        Generates a concise factual narrative summary of the observed capture.
        """
        if total_queries == 0 and matched_pairs == 0:
            return "The selected capture contains no identifiable DNS query messages or transactions."

        parts = []
        parts.append(f"The capture contains **{total_queries}** DNS query message(s) querying **{unique_domains}** unique domain name(s).")
        
        if matched_pairs > 0 and median_latency is not None:
            parts.append(
                f"A total of **{matched_pairs}** query-response transaction(s) were correlated, "
                f"with a median observed response latency of **{median_latency:.2f} ms**."
            )
        elif matched_pairs > 0:
            parts.append(f"A total of **{matched_pairs}** query-response transaction(s) were correlated.")
        else:
            parts.append("No complete query-response pairs could be matched within the capture window.")

        if nxdomain_count > 0:
            parts.append(f"Observed **{nxdomain_count}** response(s) returning **NXDOMAIN** (Non-Existent Domain).")
        else:
            parts.append("No NXDOMAIN responses were observed.")

        if unmatched_queries > 0:
            parts.append(
                f"There are **{unmatched_queries}** unanswered queries (responses may reside outside the capture window or were cached/unrecorded)."
            )

        if unmatched_responses > 0:
            parts.append(
                f"There are **{unmatched_responses}** unsolicited/unmatched responses without an observed preceding query."
            )

        return " ".join(parts)
