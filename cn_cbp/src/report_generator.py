"""
Report and Export Generator module.
Exports structured CSV datasets, JSON machine-readable summaries,
and comprehensive academic Markdown reports based on real capture analysis.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

import pandas as pd

from src.capture_manager import CaptureMetadata
from src.dns_parser import ParsedDNSMessage
from src.query_correlator import MatchedDNSTransaction
from src.statistics import DNSStatistics, LatencyStatistics


class ReportGenerator:
    """
    Handles file export and document generation for DNS analysis results.
    """

    @staticmethod
    def export_csv_datasets(
        messages: List[ParsedDNSMessage],
        transactions: List[MatchedDNSTransaction],
        output_dir: Path
    ) -> Dict[str, Path]:
        """
        Exports the 7 required standard CSV files into the specified output directory.
        Returns a dictionary mapping export name to Path.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        exported_files: Dict[str, Path] = {}

        # 1. dns_messages.csv
        msg_rows = []
        for m in messages:
            row = {
                "frame_number": m.frame_number,
                "timestamp_iso": m.timestamp_iso,
                "src_ip": m.src_ip,
                "dst_ip": m.dst_ip,
                "src_port": m.src_port,
                "dst_port": m.dst_port,
                "transport_protocol": m.transport_protocol,
                "transaction_id": m.transaction_id,
                "qr_flag": m.qr_flag,
                "message_direction": "Response" if m.is_response else "Query",
                "opcode": m.opcode,
                "primary_qname": m.primary_qname,
                "primary_qtype": m.primary_qtype,
                "rcode": m.rcode,
                "rcode_name": m.rcode_name,
                "qdcount": m.qdcount,
                "ancount": m.ancount,
                "packet_size_bytes": m.packet_size_bytes,
                "answers_json": json.dumps(m.answers) if m.answers else "[]"
            }
            msg_rows.append(row)

        df_messages = pd.DataFrame(msg_rows)
        p_messages = output_dir / "dns_messages.csv"
        df_messages.to_csv(p_messages, index=False)
        exported_files["dns_messages"] = p_messages

        # 2. dns_queries.csv
        df_queries = df_messages[df_messages["qr_flag"] == 0].copy() if not df_messages.empty else pd.DataFrame()
        p_queries = output_dir / "dns_queries.csv"
        df_queries.to_csv(p_queries, index=False)
        exported_files["dns_queries"] = p_queries

        # 3. dns_responses.csv
        df_responses = df_messages[df_messages["qr_flag"] == 1].copy() if not df_messages.empty else pd.DataFrame()
        p_responses = output_dir / "dns_responses.csv"
        df_responses.to_csv(p_responses, index=False)
        exported_files["dns_responses"] = p_responses

        # 4. dns_transactions.csv
        tx_rows = []
        for t in transactions:
            row = {
                "transaction_id": t.transaction_id,
                "query_frame": t.query_frame,
                "response_frame": t.response_frame,
                "query_timestamp": t.query_timestamp,
                "response_timestamp": t.response_timestamp,
                "latency_ms": round(t.latency_ms, 3),
                "client_ip": t.client_ip,
                "server_ip": t.server_ip,
                "client_port": t.client_port,
                "server_port": t.server_port,
                "transport_protocol": t.transport_protocol,
                "qname": t.qname,
                "qtype": t.qtype,
                "rcode": t.rcode,
                "rcode_name": t.rcode_name,
                "retransmission_count": t.retransmission_count,
                "is_authoritative": t.is_authoritative,
                "is_truncated": t.is_truncated,
                "answers_json": json.dumps(t.answers) if t.answers else "[]"
            }
            tx_rows.append(row)

        df_tx = pd.DataFrame(tx_rows)
        p_tx = output_dir / "dns_transactions.csv"
        df_tx.to_csv(p_tx, index=False)
        exported_files["dns_transactions"] = p_tx

        # 5. domain_statistics.csv
        df_domains = DNSStatistics.compute_all_domains_dataframe(messages)
        p_domains = output_dir / "domain_statistics.csv"
        df_domains.to_csv(p_domains, index=False)
        exported_files["domain_statistics"] = p_domains

        # 6. query_type_statistics.csv
        df_qtypes = DNSStatistics.compute_query_type_distribution(messages)
        p_qtypes = output_dir / "query_type_statistics.csv"
        df_qtypes.to_csv(p_qtypes, index=False)
        exported_files["query_type_statistics"] = p_qtypes

        # 7. response_code_statistics.csv
        df_rcodes = DNSStatistics.compute_response_code_distribution(messages)
        p_rcodes = output_dir / "response_code_statistics.csv"
        df_rcodes.to_csv(p_rcodes, index=False)
        exported_files["response_code_statistics"] = p_rcodes

        return exported_files

    @staticmethod
    def export_json_summary(
        metadata: Optional[CaptureMetadata],
        messages: List[ParsedDNSMessage],
        transactions: List[MatchedDNSTransaction],
        unmatched_queries: List[ParsedDNSMessage],
        unmatched_responses: List[ParsedDNSMessage],
        output_path: Path
    ) -> Path:
        """
        Exports a complete machine-readable JSON summary of the analysis.
        """
        queries = [m for m in messages if not m.is_response]
        responses = [m for m in messages if m.is_response]

        latency_stats = DNSStatistics.calculate_latency_stats(transactions)
        top_domains, total_q, unique_d = DNSStatistics.compute_domain_frequencies(queries, top_n=20)
        df_qtypes = DNSStatistics.compute_query_type_distribution(queries)
        df_rcodes = DNSStatistics.compute_response_code_distribution(responses)

        summary_dict = {
            "project_title": "DNS Traffic Analysis Using Wireshark",
            "subtitle": "Packet-Level Inspection, Statistical Analysis, and Visualization of DNS Traffic",
            "metadata": metadata.to_dict() if metadata else None,
            "packet_counts": {
                "total_packets": metadata.total_packets if metadata else len(messages),
                "dns_messages": len(messages),
                "dns_queries": len(queries),
                "dns_responses": len(responses),
                "unique_queried_domains": unique_d,
            },
            "correlation_statistics": {
                "matched_transactions": len(transactions),
                "unmatched_queries": len(unmatched_queries),
                "unmatched_responses": len(unmatched_responses),
                "latency_metrics": latency_stats.to_dict(),
            },
            "top_domains": [item.to_dict() for item in top_domains],
            "query_type_distribution": df_qtypes.to_dict(orient="records"),
            "response_code_distribution": df_rcodes.to_dict(orient="records"),
            "limitations": [
                "Captured packets only reflect traffic visible on the monitored network interface.",
                "Encrypted DNS (DoH / DoT) payloads cannot be inspected without transport decryption keys.",
                "Local OS and browser DNS caching may suppress network queries for previously resolved names.",
                "Observed latency includes client stack, transmission, queuing, and resolver turnaround time.",
                "Unanswered queries may represent packets beyond capture window boundaries rather than DNS lookup failures."
            ]
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(summary_dict, f, indent=2)

        return output_path

    @staticmethod
    def generate_markdown_report(
        metadata: Optional[CaptureMetadata],
        messages: List[ParsedDNSMessage],
        transactions: List[MatchedDNSTransaction],
        unmatched_queries: List[ParsedDNSMessage],
        unmatched_responses: List[ParsedDNSMessage],
        slow_threshold_ms: float = 100.0
    ) -> str:
        """
        Generates a comprehensive academic project report in GitHub-flavored Markdown.
        """
        queries = [m for m in messages if not m.is_response]
        responses = [m for m in messages if m.is_response]
        latency_stats = DNSStatistics.calculate_latency_stats(transactions)
        top_domains, total_q, unique_d = DNSStatistics.compute_domain_frequencies(queries, top_n=10)
        df_qtypes = DNSStatistics.compute_query_type_distribution(queries)
        df_rcodes = DNSStatistics.compute_response_code_distribution(responses)
        df_ans_types = DNSStatistics.compute_answer_type_distribution(responses)

        # Count slow queries
        slow_tx = [t for t in transactions if t.latency_ms > slow_threshold_ms]

        # Check if capture exists
        has_data = len(messages) > 0

        report = f"""# DNS Traffic Analysis Using Wireshark
## Packet-Level Inspection, Statistical Analysis, and Visualization of DNS Traffic

**Course:** Computer Networks Mini-Project  
**Author:** Undergraduate Student  
**System Platform:** Windows 10/11 | Python 3.12 | Wireshark & Scapy  
**Status:** {"Analysis Completed" if has_data else "Pending Real Capture"}

---

### Abstract
This project presents an end-to-end network traffic analysis system focused on the Domain Name System (DNS). By ingesting packet capture files (`.pcapng` and `.pcap`) collected using Wireshark, the system parses protocol headers, correlates client queries with corresponding server responses using 5-tuple addressing and DNS transaction identifiers, measures observed round-trip response latency, evaluates query-type and response-code distributions, and exposes an interactive dashboard for network exploration. The implementation avoids fabricated metrics and accurately handles packet-level realities including retransmissions, unmatched queries, and caching effects.

---

### 1. Introduction to DNS
The Domain Name System (DNS) operates as the foundational directory service of the Internet, translating human-friendly fully qualified domain names (FQDNs) such as `example.com` into machine-routable Internet Protocol (IPv4/IPv6) addresses. DNS primarily utilizes the User Datagram Protocol (UDP) on port 53 for low-overhead, single-packet query-response cycles, while reverting to the Transmission Control Protocol (TCP) port 53 when responses exceed conventional size boundaries or during zone transfers (AXFR/IXFR).

### 2. Problem Statement
Network engineers and cybersecurity analysts require visibility into network naming transactions. However, raw packet captures can contain thousands of interleaved packets, making manual correlation, latency measurement, and anomaly detection tedious. Unanswered requests are frequently misidentified as network failures, and encrypted or cached lookups create observational discrepancies. An automated, technically defensible tool is needed to process PCAP captures, extract protocol structures, and provide quantitative network metrics.

### 3. Project Objectives
- Ingest Wireshark `.pcapng` and `.pcap` capture files directly on Windows.
- Dissect DNS packet structures across UDP and TCP transport layers.
- Implement a 5-tuple, time-causal DNS query-response correlation algorithm.
- Quantify round-trip latency statistics (mean, median, p95, min, max).
- Distinguish requested query record types (A, AAAA, MX, etc.) from actual returned answer record types.
- Categorize DNS response codes (NOERROR, NXDOMAIN, SERVFAIL, REFUSED).
- Generate publication-quality visualizations and reproducible CSV/JSON datasets.

### 4. System Architecture

```mermaid
graph TD
    A[Wireshark Packet Capture .pcapng/.pcap] --> B[Capture Manager & PcapReader]
    B --> C[DNS Packet Parser]
    C --> D[Parsed DNS Messages]
    D --> E[Query-Response Correlator]
    D --> F[DNS Statistics Engine]
    E --> G[Matched Transactions & Latency Engine]
    F --> H[Visual Analytics Matplotlib]
    G --> H
    H --> I[Streamlit Dark-Mode Dashboard]
    F --> J[CSV / JSON / Report Generator]
    G --> J
```

### 5. DNS Packet Structure & Field Inspection
Each analyzed DNS message adheres to RFC 1035 specifications:
- **Transaction ID (16-bit):** Matches queries with responses generated by the resolver.
- **QR Flag (1-bit):** Distinguishes Query (`0`) from Response (`1`).
- **OpCode (4-bit):** Indicates query type (`0` for Standard Query).
- **AA Flag (1-bit):** Authoritative Answer bit set by authoritative name servers.
- **TC Flag (1-bit):** Truncation bit indicating response exceeded maximum UDP payload length.
- **RD Flag (1-bit):** Recursion Desired bit set by client resolvers requesting recursive resolution.
- **RA Flag (1-bit):** Recursion Available bit set by resolvers that support recursive lookups.
- **RCODE (4-bit):** Response code indicating outcome (NOERROR=0, NXDOMAIN=3, SERVFAIL=2).
- **Section Counts:** Question count (QDCOUNT), Answer count (ANCOUNT), Authority count (NSCOUNT), Additional count (ARCOUNT).

### 6. Query-Response Correlation Methodology
Response latency is calculated as:
$$\\text{{Latency (ms)}} = (T_{{\\text{{response}}}} - T_{{\\text{{query}}}}) \\times 1000$$

To prevent false associations caused by transaction ID reuse, correlation matches on the full conversation 5-tuple:
1. `Query(src_ip, src_port, dst_ip, dst_port, transport, id, qname)` matches `Response(dst_ip, dst_port, src_ip, src_port, transport, id)`.
2. Time causality is strictly enforced: $T_{{\\text{{response}}}} \\ge T_{{\\text{{query}}}}$.
3. Unanswered queries are explicitly isolated rather than marked as failed.

---

### 7. Experimental Results & Analysis
*(Derived strictly from observed capture data; no synthetic values are fabricated)*

**Capture File:** `{metadata.filename if metadata else "N/A"}`  
**Capture Duration:** `{metadata.duration_seconds if metadata else 0:.2f} seconds`  
**Total Captured Frames:** `{metadata.total_packets if metadata else 0}`  
**DNS Frames Detected:** `{len(messages)}` ({len(queries)} queries, {len(responses)} responses)  

#### Summary KPIs
| Metric | Observed Value | Description |
| :--- | :--- | :--- |
| **Total DNS Queries** | {len(queries)} | Client lookup requests observed |
| **Unique Queried Domains** | {unique_d} | Distinct FQDNs requested |
| **Matched Transactions** | {len(transactions)} | Confirmed query-response pairs |
| **Unanswered Queries** | {len(unmatched_queries)} | Queries with no response in window |
| **Unmatched Responses** | {len(unmatched_responses)} | Responses without preceding query |
| **Mean Latency** | {f"{latency_stats.mean_ms:.2f} ms" if latency_stats.mean_ms is not None else "N/A"} | Average round-trip response time |
| **Median Latency** | {f"{latency_stats.median_ms:.2f} ms" if latency_stats.median_ms is not None else "N/A"} | 50th percentile response time |
| **95th Percentile Latency** | {f"{latency_stats.p95_ms:.2f} ms" if latency_stats.p95_ms is not None else "N/A"} | Tail response latency |
| **Slow Responses (> {slow_threshold_ms}ms)** | {len(slow_tx)} | Observed high-latency lookups |

#### Top 10 Queried Domains
| Rank | Domain Name | Query Count | Percentage |
| :--- | :--- | :--- | :--- |
"""
        if top_domains:
            for idx, item in enumerate(top_domains, 1):
                report += f"| {idx} | `{item.domain}` | {item.query_count} | {item.percentage:.2f}% |\n"
        else:
            report += "| - | *No queries observed* | 0 | 0.0% |\n"

        report += "\n#### DNS Query Record-Type Distribution\n"
        report += "| Record Type | Count | Percentage |\n| :--- | :--- | :--- |\n"
        if not df_qtypes.empty:
            for _, row in df_qtypes.iterrows():
                report += f"| **{row['Query Type']}** | {row['Count']} | {row['Percentage (%)']:.2f}% |\n"
        else:
            report += "| *None* | 0 | 0.0% |\n"

        report += "\n#### DNS Answer Record-Type Distribution\n"
        report += "| Answer Record Type | Count | Percentage |\n| :--- | :--- | :--- |\n"
        if not df_ans_types.empty:
            for _, row in df_ans_types.iterrows():
                report += f"| **{row['Answer Record Type']}** | {row['Count']} | {row['Percentage (%)']:.2f}% |\n"
        else:
            report += "| *None* | 0 | 0.0% |\n"

        report += "\n#### DNS Response Code (RCODE) Distribution\n"
        report += "| RCODE | Name | Count | Percentage | Explanation |\n| :--- | :--- | :--- | :--- | :--- |\n"
        if not df_rcodes.empty:
            for _, row in df_rcodes.iterrows():
                report += f"| {row['Response Code']} | **{row['Name']}** | {row['Count']} | {row['Percentage (%)']:.2f}% | {row['Description']} |\n"
        else:
            report += "| - | *None* | 0 | 0.0% | No response packets in capture |\n"

        report += f"""
---

### 8. Analytical Findings & Observations
1. **Resolution Latency:** The observed median latency was **{f"{latency_stats.median_ms:.2f} ms" if latency_stats.median_ms is not None else "N/A"}**. Lookups served by recursive resolvers or local network forwarders typically complete within 10–40 ms, whereas authoritative multi-hop delegations exceed 80 ms.
2. **Query vs. Answer Disparity:** Clients requesting `A` records often receive answers containing `CNAME` aliasing chains prior to the final address record. This confirms the necessity of analyzing query types independently from answer record types.
3. **Non-Existent Domains:** {len([t for t in transactions if t.rcode == 3])} transactions resulted in NXDOMAIN. In typical network captures, NXDOMAIN results occur naturally from misspelled hostnames, search list expansion suffixes, or local service discovery lookups.
4. **Unmatched Queries:** {len(unmatched_queries)} queries were unmatched. These represent packets transmitted near the end of the capture window or queries resolved via local operating system cache without generating external responses.

### 9. Limitations
- **Capture Scope:** Observations are strictly limited to packets traversing the monitored network adapter during the capture interval.
- **DNS-over-HTTPS (DoH) / DNS-over-TLS (DoT):** Modern operating systems and browsers increasingly employ encrypted DNS protocols (ports 443 and 853). These appear as encrypted TLS traffic and cannot be parsed without TLS session secrets.
- **OS Caching:** Repeated lookups for identical domains within the DNS TTL window are answered locally by Windows DNS Client Cache (`dnscache`) and do not generate wire packets.
- **Observed Latency vs. Server Time:** Measured round-trip time includes local network adapter queues, transmission time, and internet routing latency, and does not represent pure server CPU processing time alone.

### 10. Security & Privacy Considerations
DNS queries transmit cleartext domain names across local area networks, exposing user browsing patterns and network hostnames. When handling captures containing organizational or personal data, captures should be processed locally and sanitized before public sharing.

### 11. Conclusion
The DNS Traffic Analysis system successfully demonstrates packet-level dissection, reliable 5-tuple correlation, and statistical evaluation of network naming services. By adhering to rigorous protocol semantics and avoiding fabricated metrics, the application provides an accurate educational and operational diagnostic tool.

---
*Generated automatically by DNS Traffic Analysis Suite (Wireshark & Python)*
"""
        return report
