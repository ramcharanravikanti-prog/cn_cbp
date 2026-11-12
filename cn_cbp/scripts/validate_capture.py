"""
CLI Capture Validation Tool.
Inspects and validates a PCAP/PCAPNG capture file from the command line,
printing packet counts, DNS transaction summaries, and latency statistics.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.dns_analyzer import DNSAnalyzer


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Inspect and validate a PCAP/PCAPNG file for DNS traffic."
    )
    parser.add_argument("capture_file", type=str, help="Path to .pcap or .pcapng file")
    args = parser.parse_args()

    capture_path = Path(args.capture_file)
    if not capture_path.exists():
        print(f"Error: File '{capture_path}' does not exist.")
        sys.exit(1)

    print(f"\n=======================================================")
    print(f" DNS Traffic Analysis - Capture Validation")
    print(f" Target File: {capture_path.name}")
    print(f"=======================================================")

    analyzer = DNSAnalyzer()
    try:
        result = analyzer.analyze_capture_file(capture_path)
    except Exception as e:
        print(f"Failed to load capture: {e}")
        sys.exit(1)

    meta = result.metadata
    print(f"Total Captured Packets : {meta.total_packets}")
    print(f"DNS Packets Detected   : {meta.dns_packets} ({len(result.queries)} queries, {len(result.responses)} responses)")
    print(f"Non-DNS Packets        : {meta.non_dns_packets}")
    print(f"Capture Duration       : {meta.duration_seconds:.2f} seconds")
    print(f"Start Timestamp        : {meta.start_time_iso}")
    print(f"End Timestamp          : {meta.end_time_iso}")
    print(f"-------------------------------------------------------")
    print(f"Matched Transactions   : {len(result.transactions)}")
    print(f"Unanswered Queries     : {len(result.unmatched_queries)}")
    print(f"Unmatched Responses    : {len(result.unmatched_responses)}")
    print(f"Retransmissions        : {len(result.retransmitted_queries)}")

    lat = result.latency_stats
    if lat.count > 0:
        print(f"Latency (Mean)         : {lat.mean_ms:.2f} ms")
        print(f"Latency (Median)       : {lat.median_ms:.2f} ms")
        print(f"Latency (Min / Max)    : {lat.min_ms:.2f} ms / {lat.max_ms:.2f} ms")
        print(f"Latency (95th %)       : {lat.p95_ms:.2f} ms")
    else:
        print("Latency                : N/A (No matched transactions)")

    print(f"-------------------------------------------------------")
    print(f"Available Query Types  : {', '.join(result.available_qtypes) or 'None'}")
    print(f"Available RCODEs       : {', '.join(result.available_rcodes) or 'None'}")
    print(f"Transport Protocols    : {', '.join(result.available_protocols) or 'None'}")
    print(f"\nNarrative Summary:")
    print(f"{result.narrative_summary}")
    print(f"=======================================================\n")


if __name__ == "__main__":
    main()
