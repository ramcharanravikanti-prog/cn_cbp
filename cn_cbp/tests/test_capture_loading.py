"""
Unit and integration tests for capture loading, error handling, and reporting.
Covers empty captures, malformed files, synthetic capture processing,
and CSV/JSON export integrity.
"""

import json
import pytest
from pathlib import Path

from scripts.generate_test_capture import generate_synthetic_pcap
from src.capture_manager import CaptureLoadingError, CaptureManager
from src.dns_analyzer import DNSAnalyzer
from src.report_generator import ReportGenerator


def test_empty_capture(tmp_path: Path):
    """Test 13: A capture containing 0 bytes raises CaptureLoadingError gracefully."""
    empty_file = tmp_path / "empty.pcap"
    empty_file.touch()

    with pytest.raises(CaptureLoadingError) as exc_info:
        CaptureManager.load_from_path(empty_file)
    assert "empty (0 bytes)" in str(exc_info.value)


def test_malformed_capture(tmp_path: Path):
    """Test 14: A corrupted/malformed file raises CaptureLoadingError gracefully."""
    bad_file = tmp_path / "corrupt.pcap"
    bad_file.write_bytes(b"RANDOM_JUNK_NOT_A_VALID_PCAP_HEADER_1234567890")

    with pytest.raises(CaptureLoadingError) as exc_info:
        CaptureManager.load_from_path(bad_file)
    assert "Failed to read capture file" in str(exc_info.value) or "Unsupported" in str(exc_info.value)


def test_synthetic_capture_loading_and_exports(tmp_path: Path):
    """Test 19: Load synthetic PCAP and validate CSV and JSON exports."""
    pcap_path = tmp_path / "synthetic_test.pcap"
    generate_synthetic_pcap(pcap_path)

    analyzer = DNSAnalyzer()
    result = analyzer.analyze_capture_file(pcap_path)

    assert result.metadata.total_packets >= 10
    assert result.metadata.dns_packets >= 8
    assert len(result.transactions) >= 4
    assert len(result.unmatched_queries) >= 1
    assert len(result.unmatched_responses) >= 1

    # Verify CSV exports
    csv_dir = tmp_path / "csv_out"
    exported_csvs = ReportGenerator.export_csv_datasets(
        result.messages, result.transactions, csv_dir
    )

    expected_files = [
        "dns_messages", "dns_queries", "dns_responses", "dns_transactions",
        "domain_statistics", "query_type_statistics", "response_code_statistics"
    ]
    for key in expected_files:
        assert key in exported_csvs
        assert exported_csvs[key].exists()
        assert exported_csvs[key].stat().st_size > 0

    # Verify JSON export
    json_path = tmp_path / "summary.json"
    ReportGenerator.export_json_summary(
        result.metadata, result.messages, result.transactions,
        result.unmatched_queries, result.unmatched_responses,
        json_path
    )
    assert json_path.exists()
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        assert data["project_title"] == "DNS Traffic Analysis Using Wireshark"
        assert data["packet_counts"]["dns_messages"] > 0
        assert data["correlation_statistics"]["matched_transactions"] > 0

    # Verify Markdown report generation
    md_content = ReportGenerator.generate_markdown_report(
        result.metadata, result.messages, result.transactions,
        result.unmatched_queries, result.unmatched_responses
    )
    assert "# DNS Traffic Analysis Using Wireshark" in md_content
    assert "Experimental Results" in md_content
