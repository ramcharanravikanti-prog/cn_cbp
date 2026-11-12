"""
DNS Traffic Analysis Using Wireshark.
Packet-Level Inspection, Statistical Analysis, and Visualization of DNS Traffic.

Streamlit interactive local dashboard.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import List, Optional

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

# Internal analysis modules
from src.dns_analyzer import CaptureAnalysisResult, DNSAnalyzer
from src.report_generator import ReportGenerator
from src.statistics import DNSStatistics
from src.utils import format_latency, format_timestamp, get_rcode_description, sanitize_text
from src.visualizations import (
    plot_latency_distribution,
    plot_outcome_breakdown,
    plot_query_types,
    plot_query_volume_over_time,
    plot_response_codes,
    plot_top_domains,
)

# Page configuration
st.set_page_config(
    page_title="DNS Traffic Analysis Using Wireshark",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling (Dark Slate & Cyan Aesthetic)
CUSTOM_CSS = """
<style>
    /* Global Background and Typography */
    .stApp {
        background-color: #0B1120;
        color: #F8FAFC;
    }
    
    /* Headers */
    h1, h2, h3, h4 {
        color: #F8FAFC !important;
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    }
    
    /* Metric Cards */
    .metric-card {
        background-color: #1E293B;
        border: 1px solid #334155;
        border-radius: 8px;
        padding: 16px 20px;
        margin-bottom: 12px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2);
    }
    .metric-title {
        color: #94A3B8;
        font-size: 0.82rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 6px;
    }
    .metric-value {
        color: #38BDF8;
        font-size: 1.85rem;
        font-weight: 700;
        line-height: 1.2;
    }
    .metric-subtext {
        color: #64748B;
        font-size: 0.75rem;
        margin-top: 4px;
    }

    /* Narrative Box */
    .narrative-box {
        background-color: #1E293B;
        border-left: 4px solid #06B6D4;
        padding: 16px 20px;
        border-radius: 0 8px 8px 0;
        margin-bottom: 20px;
        color: #E2E8F0;
        font-size: 0.95rem;
        line-height: 1.6;
    }

    /* Status Badges */
    .badge-success {
        display: inline-block;
        background-color: rgba(16, 185, 129, 0.2);
        color: #34D399;
        border: 1px solid #059669;
        border-radius: 4px;
        padding: 3px 8px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-warning {
        display: inline-block;
        background-color: rgba(245, 158, 11, 0.2);
        color: #FBBF24;
        border: 1px solid #D97706;
        border-radius: 4px;
        padding: 3px 8px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-info {
        display: inline-block;
        background-color: rgba(6, 182, 212, 0.2);
        color: #38BDF8;
        border: 1px solid #0284C7;
        border-radius: 4px;
        padding: 3px 8px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    /* Code and Pre formatting */
    code {
        color: #38BDF8 !important;
        background-color: #1E293B !important;
    }

    /* Tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
        border-bottom: 1px solid #334155;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 18px;
        color: #94A3B8;
        border-radius: 6px 6px 0 0;
    }
    .stTabs [aria-selected="true"] {
        color: #38BDF8 !important;
        border-bottom: 2px solid #06B6D4 !important;
        font-weight: 600;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_html=True)


@st.cache_resource
def get_analyzer() -> DNSAnalyzer:
    """Returns a cached analyzer instance."""
    return DNSAnalyzer()


def render_metric_card(title: str, value: str, subtext: str = ""):
    """Renders a styled KPI card."""
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-title">{sanitize_text(title)}</div>
            <div class="metric-value">{sanitize_text(value)}</div>
            {f'<div class="metric-subtext">{sanitize_text(subtext)}</div>' if subtext else ''}
        </div>
        """,
        unsafe_allow_html=True
    )


def main():
    analyzer = get_analyzer()

    # Session State Initialization
    if "current_result" not in st.session_state:
        st.session_state.current_result = None
    if "loaded_filename" not in st.session_state:
        st.session_state.loaded_filename = None

    # Application Header
    col_head, col_status = st.columns([3, 1])
    with col_head:
        st.markdown(
            """
            <h1 style='margin-bottom: 0px;'>DNS Traffic Analysis</h1>
            <p style='color: #94A3B8; font-size: 1.05rem; margin-top: 4px; margin-bottom: 20px;'>
                Wireshark Packet Inspection and Statistical Analysis &bull; 
                <span style='color: #06B6D4;'>Packet-Level Inspection, Statistical Analysis, and Visualization of DNS Traffic</span>
            </p>
            """,
            unsafe_allow_html=True
        )

    with col_status:
        if st.session_state.current_result is not None:
            fn = st.session_state.loaded_filename or "Capture"
            st.markdown(
                f"""
                <div style='text-align: right; padding-top: 15px;'>
                    <span class='badge-success'>● CAPTURE LOADED</span><br>
                    <span style='color: #94A3B8; font-size: 0.8rem;'>{sanitize_text(fn)}</span>
                </div>
                """,
                unsafe_allow_html=True
            )
        else:
            st.markdown(
                """
                <div style='text-align: right; padding-top: 15px;'>
                    <span class='badge-warning'>○ NO CAPTURE LOADED</span><br>
                    <span style='color: #94A3B8; font-size: 0.8rem;'>Select or upload a file</span>
                </div>
                """,
                unsafe_allow_html=True
            )

    # Sidebar Controls
    with st.sidebar:
        st.markdown("### 📁 Capture Selection")

        source_type = st.radio(
            "Capture Source:",
            ["Select Existing Capture", "Upload PCAP/PCAPNG"],
            index=0
        )

        capture_to_load = None
        upload_buffer = None

        captures_dir = Path("captures")
        existing_captures = []
        if captures_dir.exists():
            for p in captures_dir.iterdir():
                if p.suffix.lower() in [".pcap", ".pcapng", ".cap"] and p.is_file():
                    existing_captures.append(p)

        if source_type == "Select Existing Capture":
            if existing_captures:
                capture_names = [p.name for p in existing_captures]
                selected_name = st.selectbox("Select local capture file:", capture_names)
                capture_to_load = captures_dir / selected_name
            else:
                st.info("No capture files found in `captures/` folder.")
                st.caption("Run `python scripts/generate_test_capture.py` or place Wireshark files in `captures/`.")
        else:
            upload_buffer = st.file_uploader(
                "Upload a `.pcap` or `.pcapng` file:",
                type=["pcap", "pcapng", "cap"],
                help="Accepts Wireshark captures directly from your local system."
            )

        load_btn = st.button("🚀 Analyze Capture", width="stretch")

        if load_btn:
            try:
                with st.spinner("Parsing packet headers and correlating DNS transactions..."):
                    if source_type == "Select Existing Capture" and capture_to_load:
                        res = analyzer.analyze_capture_file(capture_to_load)
                        st.session_state.current_result = res
                        st.session_state.loaded_filename = capture_to_load.name
                        st.success(f"Loaded {res.metadata.total_packets} packets successfully!")
                        st.rerun()
                    elif source_type == "Upload PCAP/PCAPNG" and upload_buffer:
                        res = analyzer.analyze_capture_buffer(upload_buffer, upload_buffer.name)
                        st.session_state.current_result = res
                        st.session_state.loaded_filename = upload_buffer.name
                        st.success(f"Uploaded and analyzed {upload_buffer.name} successfully!")
                        st.rerun()
                    else:
                        st.warning("Please choose or upload a capture file first.")
            except Exception as e:
                st.error(f"Error loading capture: {e}")

        # Active Filter Controls
        st.markdown("---")
        st.markdown("### 🔍 Filter Controls")

        result: Optional[CaptureAnalysisResult] = st.session_state.current_result

        filter_direction = "All"
        filter_search = ""
        filter_qtypes: List[str] = []
        filter_rcodes: List[str] = []
        filter_protocols: List[str] = []

        if result:
            filter_direction = st.selectbox(
                "Message Direction:",
                ["All", "Queries Only", "Responses Only"]
            )
            filter_search = st.text_input("Domain Search:", placeholder="e.g. example.com")
            
            if result.available_qtypes:
                filter_qtypes = st.multiselect(
                    "Query Types:",
                    result.available_qtypes,
                    default=[]
                )
            if result.available_rcodes:
                filter_rcodes = st.multiselect(
                    "Response Codes:",
                    result.available_rcodes,
                    default=[]
                )
            if result.available_protocols:
                filter_protocols = st.multiselect(
                    "Transport Protocols:",
                    result.available_protocols,
                    default=[]
                )

            if st.button("🔄 Reset Filters", width="stretch"):
                st.rerun()

        st.markdown("---")
        st.markdown("### 📥 Quick Exports")
        if result:
            summary_json_str = json.dumps({
                "project": "DNS Traffic Analysis",
                "capture_file": result.metadata.filename,
                "total_packets": result.metadata.total_packets,
                "dns_messages": len(result.messages),
                "matched_transactions": len(result.transactions),
                "latency_stats": result.latency_stats.to_dict()
            }, indent=2)
            st.download_button(
                "⬇️ Download Summary JSON",
                data=summary_json_str,
                file_name="dns_summary.json",
                mime="application/json",
                width="stretch"
            )
        else:
            st.caption("Load a capture to enable exports.")

    # Main Tabs
    tab_overview, tab_explorer, tab_charts, tab_details, tab_findings, tab_guide = st.tabs([
        "📊 Overview",
        "🔎 DNS Traffic Explorer",
        "📈 Visual Analytics",
        "🔬 Packet Details",
        "📋 Findings & Report",
        "📖 Capture Guide & Setup"
    ])

    if result is None:
        # Empty State Display
        with tab_overview:
            st.info("👋 Welcome to the DNS Traffic Analysis Suite!")
            st.markdown(
                """
                To begin analyzing DNS traffic:
                1. Select an existing capture from the sidebar (or run `python scripts/generate_test_capture.py` to create a sample).
                2. Alternatively, capture live DNS traffic in Wireshark on Windows and upload your `.pcapng` file.
                3. Click **Analyze Capture** to parse packet layers, correlate transactions, and explore metrics.

                *Check the **Capture Guide & Setup** tab above for step-by-step Wireshark collection instructions.*
                """
            )
            # Show empty KPI cards
            c1, c2, c3, c4 = st.columns(4)
            with c1: render_metric_card("Total Packets", "—")
            with c2: render_metric_card("DNS Packets", "—")
            with c3: render_metric_card("DNS Queries", "—")
            with c4: render_metric_card("DNS Responses", "—")
            c5, c6, c7, c8 = st.columns(4)
            with c5: render_metric_card("Unique Domains", "—")
            with c6: render_metric_card("Matched Transactions", "—")
            with c7: render_metric_card("Mean Latency", "—")
            with c8: render_metric_card("NXDOMAIN Responses", "—")

        with tab_guide:
            render_guide_tab()
        return

    # Filter Messages based on sidebar controls
    filtered_messages = DNSAnalyzer.filter_messages(
        messages=result.messages,
        search_domain=filter_search,
        selected_qtypes=filter_qtypes,
        selected_rcodes=filter_rcodes,
        selected_protocols=filter_protocols,
        direction=filter_direction
    )

    filtered_queries = [m for m in filtered_messages if not m.is_response]
    filtered_responses = [m for m in filtered_messages if m.is_response]
    _, _, unique_domains_count = DNSStatistics.compute_domain_frequencies(filtered_queries)

    # -------------------------------------------------------------
    # TAB 1: OVERVIEW
    # -------------------------------------------------------------
    with tab_overview:
        st.markdown("### 📌 Executive Capture Metrics")

        k1, k2, k3, k4 = st.columns(4)
        with k1:
            render_metric_card(
                "Total Packets",
                str(result.metadata.total_packets),
                f"File: {result.metadata.filename}"
            )
        with k2:
            render_metric_card(
                "DNS Packets",
                str(len(result.messages)),
                f"Non-DNS: {result.metadata.non_dns_packets}"
            )
        with k3:
            render_metric_card(
                "DNS Queries",
                str(len(result.queries)),
                "Client lookup requests"
            )
        with k4:
            render_metric_card(
                "DNS Responses",
                str(len(result.responses)),
                "Server reply packets"
            )

        k5, k6, k7, k8 = st.columns(4)
        with k5:
            render_metric_card(
                "Unique Domains",
                str(unique_domains_count),
                "Distinct FQDNs queried"
            )
        with k6:
            render_metric_card(
                "Matched Transactions",
                str(len(result.transactions)),
                f"Retransmissions: {len(result.retransmitted_queries)}"
            )
        with k7:
            lat_mean_str = format_latency(result.latency_stats.mean_ms)
            lat_med_str = format_latency(result.latency_stats.median_ms)
            render_metric_card(
                "Mean Latency",
                lat_mean_str,
                f"Median: {lat_med_str}"
            )
        with k8:
            nx_count = sum(1 for r in result.responses if r.rcode == 3)
            render_metric_card(
                "NXDOMAIN Responses",
                str(nx_count),
                "Non-existent domains"
            )

        st.markdown("### 📝 Capture Analytical Narrative")
        st.markdown(f'<div class="narrative-box">{result.narrative_summary}</div>', unsafe_allow_html=True)

        st.markdown("### 📋 Capture File Information")
        meta_col1, meta_col2 = st.columns(2)
        with meta_col1:
            st.markdown(f"**Capture Filename:** `{result.metadata.filename}`")
            st.markdown(f"**File Size:** `{result.metadata.file_size_bytes / 1024:.2f} KB`")
            st.markdown(f"**Capture Duration:** `{result.metadata.duration_seconds:.3f} seconds`")
        with meta_col2:
            st.markdown(f"**Start Time:** `{result.metadata.start_time_iso}`")
            st.markdown(f"**End Time:** `{result.metadata.end_time_iso}`")
            st.markdown(f"**Unanswered Queries:** `{len(result.unmatched_queries)}` | **Unmatched Responses:** `{len(result.unmatched_responses)}`")

    # -------------------------------------------------------------
    # TAB 2: DNS TRAFFIC EXPLORER
    # -------------------------------------------------------------
    with tab_explorer:
        st.markdown("### 🔎 DNS Message Explorer")
        st.caption(f"Showing {len(filtered_messages)} of {len(result.messages)} total DNS messages based on active filters.")

        if filtered_messages:
            explorer_df = DNSAnalyzer.build_explorer_dataframe(filtered_messages)

            # Pagination / page size
            page_size = st.selectbox("Rows per page:", [25, 50, 100, 250], index=0)
            total_rows = len(explorer_df)
            total_pages = max(1, (total_rows + page_size - 1) // page_size)

            col_p1, col_p2 = st.columns([1, 4])
            with col_p1:
                page_num = st.number_input("Page", min_value=1, max_value=total_pages, value=1, step=1)

            start_idx = (page_num - 1) * page_size
            end_idx = min(start_idx + page_size, total_rows)
            page_slice = explorer_df.iloc[start_idx:end_idx]

            st.dataframe(page_slice, width="stretch", hide_index=True)
            st.caption(f"Displaying rows {start_idx + 1} to {end_idx} of {total_rows}")
        else:
            st.warning("No DNS messages match your active filter criteria.")

    # -------------------------------------------------------------
    # TAB 3: VISUAL ANALYTICS
    # -------------------------------------------------------------
    with tab_charts:
        st.markdown("### 📈 Visual Analytics & Statistical Distributions")
        st.caption("All figures dynamically reflect actual capture data with dedicated captions and empty-state safeguards.")

        # Compute datasets for plots
        domain_df = DNSStatistics.compute_all_domains_dataframe(filtered_messages)
        qtype_df = DNSStatistics.compute_query_type_distribution(filtered_messages)
        rcode_df = DNSStatistics.compute_response_code_distribution(filtered_messages)
        time_series_df = DNSStatistics.compute_time_series_volume(filtered_messages)

        row1_c1, row1_c2 = st.columns(2)
        with row1_c1:
            fig1, cap1 = plot_top_domains(domain_df, top_n=10)
            st.pyplot(fig1)
            st.caption(f"**Interpretation:** {cap1}")

        with row1_c2:
            fig2, cap2 = plot_query_types(qtype_df)
            st.pyplot(fig2)
            st.caption(f"**Interpretation:** {cap2}")

        row2_c1, row2_c2 = st.columns(2)
        with row2_c1:
            fig3, cap3 = plot_response_codes(rcode_df)
            st.pyplot(fig3)
            st.caption(f"**Interpretation:** {cap3}")

        with row2_c2:
            latencies = [t.latency_ms for t in result.transactions if t.latency_ms is not None]
            fig4, cap4 = plot_latency_distribution(latencies)
            st.pyplot(fig4)
            st.caption(f"**Interpretation:** {cap4}")

        row3_c1, row3_c2 = st.columns(2)
        with row3_c1:
            fig5, cap5 = plot_query_volume_over_time(time_series_df)
            st.pyplot(fig5)
            st.caption(f"**Interpretation:** {cap5}")

        with row3_c2:
            nx_count = sum(1 for r in result.responses if r.rcode == 3)
            fig6, cap6 = plot_outcome_breakdown(
                matched_count=len(result.transactions),
                unmatched_queries_count=len(result.unmatched_queries),
                unmatched_responses_count=len(result.unmatched_responses),
                nxdomain_count=nx_count
            )
            st.pyplot(fig6)
            st.caption(f"**Interpretation:** {cap6}")

    # -------------------------------------------------------------
    # TAB 4: PACKET DETAILS
    # -------------------------------------------------------------
    with tab_details:
        st.markdown("### 🔬 Deep Packet Field Inspection")
        st.caption("Select any captured packet to view parsed RFC 1035 protocol headers and correlation findings.")

        if result.messages:
            frame_options = [f"Frame #{m.frame_number}: {m.primary_qname or '<none>'} ({'Response' if m.is_response else 'Query'})" for m in result.messages]
            selected_frame_str = st.selectbox("Select packet to inspect:", frame_options, index=0)
            selected_frame_num = int(selected_frame_str.split(":")[0].replace("Frame #", "").strip())

            msg = next((m for m in result.messages if m.frame_number == selected_frame_num), None)

            if msg:
                st.markdown(
                    f"""
                    <div style='background-color: #1E293B; border: 1px solid #334155; border-radius: 8px; padding: 16px; margin-bottom: 16px;'>
                        <h4 style='margin-top: 0;'>Frame #{msg.frame_number} &bull; {msg.primary_qname or 'Unknown Domain'}</h4>
                        <span class='{"badge-info" if not msg.is_response else "badge-success"}'>{'DNS QUERY' if not msg.is_response else f'DNS RESPONSE ({msg.rcode_name})'}</span>
                        <span class='badge-info'>{msg.transport_protocol}</span>
                        <span style='color: #94A3B8; font-size: 0.85rem; margin-left: 10px;'>Captured at: {msg.timestamp_iso}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )

                d_col1, d_col2 = st.columns(2)
                with d_col1:
                    st.markdown("##### 🌐 Network & Addressing Details")
                    st.write({
                        "Source Address": f"{msg.src_ip}:{msg.src_port}",
                        "Destination Address": f"{msg.dst_ip}:{msg.dst_port}",
                        "IP Version": f"IPv{msg.ip_version}" if msg.ip_version else "Unknown",
                        "Transport Protocol": msg.transport_protocol,
                        "Frame Size": f"{msg.packet_size_bytes} bytes",
                        "DNS Payload Size": f"{msg.dns_payload_bytes} bytes"
                    })

                    st.markdown("##### 🏷️ DNS Header Flags")
                    st.write({
                        "Transaction ID": f"0x{msg.transaction_id:04x} ({msg.transaction_id})",
                        "QR Flag": f"{msg.qr_flag} ({'Response' if msg.is_response else 'Query'})",
                        "Opcode": f"{msg.opcode} (Standard Query)",
                        "Authoritative Answer (AA)": bool(msg.aa),
                        "Truncation Flag (TC)": bool(msg.tc),
                        "Recursion Desired (RD)": bool(msg.rd),
                        "Recursion Available (RA)": bool(msg.ra),
                        "Response Code (RCODE)": f"{msg.rcode} ({msg.rcode_name})"
                    })

                with d_col2:
                    st.markdown("##### ❓ Questions Section")
                    if msg.questions:
                        st.dataframe(pd.DataFrame(msg.questions), width="stretch", hide_index=True)
                    else:
                        st.write("No questions recorded in this packet.")

                    st.markdown("##### 💬 Answers Section")
                    if msg.answers:
                        st.dataframe(pd.DataFrame(msg.answers), width="stretch", hide_index=True)
                    else:
                        st.write("No answer resource records in this packet.")

                    # Correlated transaction info
                    st.markdown("##### 🔗 Query-Response Correlation")
                    matched_t = next((t for t in result.transactions if t.query_frame == msg.frame_number or t.response_frame == msg.frame_number), None)
                    if matched_t:
                        st.success(
                            f"Correlated Transaction! "
                            f"Matched Query Frame #{matched_t.query_frame} with Response Frame #{matched_t.response_frame}. "
                            f"Observed Round-Trip Latency: **{matched_t.latency_ms:.2f} ms**"
                        )
                    else:
                        if not msg.is_response:
                            st.warning("This query has no matching response within the capture window.")
                        else:
                            st.info("This response has no matching query within the capture window.")

                st.caption("ℹ️ *Note: The application presents parsed protocol fields extracted by Scapy, not a raw byte-for-byte hex reconstruction of the frame.*")
        else:
            st.info("No packets to inspect.")

    # -------------------------------------------------------------
    # TAB 5: FINDINGS & REPORT
    # -------------------------------------------------------------
    with tab_findings:
        st.markdown("### 📋 Analytical Findings & Comprehensive Report")

        # Threshold slider for slow responses
        slow_threshold = st.slider(
            "Slow Query Threshold (ms):",
            min_value=20.0, max_value=500.0, value=100.0, step=10.0,
            help="Configurable threshold for flagging high latency lookups. High latency is not inherently malicious."
        )

        slow_tx = [t for t in result.transactions if t.latency_ms > slow_threshold]
        if slow_tx:
            st.warning(
                f"Observed **{len(slow_tx)}** transaction(s) with response latency exceeding {slow_threshold:.1f} ms. "
                "Notice: Slow lookups often stem from cold resolver caches, multi-hop authoritative delegations, or packet loss, "
                "and must not be interpreted as malicious intrusion or exfiltration without independent corroboration."
            )

        st.markdown("#### 📥 Download Complete Deliverables")
        dl_c1, dl_c2, dl_c3 = st.columns(3)

        # Markdown Report Download
        md_report = ReportGenerator.generate_markdown_report(
            metadata=result.metadata,
            messages=result.messages,
            transactions=result.transactions,
            unmatched_queries=result.unmatched_queries,
            unmatched_responses=result.unmatched_responses,
            slow_threshold_ms=slow_threshold
        )
        with dl_c1:
            st.download_button(
                "📄 Download Project Report (.md)",
                data=md_report,
                file_name="project_report.md",
                mime="text/markdown",
                width="stretch"
            )

        # JSON Summary Download
        json_data = json.dumps({
            "metadata": result.metadata.to_dict(),
            "packet_counts": {
                "total_packets": result.metadata.total_packets,
                "dns_messages": len(result.messages),
                "queries": len(result.queries),
                "responses": len(result.responses),
            },
            "latency_statistics": result.latency_stats.to_dict(),
            "narrative_summary": result.narrative_summary
        }, indent=2)
        with dl_c2:
            st.download_button(
                "📊 Download JSON Summary",
                data=json_data,
                file_name="dns_analysis_summary.json",
                mime="application/json",
                width="stretch"
            )

        # Export CSVs button to local outputs/ folder
        with dl_c3:
            if st.button("💾 Export All 7 CSVs to outputs/", width="stretch"):
                out_dir = Path("outputs")
                files = ReportGenerator.export_csv_datasets(
                    result.messages, result.transactions, out_dir
                )
                st.success(f"Exported {len(files)} CSV files into `{out_dir.resolve()}`!")

        # Preview Markdown Report in-dashboard
        with st.expander("📖 Read Academic Project Report In-App", expanded=True):
            st.markdown(md_report)

    # -------------------------------------------------------------
    # TAB 6: CAPTURE GUIDE & SETUP
    # -------------------------------------------------------------
    with tab_guide:
        render_guide_tab()


def render_guide_tab():
    """Renders the Wireshark and Windows capture documentation tab."""
    st.markdown("### 📖 Step-by-Step Wireshark Capture & Windows Setup Guide")
    st.markdown(
        """
        This guide explains how to capture real DNS traffic using Wireshark on Windows,
        generate lookups, save as `.pcapng`, and load into this analysis platform.
        """
    )

    st.markdown("#### 1. Capturing Real Traffic in Wireshark")
    st.markdown(
        """
        1. **Launch Wireshark** on Windows (`Wireshark.exe`).
        2. In the interface list, double-click your active network adapter (**Wi-Fi** or **Ethernet**).
        3. In the Wireshark display filter bar at the top, type `dns` and press Enter (this restricts visible frames to DNS).
        4. Open **PowerShell** or **Command Prompt** and generate test DNS traffic using `nslookup`:
        ```powershell
        nslookup example.com
        nslookup wikipedia.org
        nslookup github.com
        nslookup -type=A example.com
        nslookup -type=AAAA example.com
        nslookup -type=MX gmail.com
        nslookup nonexistent-domain-847291.example
        ```
        5. In Wireshark, click the red **Stop Capture** square button.
        6. Go to **File -> Save As...**, name your file (e.g., `my_dns_traffic.pcapng`), and save it into the project's `captures/` folder.
        7. In this dashboard's sidebar, select your capture and click **Analyze Capture**!
        """
    )

    st.markdown("#### 2. Understanding Real-World Capture Variables")
    st.info(
        """
        - **Local DNS Caching:** If you run `nslookup example.com` twice in a row, the second lookup may be answered 
          from the Windows DNS Cache (`ipconfig /displaydns`) without generating an Ethernet packet. 
          To test fresh queries, clear the cache using `ipconfig /flushdns`.
        - **DNS-over-HTTPS (DoH):** Modern web browsers often route DNS requests through HTTPS over port 443 
          (e.g., Cloudflare `1.1.1.1` or Google `8.8.8.8`). These encrypted packets cannot be parsed as plain DNS 
          without TLS decryption secrets. Use `nslookup` for guaranteed standard UDP/TCP port 53 DNS.
        - **VPNs and Split-Tunneling:** If a VPN is connected, lookups will be routed through the virtual tunnel adapter. 
          Select the VPN adapter in Wireshark to capture those packets.
        """
    )

    st.markdown("#### 3. Windows PowerShell Environment Commands")
    st.code(
        """
# 1. Create a virtual environment
python -m venv .venv

# 2. Activate virtual environment in PowerShell
.\\.venv\\Scripts\\Activate.ps1
# If you encounter ExecutionPolicy errors, run:
# Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# (Alternative Command Prompt activation)
# .venv\\Scripts\\activate.bat

# 3. Install requirements
python -m pip install -r requirements.txt

# 4. Run automated test suite
python -m pytest -v

# 5. Launch the Streamlit dashboard
streamlit run app.py
        """,
        language="powershell"
    )


if __name__ == "__main__":
    main()
