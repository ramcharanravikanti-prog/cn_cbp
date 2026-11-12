"""
Visual Analytics module for DNS traffic analysis.
Generates polished, high-contrast, publication-quality Matplotlib figures
styled for dark theme interfaces, with captions, empty states, and descriptive labels.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

# Design System Colors (Dark Navy / Cyan / Slate Palette)
THEME_BG = "#0B1120"
THEME_CARD_BG = "#1E293B"
THEME_TEXT = "#F8FAFC"
THEME_MUTED = "#94A3B8"
THEME_GRID = "#334155"
THEME_CYAN = "#06B6D4"
THEME_BLUE = "#3B82F6"
THEME_AMBER = "#F59E0B"
THEME_ROSE = "#F43F5E"
THEME_EMERALD = "#10B981"
THEME_PURPLE = "#8B5CF6"


def apply_dark_theme(fig: plt.Figure, ax: plt.Axes) -> None:
    """Applies consistent dark aesthetics to a Matplotlib figure and axis."""
    fig.patch.set_facecolor(THEME_BG)
    ax.set_facecolor(THEME_CARD_BG)
    ax.tick_params(colors=THEME_TEXT, labelsize=9)
    ax.xaxis.label.set_color(THEME_TEXT)
    ax.yaxis.label.set_color(THEME_TEXT)
    ax.title.set_color(THEME_TEXT)
    ax.spines["bottom"].set_color(THEME_GRID)
    ax.spines["top"].set_color(THEME_GRID)
    ax.spines["left"].set_color(THEME_GRID)
    ax.spines["right"].set_color(THEME_GRID)
    ax.grid(True, linestyle="--", alpha=0.3, color=THEME_GRID)


def create_empty_state_figure(title: str, message: str = "No data available in this capture") -> plt.Figure:
    """Renders a graceful empty-state placeholder figure."""
    fig, ax = plt.subplots(figsize=(7, 3.5), dpi=100)
    apply_dark_theme(fig, ax)
    ax.text(
        0.5, 0.5,
        f"{title}\n\n({message})",
        ha="center", va="center",
        color=THEME_MUTED, fontsize=11, fontweight="medium"
    )
    ax.set_xticks([])
    ax.set_yticks([])
    for spine in ax.spines.values():
        spine.set_visible(False)
    fig.tight_layout()
    return fig


def plot_top_domains(domain_df: pd.DataFrame, top_n: int = 10) -> Tuple[plt.Figure, str]:
    """
    Renders a horizontal bar chart of the top queried domains.
    Caption explains the observation and data scope.
    """
    caption = (
        f"Top {top_n} domain names queried by client hosts. "
        "Frequencies are counted strictly from query messages, excluding responses."
    )

    if domain_df.empty or "Domain" not in domain_df.columns:
        return create_empty_state_figure("Top Queried Domains", "No DNS query records found"), caption

    top_df = domain_df.head(top_n).copy()
    if top_df.empty:
        return create_empty_state_figure("Top Queried Domains", "No DNS query records found"), caption

    # Reverse so top item is at the top of the horizontal bar chart
    top_df = top_df.iloc[::-1]

    fig, ax = plt.subplots(figsize=(8, max(4.0, len(top_df) * 0.45)), dpi=100)
    apply_dark_theme(fig, ax)

    bars = ax.barh(top_df["Domain"], top_df["Query Count"], color=THEME_CYAN, edgecolor="#0891B2", height=0.6)

    # Add count labels on ends of bars
    for bar in bars:
        width = bar.get_width()
        ax.text(
            width + max(0.5, width * 0.01),
            bar.get_y() + bar.get_height() / 2,
            f" {int(width)}",
            ha="left", va="center", color=THEME_TEXT, fontsize=9, fontweight="bold"
        )

    ax.set_xlabel("Query Count", fontsize=10, labelpad=8)
    ax.set_ylabel("Domain Name", fontsize=10, labelpad=8)
    ax.set_title(f"Top {len(top_df)} Most Frequently Queried Domains", fontsize=12, fontweight="bold", pad=12)

    max_val = top_df["Query Count"].max()
    ax.set_xlim(0, max_val * 1.15 if max_val > 0 else 10)
    fig.tight_layout()

    return fig, caption


def plot_query_types(query_type_df: pd.DataFrame) -> Tuple[plt.Figure, str]:
    """
    Renders a bar chart of requested DNS query types (e.g. A, AAAA, MX, CNAME).
    """
    caption = (
        "Distribution of DNS query record types requested by clients. "
        "A queries request IPv4 records, AAAA request IPv6, and PTR request reverse lookups."
    )

    if query_type_df.empty or "Query Type" not in query_type_df.columns:
        return create_empty_state_figure("DNS Query-Type Distribution", "No query records found"), caption

    fig, ax = plt.subplots(figsize=(7, 4), dpi=100)
    apply_dark_theme(fig, ax)

    types = query_type_df["Query Type"].tolist()
    counts = query_type_df["Count"].tolist()

    bars = ax.bar(types, counts, color=THEME_BLUE, edgecolor="#2563EB", width=0.55)

    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + max(0.2, height * 0.01),
            f"{int(height)}",
            ha="center", va="bottom", color=THEME_TEXT, fontsize=9, fontweight="bold"
        )

    ax.set_xlabel("DNS Record Type", fontsize=10, labelpad=8)
    ax.set_ylabel("Query Count", fontsize=10, labelpad=8)
    ax.set_title("DNS Query Record-Type Distribution", fontsize=12, fontweight="bold", pad=12)

    max_val = max(counts) if counts else 10
    ax.set_ylim(0, max_val * 1.15 if max_val > 0 else 10)
    fig.tight_layout()

    return fig, caption


def plot_response_codes(rcode_df: pd.DataFrame) -> Tuple[plt.Figure, str]:
    """
    Renders a bar chart of observed DNS response codes (NOERROR, NXDOMAIN, etc.).
    """
    caption = (
        "Proportions of DNS server response codes (RCODE). "
        "NOERROR signifies successful name resolution, while NXDOMAIN denotes non-existent domains."
    )

    if rcode_df.empty or "Name" not in rcode_df.columns:
        return create_empty_state_figure("DNS Response-Code Distribution", "No response records found"), caption

    fig, ax = plt.subplots(figsize=(7, 4), dpi=100)
    apply_dark_theme(fig, ax)

    names = rcode_df["Name"].tolist()
    counts = rcode_df["Count"].tolist()

    # Color code by severity: NOERROR=emerald, NXDOMAIN=amber, SERVFAIL/FORMERR/REFUSED=rose
    colors = []
    for name in names:
        if name == "NOERROR":
            colors.append(THEME_EMERALD)
        elif name == "NXDOMAIN":
            colors.append(THEME_AMBER)
        else:
            colors.append(THEME_ROSE)

    bars = ax.bar(names, counts, color=colors, width=0.5)

    for bar in bars:
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            height + max(0.2, height * 0.01),
            f"{int(height)}",
            ha="center", va="bottom", color=THEME_TEXT, fontsize=9, fontweight="bold"
        )

    ax.set_xlabel("Response Code (RCODE)", fontsize=10, labelpad=8)
    ax.set_ylabel("Response Count", fontsize=10, labelpad=8)
    ax.set_title("DNS Response-Code Distribution", fontsize=12, fontweight="bold", pad=12)

    max_val = max(counts) if counts else 10
    ax.set_ylim(0, max_val * 1.15 if max_val > 0 else 10)
    fig.tight_layout()

    return fig, caption


def plot_latency_distribution(latencies: List[float]) -> Tuple[plt.Figure, str]:
    """
    Renders a histogram of DNS round-trip latency in milliseconds.
    """
    caption = (
        "Histogram of observed DNS query-response round-trip latency in milliseconds (ms). "
        "Measures the network travel and resolver processing time between request and response."
    )

    if not latencies:
        return create_empty_state_figure("Response-Latency Distribution", "No matched transactions available"), caption

    lat_arr = np.array(latencies, dtype=float)
    fig, ax = plt.subplots(figsize=(7, 4), dpi=100)
    apply_dark_theme(fig, ax)

    # Calculate optimal bins
    num_bins = min(30, max(10, int(len(lat_arr) / 3)))
    n, bins, patches = ax.hist(
        lat_arr, bins=num_bins, color=THEME_PURPLE, edgecolor="#7C3AED", alpha=0.85
    )

    # Add vertical median and p95 lines
    median_val = float(np.median(lat_arr))
    p95_val = float(np.percentile(lat_arr, 95))

    ax.axvline(median_val, color=THEME_CYAN, linestyle="--", linewidth=1.8, label=f"Median: {median_val:.1f} ms")
    ax.axvline(p95_val, color=THEME_AMBER, linestyle=":", linewidth=1.8, label=f"95th %: {p95_val:.1f} ms")

    ax.set_xlabel("Round-Trip Latency (ms)", fontsize=10, labelpad=8)
    ax.set_ylabel("Transaction Count", fontsize=10, labelpad=8)
    ax.set_title("DNS Query-Response Latency Distribution", fontsize=12, fontweight="bold", pad=12)
    ax.legend(facecolor=THEME_CARD_BG, edgecolor=THEME_GRID, labelcolor=THEME_TEXT, loc="upper right")

    fig.tight_layout()
    return fig, caption


def plot_query_volume_over_time(time_series_df: pd.DataFrame) -> Tuple[plt.Figure, str]:
    """
    Renders a time-series line chart of DNS query volume over time.
    """
    caption = (
        "Temporal volume of DNS query messages captured over time. "
        "Reveals lookup bursts, query pacing, and idle periods."
    )

    if time_series_df.empty or "Timestamp" not in time_series_df.columns:
        return create_empty_state_figure("DNS Query Volume Over Time", "No timestamped queries available"), caption

    fig, ax = plt.subplots(figsize=(8, 3.8), dpi=100)
    apply_dark_theme(fig, ax)

    x_vals = time_series_df["Timestamp"]
    y_vals = time_series_df["Query Count"]

    ax.plot(x_vals, y_vals, color=THEME_CYAN, linewidth=2.0, marker="o", markersize=4, markerfacecolor=THEME_BLUE)
    ax.fill_between(x_vals, y_vals, color=THEME_CYAN, alpha=0.15)

    ax.set_xlabel("Time", fontsize=10, labelpad=8)
    ax.set_ylabel("Queries / Bin", fontsize=10, labelpad=8)
    ax.set_title("DNS Query Volume Over Time", fontsize=12, fontweight="bold", pad=12)

    # Format datetime axis
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M:%S"))
    fig.autofmt_xdate(rotation=30)
    fig.tight_layout()

    return fig, caption


def plot_outcome_breakdown(
    matched_count: int,
    unmatched_queries_count: int,
    unmatched_responses_count: int,
    nxdomain_count: int
) -> Tuple[plt.Figure, str]:
    """
    Renders a breakdown donut chart of DNS transaction outcomes.
    """
    caption = (
        "Summary breakdown of DNS packet interaction outcomes: successful matches (NOERROR vs errors), "
        "unanswered queries, and unsolicited responses."
    )

    labels = []
    values = []
    colors = []

    # Calculate successful vs error matches
    noerror_matches = max(0, matched_count - nxdomain_count)
    if noerror_matches > 0:
        labels.append("Matched NOERROR")
        values.append(noerror_matches)
        colors.append(THEME_EMERALD)

    if nxdomain_count > 0:
        labels.append("Matched NXDOMAIN")
        values.append(nxdomain_count)
        colors.append(THEME_AMBER)

    if unmatched_queries_count > 0:
        labels.append("Unanswered Queries")
        values.append(unmatched_queries_count)
        colors.append(THEME_BLUE)

    if unmatched_responses_count > 0:
        labels.append("Unmatched Responses")
        values.append(unmatched_responses_count)
        colors.append(THEME_PURPLE)

    if not values:
        return create_empty_state_figure("Transaction Outcomes Breakdown", "No DNS transactions observed"), caption

    fig, ax = plt.subplots(figsize=(6, 4.5), dpi=100)
    fig.patch.set_facecolor(THEME_BG)
    ax.set_facecolor(THEME_BG)

    wedges, texts, autotexts = ax.pie(
        values,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        startangle=140,
        pctdistance=0.75,
        textprops={"color": THEME_TEXT, "fontsize": 9},
        wedgeprops={"edgecolor": THEME_CARD_BG, "linewidth": 2, "width": 0.45}
    )

    for autotext in autotexts:
        autotext.set_color(THEME_TEXT)
        autotext.set_fontweight("bold")

    ax.set_title("DNS Transaction Outcomes Breakdown", fontsize=12, fontweight="bold", color=THEME_TEXT, pad=12)
    fig.tight_layout()

    return fig, caption
