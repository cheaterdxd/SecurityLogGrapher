"""
Matplotlib Visualization Module
Render a NetworkX graph as a static PNG image using matplotlib.
Handles large graphs better than browser-based PyVis.
Layout is sorted top-to-bottom by timestamp (earliest at top).
"""
from __future__ import annotations

import logging
import os
from collections import defaultdict
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import matplotlib.lines as mlines
import networkx as nx

logger = logging.getLogger(__name__)


def _short_label(label: str, max_len: int = 30) -> str:
    """Shorten a label for display, keeping just the executable name."""
    if "\\" in label:
        label = label.rsplit("\\", 1)[-1]
    if "/" in label:
        label = label.rsplit("/", 1)[-1]
    if len(label) > max_len:
        return label[:max_len - 3] + "..."
    return label


def _parse_timestamp(ts: str) -> datetime | None:
    """Parse ISO timestamp strings from Windows Event Log."""
    if not ts:
        return None
    try:
        # Handle formats like "2024-01-15T10:30:00.1234567Z"
        ts = ts.rstrip("Z")
        # Truncate fractional seconds to 6 digits for Python
        if "." in ts:
            base, frac = ts.split(".", 1)
            frac = frac[:6]
            ts = f"{base}.{frac}"
        return datetime.fromisoformat(ts)
    except (ValueError, TypeError):
        return None


def _compute_timeline_positions(graph: nx.DiGraph) -> dict:
    """
    Compute node positions based on timestamps.
    Y-axis = time (top=earliest, bottom=latest).
    X-axis = spread out siblings to avoid overlap.
    """
    # Collect (node, timestamp, event_order) and sort
    node_times = []
    for node, data in graph.nodes(data=True):
        ts = _parse_timestamp(data.get("timestamp", ""))
        order = data.get("event_order", 0)
        node_times.append((node, ts, order))

    # Sort by (timestamp, event_order) — None timestamps go first (parent stubs)
    node_times.sort(key=lambda x: (
        x[1] if x[1] is not None else datetime.min,
        x[2],
    ))

    n = len(node_times)
    if n == 0:
        return {}

    # Assign Y from top to bottom: first event = high Y, last = low Y
    # Group by timestamp to put same-time events at the same Y level
    pos = {}
    y_levels: dict[str, float] = {}  # ts_key → y
    current_y = n  # start high
    x_at_level: dict[float, int] = defaultdict(int)  # y → count

    for node, ts, order in node_times:
        # Create a time key for grouping
        ts_key = ts.isoformat() if ts else f"_order_{order}"

        if ts_key not in y_levels:
            y_levels[ts_key] = current_y
            current_y -= 1

        y = y_levels[ts_key]
        x = x_at_level[y]
        x_at_level[y] += 1
        pos[node] = (x, y)

    # Center X positions per level so the graph looks balanced
    for y_val in set(y for (_, y) in pos.values()):
        nodes_at_y = [n for n, (x, y) in pos.items() if y == y_val]
        count = len(nodes_at_y)
        if count > 1:
            offset = -(count - 1) / 2.0
            for i, n in enumerate(nodes_at_y):
                old_x, old_y = pos[n]
                pos[n] = (offset + i, old_y)

    return pos


def _format_time_label(ts: str) -> str:
    """Format timestamp for axis tick labels."""
    dt = _parse_timestamp(ts)
    if dt is None:
        return ""
    return dt.strftime("%H:%M:%S")


def render_graph_image(
    graph: nx.DiGraph,
    output_file: str,
    width: int = 28,
    height: int = 20,
    dpi: int = 150,
) -> None:
    """
    Render a NetworkX directed graph as a static PNG image.
    Nodes are positioned chronologically top-to-bottom by timestamp.
    """
    if graph.number_of_nodes() == 0:
        logger.warning("Empty graph, nothing to render.")
        return

    n_nodes = graph.number_of_nodes()

    # Scale figure to data
    dynamic_height = max(height, n_nodes * 0.4)
    dynamic_width = max(width, 20)

    fig, ax = plt.subplots(figsize=(dynamic_width, dynamic_height))
    fig.patch.set_facecolor("#0d1117")
    ax.set_facecolor("#0d1117")

    # Compute timeline-based positions
    pos = _compute_timeline_positions(graph)

    # Separate root nodes from child nodes
    root_nodes = [n for n in graph.nodes() if graph.in_degree(n) == 0]
    child_nodes = [n for n in graph.nodes() if graph.in_degree(n) > 0]

    # Draw edges
    nx.draw_networkx_edges(
        graph, pos, ax=ax,
        edge_color="#4a90d9",
        alpha=0.5,
        arrows=True,
        arrowsize=15,
        arrowstyle="-|>",
        connectionstyle="arc3,rad=0.05",
        width=1.2,
    )

    # Draw root nodes (red/orange)
    if root_nodes:
        nx.draw_networkx_nodes(
            graph, pos, nodelist=root_nodes, ax=ax,
            node_color="#e74c3c",
            node_size=350,
            alpha=0.9,
            edgecolors="#ffffff",
            linewidths=1.2,
        )

    # Draw child nodes (blue)
    if child_nodes:
        nx.draw_networkx_nodes(
            graph, pos, nodelist=child_nodes, ax=ax,
            node_color="#3498db",
            node_size=250,
            alpha=0.85,
            edgecolors="#ffffff",
            linewidths=0.6,
        )

    # Labels: show process name + timestamp
    labels = {}
    for node, data in graph.nodes(data=True):
        raw_label = data.get("label", str(node))
        short = _short_label(raw_label)
        ts = data.get("timestamp", "")
        time_str = _format_time_label(ts)
        if time_str:
            labels[node] = f"{short}\n{time_str}"
        else:
            labels[node] = short

    nx.draw_networkx_labels(
        graph, pos, labels, ax=ax,
        font_size=6,
        font_color="#e6e6e6",
        font_family="sans-serif",
    )

    # Add time axis annotation on the left
    # Collect unique Y levels with their timestamps
    y_ts_map: dict[float, str] = {}
    for node, data in graph.nodes(data=True):
        if node in pos:
            y = pos[node][1]
            ts = data.get("timestamp", "")
            if ts and y not in y_ts_map:
                y_ts_map[y] = ts

    if y_ts_map:
        # Get X range for time labels placement
        all_x = [p[0] for p in pos.values()]
        min_x = min(all_x) - 2.5

        for y_val, ts in sorted(y_ts_map.items(), reverse=True):
            time_str = _format_time_label(ts)
            if time_str:
                ax.text(
                    min_x, y_val, time_str,
                    fontsize=7,
                    color="#8b949e",
                    ha="right",
                    va="center",
                    fontfamily="monospace",
                )

    # Legend
    legend_elements = [
        mpatches.Patch(color="#e74c3c", label=f"Root processes ({len(root_nodes)})"),
        mpatches.Patch(color="#3498db", label=f"Child processes ({len(child_nodes)})"),
        mlines.Line2D([], [], color="#4a90d9", marker=">", markersize=8,
                       label="CREATED edge", linestyle="-"),
    ]
    ax.legend(
        handles=legend_elements,
        loc="upper right",
        fontsize=10,
        facecolor="#161b22",
        edgecolor="#30363d",
        labelcolor="#e6e6e6",
    )

    # Title
    ax.set_title(
        f"Process Tree (Timeline)  —  {n_nodes} nodes, {graph.number_of_edges()} edges",
        fontsize=14,
        color="#e6e6e6",
        pad=20,
    )

    # Add a "TIME ↓" indicator
    all_x = [p[0] for p in pos.values()]
    min_x_pos = min(all_x) - 3.5
    all_y = [p[1] for p in pos.values()]
    mid_y = (max(all_y) + min(all_y)) / 2

    ax.annotate(
        "TIME ↓",
        xy=(min_x_pos, mid_y),
        fontsize=11,
        color="#58a6ff",
        ha="center",
        va="center",
        fontweight="bold",
        rotation=90,
    )

    ax.axis("off")
    plt.tight_layout()

    # Ensure output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    plt.savefig(output_file, dpi=dpi, facecolor=fig.get_facecolor(), bbox_inches="tight")
    plt.close(fig)

    logger.info("Graph image saved to %s (%d nodes, %d edges)",
                output_file, n_nodes, graph.number_of_edges())
