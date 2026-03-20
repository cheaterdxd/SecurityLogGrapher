"""
PyVis Visualization Module
Convert a NetworkX graph to an interactive HTML visualization.
"""
from __future__ import annotations

import logging
import os

import networkx as nx
from pyvis.network import Network

logger = logging.getLogger(__name__)


def render_graph(graph: nx.DiGraph, output_file: str) -> None:
    """
    Convert a NetworkX directed graph into an interactive HTML file using PyVis.

    Each node displays the process name as its label.
    Hovering over a node shows PID and command line info in a tooltip.

    Args:
        graph: NetworkX DiGraph with node attributes:
            label, pid, command_line
        output_file: Path for the output HTML file.
    """
    net = Network(
        height="900px",
        width="100%",
        directed=True,
        bgcolor="#1a1a2e",
        font_color="white",
        notebook=False,
    )

    # Physics configuration for better layout
    net.set_options("""
    {
        "nodes": {
            "font": {
                "size": 14,
                "face": "Segoe UI, sans-serif"
            },
            "shape": "dot",
            "size": 16
        },
        "edges": {
            "arrows": {
                "to": { "enabled": true, "scaleFactor": 0.8 }
            },
            "color": {
                "color": "#4a90d9",
                "highlight": "#ff6b6b"
            },
            "smooth": {
                "type": "cubicBezier",
                "forceDirection": "vertical"
            }
        },
        "physics": {
            "hierarchicalRepulsion": {
                "centralGravity": 0.2,
                "springLength": 150,
                "springConstant": 0.02,
                "nodeDistance": 180
            },
            "solver": "hierarchicalRepulsion"
        },
        "layout": {
            "hierarchical": {
                "enabled": true,
                "direction": "UD",
                "sortMethod": "directed",
                "levelSeparation": 120,
                "nodeSpacing": 150
            }
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 100,
            "navigationButtons": true,
            "keyboard": true
        }
    }
    """)

    # Add nodes
    for node_id, data in graph.nodes(data=True):
        label = data.get("label", str(node_id))
        pid = data.get("pid", "?")
        cmd = data.get("command_line") or "N/A"

        # Truncate long command lines for tooltip
        cmd_display = cmd if len(cmd) <= 200 else cmd[:200] + "..."

        tooltip = f"<b>PID:</b> {pid}<br><b>Command:</b> {cmd_display}"

        # Color root nodes differently (nodes with no incoming edges)
        if graph.in_degree(node_id) == 0:
            color = "#e74c3c"  # Red for root processes
        else:
            color = "#3498db"  # Blue for child processes

        net.add_node(
            node_id,
            label=label,
            title=tooltip,
            color=color,
        )

    # Add edges
    for source, target, data in graph.edges(data=True):
        timestamp = data.get("timestamp", "")
        edge_title = f"CREATED at {timestamp}" if timestamp else "CREATED"
        net.add_edge(source, target, title=edge_title)

    # Ensure output directory exists
    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    net.save_graph(output_file)
    logger.info("Graph saved to %s (%d nodes, %d edges)",
                output_file,
                graph.number_of_nodes(),
                graph.number_of_edges())
