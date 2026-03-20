"""
Graph Builder Module
Build a directed process tree graph from normalized events using NetworkX.
"""
from __future__ import annotations

import logging
from typing import Iterable

import networkx as nx

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Builds a directed graph representing parent-child process relationships."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self._event_order: int = 0  # monotonic counter for ordering

    def add_event(self, event: dict) -> None:
        """
        Add a normalized event to the graph.

        Creates parent and child nodes (if not already present)
        and adds a CREATED edge from parent to child.

        Args:
            event: Normalized event dict with keys:
                pid, ppid, process_name, command_line, timestamp, raw_xml
        """
        parent_id = f"pid_{event['ppid']}"
        child_id = f"pid_{event['pid']}"
        ts = event.get("timestamp", "")
        self._event_order += 1

        # Add parent node if not exists (may lack full info)
        if not self.graph.has_node(parent_id):
            self.graph.add_node(
                parent_id,
                label=f"PID {event['ppid']}",
                pid=event["ppid"],
                command_line=None,
                timestamp=ts,           # best estimate: same as child
                event_order=self._event_order - 1,  # slightly before child
                raw_xml=None,
            )

        # Add or update child node with full information
        self.graph.add_node(
            child_id,
            label=event["process_name"],
            pid=event["pid"],
            command_line=event.get("command_line"),
            timestamp=ts,
            event_order=self._event_order,
            raw_xml=event.get("raw_xml"),
        )

        # Add edge: parent → child
        self.graph.add_edge(
            parent_id,
            child_id,
            type="CREATED",
            timestamp=ts,
        )

    def build(self, events: Iterable[dict]) -> nx.DiGraph:
        """
        Iterate over normalized events and build the process graph.

        Args:
            events: Iterable of normalized event dicts.

        Returns:
            NetworkX DiGraph representing the process tree.
        """
        count = 0
        for event in events:
            self.add_event(event)
            count += 1

        logger.info("Built graph with %d nodes and %d edges from %d events",
                     self.graph.number_of_nodes(),
                     self.graph.number_of_edges(),
                     count)
        return self.graph
