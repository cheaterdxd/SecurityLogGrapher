"""
Tests for the Graph Builder module.
"""
import pytest
import networkx as nx

from threatgraph.graph.builder import GraphBuilder


def make_event(pid, ppid, name="test.exe", cmd=None, ts="2024-01-01T00:00:00Z"):
    """Helper to create a normalized event dict."""
    return {
        "pid": pid,
        "ppid": ppid,
        "process_name": name,
        "command_line": cmd,
        "timestamp": ts,
    }


class TestGraphBuilder:
    """Tests for GraphBuilder class."""

    def test_single_event_creates_two_nodes_one_edge(self):
        builder = GraphBuilder()
        event = make_event(pid=1234, ppid=1000, name="cmd.exe", cmd="cmd /c dir")
        builder.add_event(event)

        g = builder.graph
        assert g.number_of_nodes() == 2
        assert g.number_of_edges() == 1
        assert g.has_node("pid_1000")
        assert g.has_node("pid_1234")
        assert g.has_edge("pid_1000", "pid_1234")

    def test_child_node_has_correct_attributes(self):
        builder = GraphBuilder()
        event = make_event(pid=100, ppid=50, name="powershell.exe", cmd="ps -enc X")
        builder.add_event(event)

        data = builder.graph.nodes["pid_100"]
        assert data["label"] == "powershell.exe"
        assert data["pid"] == 100
        assert data["command_line"] == "ps -enc X"

    def test_parent_node_has_generic_label(self):
        builder = GraphBuilder()
        event = make_event(pid=200, ppid=100, name="child.exe")
        builder.add_event(event)

        data = builder.graph.nodes["pid_100"]
        assert data["label"] == "PID 100"
        assert data["command_line"] is None

    def test_parent_updated_when_seen_as_child(self):
        builder = GraphBuilder()
        # First: parent 50 creates child 100
        builder.add_event(make_event(pid=100, ppid=50, name="parent.exe"))
        # Then: parent 10 creates child 50
        builder.add_event(make_event(pid=50, ppid=10, name="grandparent.exe"))

        # Now pid_50 should have been updated with actual process info
        data = builder.graph.nodes["pid_50"]
        assert data["label"] == "grandparent.exe"

    def test_tree_structure(self):
        """
        Build tree: 1 → 2, 1 → 3, 2 → 4
        """
        builder = GraphBuilder()
        builder.add_event(make_event(pid=2, ppid=1, name="svchost.exe"))
        builder.add_event(make_event(pid=3, ppid=1, name="explorer.exe"))
        builder.add_event(make_event(pid=4, ppid=2, name="cmd.exe"))

        g = builder.graph
        assert g.number_of_nodes() == 4
        assert g.number_of_edges() == 3

        # Verify specific edges
        assert g.has_edge("pid_1", "pid_2")
        assert g.has_edge("pid_1", "pid_3")
        assert g.has_edge("pid_2", "pid_4")

    def test_edge_has_created_type(self):
        builder = GraphBuilder()
        builder.add_event(make_event(pid=2, ppid=1, name="test.exe"))

        edge_data = builder.graph.edges["pid_1", "pid_2"]
        assert edge_data["type"] == "CREATED"

    def test_build_method_returns_graph(self):
        events = [
            make_event(pid=2, ppid=1, name="a.exe"),
            make_event(pid=3, ppid=1, name="b.exe"),
        ]
        builder = GraphBuilder()
        g = builder.build(events)

        assert isinstance(g, nx.DiGraph)
        assert g.number_of_nodes() == 3
        assert g.number_of_edges() == 2

    def test_build_with_empty_events(self):
        builder = GraphBuilder()
        g = builder.build([])

        assert g.number_of_nodes() == 0
        assert g.number_of_edges() == 0

    def test_duplicate_pid_updates_node(self):
        builder = GraphBuilder()
        builder.add_event(make_event(pid=100, ppid=50, name="first.exe", cmd="first"))
        builder.add_event(make_event(pid=100, ppid=50, name="second.exe", cmd="second"))

        # Node should be updated with latest info
        data = builder.graph.nodes["pid_100"]
        assert data["label"] == "second.exe"
        assert data["command_line"] == "second"
