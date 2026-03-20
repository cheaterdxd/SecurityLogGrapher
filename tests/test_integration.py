"""
Integration tests for the full ThreatGraph pipeline.
Tests the complete flow: normalize → build graph → render HTML.
"""
import os
import tempfile

import pytest

from threatgraph.normalize.event_4688 import normalize_event
from threatgraph.graph.builder import GraphBuilder
from threatgraph.visualize.pyvis_render import render_graph


# --- Mock XML events simulating a process tree ---

MOCK_EVENTS = [
    # svchost.exe (PID 0x3e8 = 1000) spawned by services.exe (PID 0x1f4 = 500)
    """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4688</EventID>
        <TimeCreated SystemTime="2024-01-15T10:00:00.000Z"/>
      </System>
      <EventData>
        <Data Name="NewProcessId">0x3e8</Data>
        <Data Name="ProcessId">0x1f4</Data>
        <Data Name="NewProcessName">C:\\Windows\\System32\\svchost.exe</Data>
        <Data Name="CommandLine">svchost.exe -k netsvcs</Data>
      </EventData>
    </Event>
    """,
    # cmd.exe (PID 0x7d0 = 2000) spawned by svchost.exe (PID 0x3e8 = 1000)
    """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4688</EventID>
        <TimeCreated SystemTime="2024-01-15T10:01:00.000Z"/>
      </System>
      <EventData>
        <Data Name="NewProcessId">0x7d0</Data>
        <Data Name="ProcessId">0x3e8</Data>
        <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
        <Data Name="CommandLine">cmd /c whoami</Data>
      </EventData>
    </Event>
    """,
    # powershell.exe (PID 0xbb8 = 3000) spawned by cmd.exe (PID 0x7d0 = 2000)
    """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4688</EventID>
        <TimeCreated SystemTime="2024-01-15T10:02:00.000Z"/>
      </System>
      <EventData>
        <Data Name="NewProcessId">0xbb8</Data>
        <Data Name="ProcessId">0x7d0</Data>
        <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
        <Data Name="CommandLine">powershell -enc SGVsbG8=</Data>
      </EventData>
    </Event>
    """,
    # Non-4688 event (should be filtered out)
    """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <EventID>4689</EventID>
        <TimeCreated SystemTime="2024-01-15T10:03:00.000Z"/>
      </System>
      <EventData>
        <Data Name="ProcessId">0x7d0</Data>
        <Data Name="ProcessName">C:\\Windows\\System32\\cmd.exe</Data>
      </EventData>
    </Event>
    """,
]


class TestIntegration:
    """Full pipeline integration tests using mock data."""

    def test_full_pipeline_normalize_build_render(self):
        """Test complete flow: normalize → filter → build → render."""
        # Step 1 & 2: Normalize and filter
        normalized = (normalize_event(xml) for xml in MOCK_EVENTS)
        filtered = [e for e in normalized if e is not None]

        # Should have 3 valid events (4th is Event 4689)
        assert len(filtered) == 3

        # Step 3: Build graph
        builder = GraphBuilder()
        graph = builder.build(filtered)

        # 4 nodes: pid_500 (parent), pid_1000, pid_2000, pid_3000
        assert graph.number_of_nodes() == 4
        # 3 edges: 500→1000, 1000→2000, 2000→3000
        assert graph.number_of_edges() == 3

        # Verify the chain: services.exe → svchost → cmd → powershell
        assert graph.has_edge("pid_500", "pid_1000")
        assert graph.has_edge("pid_1000", "pid_2000")
        assert graph.has_edge("pid_2000", "pid_3000")

        # Step 4: Render to HTML
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            output_path = f.name

        try:
            render_graph(graph, output_path)
            assert os.path.exists(output_path)

            # Check that the HTML file has content
            size = os.path.getsize(output_path)
            assert size > 100  # Should be a substantial HTML file

            # Check basic HTML structure
            with open(output_path, "r", encoding="utf-8") as f:
                content = f.read()
                assert "<html>" in content.lower() or "<!doctype" in content.lower()
        finally:
            os.unlink(output_path)

    def test_pipeline_with_only_non_4688_events(self):
        """No valid events should produce an empty graph."""
        non_4688 = [MOCK_EVENTS[3]]  # Only the 4689 event
        normalized = (normalize_event(xml) for xml in non_4688)
        filtered = [e for e in normalized if e is not None]

        assert len(filtered) == 0

        builder = GraphBuilder()
        graph = builder.build(filtered)
        assert graph.number_of_nodes() == 0
