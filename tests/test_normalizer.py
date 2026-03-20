"""
Tests for the Event 4688 Normalizer module.
"""
import pytest

from threatgraph.normalize.events import normalize_event, _parse_pid


# --- Sample XML data ---

VALID_EVENT_4688 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2024-01-15T10:30:00.000Z"/>
  </System>
  <EventData>
    <Data Name="NewProcessId">0x1a4</Data>
    <Data Name="ProcessId">0x3e8</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd /c whoami</Data>
  </EventData>
</Event>
"""

EVENT_4688_NO_CMDLINE = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2024-01-15T10:31:00.000Z"/>
  </System>
  <EventData>
    <Data Name="NewProcessId">0x500</Data>
    <Data Name="ProcessId">0x100</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\notepad.exe</Data>
  </EventData>
</Event>
"""

EVENT_4688_DECIMAL_PID = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4688</EventID>
    <TimeCreated SystemTime="2024-01-15T10:32:00.000Z"/>
  </System>
  <EventData>
    <Data Name="NewProcessId">1234</Data>
    <Data Name="ProcessId">5678</Data>
    <Data Name="NewProcessName">C:\\Windows\\System32\\powershell.exe</Data>
    <Data Name="CommandLine">powershell -enc ABC123</Data>
  </EventData>
</Event>
"""

EVENT_4689 = """
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <EventID>4689</EventID>
    <TimeCreated SystemTime="2024-01-15T10:33:00.000Z"/>
  </System>
  <EventData>
    <Data Name="ProcessId">0x1a4</Data>
    <Data Name="ProcessName">C:\\Windows\\System32\\cmd.exe</Data>
  </EventData>
</Event>
"""

MALFORMED_XML = "<Event><broken"


class TestParsesPid:
    """Tests for _parse_pid helper."""

    def test_hex_pid(self):
        assert _parse_pid("0x1a4") == 420

    def test_hex_pid_uppercase(self):
        assert _parse_pid("0x1A4") == 420

    def test_decimal_pid(self):
        assert _parse_pid("1234") == 1234

    def test_none_pid(self):
        assert _parse_pid(None) is None

    def test_invalid_pid(self):
        assert _parse_pid("not_a_number") is None


class TestNormalizeEvent:
    """Tests for normalize_event function."""

    def test_valid_event_4688(self):
        result = normalize_event(VALID_EVENT_4688)
        assert result is not None
        assert result["pid"] == 0x1A4  # 420
        assert result["ppid"] == 0x3E8  # 1000
        assert result["process_name"] == "C:\\Windows\\System32\\cmd.exe"
        assert result["command_line"] == "cmd /c whoami"
        assert result["timestamp"] == "2024-01-15T10:30:00.000Z"

    def test_missing_command_line(self):
        result = normalize_event(EVENT_4688_NO_CMDLINE)
        assert result is not None
        assert result["command_line"] is None
        assert result["pid"] == 0x500  # 1280
        assert result["ppid"] == 0x100  # 256

    def test_decimal_pid(self):
        result = normalize_event(EVENT_4688_DECIMAL_PID)
        assert result is not None
        assert result["pid"] == 1234
        assert result["ppid"] == 5678

    def test_non_4688_event_returns_none(self):
        result = normalize_event(EVENT_4689)
        assert result is None

    def test_malformed_xml_returns_none(self):
        result = normalize_event(MALFORMED_XML)
        assert result is None

    def test_empty_string_returns_none(self):
        result = normalize_event("")
        assert result is None
