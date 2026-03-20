"""
Event 4688 Normalizer Module
Parse XML event strings and extract Process Creation (Event ID 4688) fields.
"""
from __future__ import annotations

import logging
from typing import Optional

from lxml import etree

logger = logging.getLogger(__name__)

# Windows Event Log XML namespace
NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _get_text(root: etree._Element, xpath: str) -> Optional[str]:
    """Safely extract text from an XML element via XPath."""
    elements = root.xpath(xpath, namespaces=NS)
    if elements:
        return elements[0].text
    return None


def _get_data_value(root: etree._Element, name: str) -> Optional[str]:
    """Extract a value from EventData/Data[@Name='...']."""
    xpath = f".//evt:EventData/evt:Data[@Name='{name}']"
    elements = root.xpath(xpath, namespaces=NS)
    if elements and elements[0].text:
        return elements[0].text.strip()
    return None


def _parse_pid(value: Optional[str]) -> Optional[int]:
    """
    Parse a PID value from EVTX.
    Handles both hex strings (0x1a4) and decimal strings (420).
    """
    if value is None:
        return None
    value = value.strip()
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except (ValueError, TypeError):
        logger.warning("Could not parse PID value: %s", value)
        return None


def normalize_event(xml_event: str) -> Optional[dict]:
    """
    Parse an XML event string and extract fields for Event ID 4688.

    Returns a normalized dict if the event is ID 4688,
    or None if it's a different event type or parsing fails.

    Args:
        xml_event: Raw XML string of a single Windows event.

    Returns:
        Normalized event dict with keys:
            - timestamp (str): ISO format timestamp
            - pid (int): New process ID
            - ppid (int): Parent process ID
            - process_name (str): New process name
            - command_line (str | None): Command line, if available
            - raw_xml (str): The raw unbroken XML event text
        Or None if not Event ID 4688.
    """
    try:
        root = etree.fromstring(xml_event.encode("utf-8"))
    except etree.XMLSyntaxError as e:
        logger.warning("Failed to parse XML: %s", e)
        return None

    # Check Event ID
    event_id_text = _get_text(root, ".//evt:System/evt:EventID")
    if event_id_text is None or event_id_text.strip() != "4688":
        return None

    # Extract timestamp
    time_elements = root.xpath(".//evt:System/evt:TimeCreated", namespaces=NS)
    timestamp = None
    if time_elements:
        timestamp = time_elements[0].get("SystemTime", "")

    # Extract process fields
    new_process_id = _parse_pid(_get_data_value(root, "NewProcessId"))
    parent_process_id = _parse_pid(_get_data_value(root, "ProcessId"))
    new_process_name = _get_data_value(root, "NewProcessName")
    command_line = _get_data_value(root, "CommandLine")

    # Validate required fields
    if new_process_id is None or parent_process_id is None or new_process_name is None:
        logger.warning("Missing required fields in Event 4688")
        return None

    return {
        "timestamp": timestamp or "",
        "pid": new_process_id,
        "ppid": parent_process_id,
        "process_name": new_process_name,
        "command_line": command_line,
        "raw_xml": xml_event,
    }
