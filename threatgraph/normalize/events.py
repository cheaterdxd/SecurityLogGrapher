"""
Event Normalizer Module
Parse XML event strings and extract fields for Event IDs 4688, 4663, 4657.
"""
import logging
import hashlib
from typing import Optional
from lxml import etree

logger = logging.getLogger(__name__)

# Windows Event Log XML namespace
NS = {"evt": "http://schemas.microsoft.com/win/2004/08/events/event"}

def _get_text(root: etree._Element, xpath: str) -> Optional[str]:
    elements = root.xpath(xpath, namespaces=NS)
    return elements[0].text if elements else None

def _get_data_value(root: etree._Element, name: str) -> Optional[str]:
    elements = root.xpath(f".//evt:EventData/evt:Data[@Name='{name}']", namespaces=NS)
    return elements[0].text.strip() if elements and elements[0].text else None

def _parse_pid(value: Optional[str]) -> Optional[int]:
    if not value: return None
    value = value.strip()
    try: return int(value, 16) if value.lower().startswith("0x") else int(value)
    except Exception: return None

def normalize_event(xml_event: str) -> Optional[dict]:
    try:
        root = etree.fromstring(xml_event.encode("utf-8"))
    except etree.XMLSyntaxError:
        return None

    event_id = _get_text(root, ".//evt:System/evt:EventID")
    if not event_id: return None
    event_id = event_id.strip()

    if event_id not in ("4688", "4663", "4657"):
        return None

    time_elements = root.xpath(".//evt:System/evt:TimeCreated", namespaces=NS)
    timestamp = time_elements[0].get("SystemTime", "") if time_elements else ""

    if event_id == "4688":
        new_process_id = _parse_pid(_get_data_value(root, "NewProcessId"))
        parent_process_id = _parse_pid(_get_data_value(root, "ProcessId"))
        new_process_name = _get_data_value(root, "NewProcessName")
        command_line = _get_data_value(root, "CommandLine")

        if new_process_id is None or parent_process_id is None or new_process_name is None:
            return None

        return {
            "event_id": "4688",
            "timestamp": timestamp,
            "pid": str(new_process_id),
            "ppid": str(parent_process_id),
            "process_name": new_process_name,
            "command_line": command_line,
            "node_type": "process",
            "raw_xml": xml_event,
        }

    elif event_id == "4663":
        process_id = _parse_pid(_get_data_value(root, "ProcessId"))
        object_name = _get_data_value(root, "ObjectName")
        object_type = _get_data_value(root, "ObjectType")
        # AccessList is per research doc
        accesses = _get_data_value(root, "AccessList") or _get_data_value(root, "Accesses")
        
        if process_id is None or object_name is None:
            return None

        # Hash the object name to generate a persistent "PID" for the graph node
        # ensuring all 4663s hitting the same file map to the same node!
        obj_id = f"obj_{hashlib.md5(object_name.encode()).hexdigest()[:12]}"
        
        # Override all ObjectTypes in 4663 to be file as per user request
        ntype = "file"
        
        return {
            "event_id": "4663",
            "timestamp": timestamp,
            "pid": obj_id,
            "ppid": str(process_id),
            "process_name": object_name.split("\\")[-1] if "\\" in object_name else object_name,
            "command_line": f"Accesses: {accesses}\nPath: {object_name}",
            "node_type": ntype,
            "object_name": object_name,
            "access_list": accesses if accesses else "None",
            "raw_xml": xml_event,
        }

    elif event_id == "4657":
        process_id = _parse_pid(_get_data_value(root, "ProcessId"))
        object_name = _get_data_value(root, "ObjectName")
        object_value_name = _get_data_value(root, "ObjectValueName")
        operation_type = _get_data_value(root, "OperationType")
        old_val = _get_data_value(root, "OldValue")
        new_val = _get_data_value(root, "NewValue")
        
        if process_id is None or object_name is None:
            return None

        full_reg = f"{object_name}\\{object_value_name}" if object_value_name else object_name
        obj_id = f"reg_{hashlib.md5(full_reg.encode()).hexdigest()[:12]}"
        
        changes = []
        if old_val: changes.append(f"Old: {old_val}")
        if new_val: changes.append(f"New: {new_val}")
        change_str = "\n".join(changes)

        return {
            "event_id": "4657",
            "timestamp": timestamp,
            "pid": obj_id,
            "ppid": str(process_id),
            "process_name": object_value_name or object_name.split("\\")[-1] or "Registry",
            "command_line": f"Path: {object_name}\n{change_str}",
            "node_type": "registry",
            "object_name": object_name,
            "new_value": new_val if new_val else "None",
            "raw_xml": xml_event,
        }

    return None
