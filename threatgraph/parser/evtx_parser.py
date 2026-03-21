"""
EVTX Parser Module
Parse Windows Event Log (.evtx) files and yield raw XML strings.

Uses pyevtx-rs (Rust-based) for high-performance parsing.
~650-1600x faster than the previous pure-Python python-evtx library.
"""
from __future__ import annotations

import logging
from typing import Generator

from evtx import PyEvtxParser

logger = logging.getLogger(__name__)


def parse_evtx(file_path: str) -> Generator[str, None, None]:
    """
    Parse an EVTX file and yield each event record as a raw XML string.

    Uses the Rust-based pyevtx-rs parser for high-performance streaming.
    Malformed records are handled internally by the Rust parser.

    Args:
        file_path: Path to the .evtx file.

    Yields:
        Raw XML string for each event record.
    """
    parser = PyEvtxParser(file_path)
    for record in parser.records():
        yield record["data"]
