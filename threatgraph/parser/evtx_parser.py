"""
EVTX Parser Module
Parse Windows Event Log (.evtx) files and yield raw XML strings.
"""
from __future__ import annotations

import logging
from typing import Generator

import Evtx.Evtx as evtx

logger = logging.getLogger(__name__)


def parse_evtx(file_path: str) -> Generator[str, None, None]:
    """
    Parse an EVTX file and yield each event record as a raw XML string.

    Uses streaming approach — yields one record at a time
    without loading the entire file into memory.

    Args:
        file_path: Path to the .evtx file.

    Yields:
        Raw XML string for each event record.
    """
    with evtx.Evtx(file_path) as log:
        for record in log.records():
            try:
                yield record.xml()
            except Exception as e:
                logger.warning("Skipping malformed record: %s", e)
                continue
