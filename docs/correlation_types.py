"""
correlation_types.py
====================
Agent-readable type contracts for Windows Event Log Process Tree Correlation.
This file is the Python companion to correlation_spec.kql.

Usage for code agents:
  - Import these dataclasses as the canonical schema
  - Implement CorrelationEngine methods following the step order in AGENT_IMPL_ORDER
  - Every JOIN condition is documented in the method docstring
  - Every flag/anomaly column has an explicit detection rule comment
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional


# ──────────────────────────────────────────────────────────────
# CONSTANTS
# ──────────────────────────────────────────────────────────────

WELL_KNOWN_LOGON_IDS = frozenset({
    "0x3e7", "0x3E7",   # SYSTEM
    "0x3e4", "0x3E4",   # Network Service
    "0x3e5", "0x3E5",   # Local Service
})
"""Filter these from user-session grouping — they are not real user sessions."""

DEFAULT_PID_REUSE_GAP    = timedelta(seconds=30)
DEFAULT_REG_TIME_WINDOW  = timedelta(seconds=30)
DEFAULT_CLOCK_SKEW_MAX   = timedelta(minutes=5)
DEFAULT_LATERAL_WINDOW   = timedelta(minutes=5)
UAC_PAIR_WINDOW          = timedelta(seconds=60)


# ──────────────────────────────────────────────────────────────
# ENUMS
# ──────────────────────────────────────────────────────────────

class LogonType(Enum):
    INTERACTIVE        = 2
    NETWORK            = 3
    BATCH              = 4
    SERVICE            = 5
    UNLOCK             = 7
    NETWORK_CLEARTEXT  = 8
    NEW_CREDENTIALS    = 9
    REMOTE_INTERACTIVE = 10   # RDP
    CACHED_INTERACTIVE = 11


class RegistryOp(Enum):
    NEW_VALUE      = "%%1904"
    MODIFY_VALUE   = "%%1905"
    DELETE_VALUE   = "%%1906"


class JoinQuality(Enum):
    """Confidence level of the JOIN that produced an enriched event row."""
    L1_PID_AND_NAME          = "L1_PID+Name"
    L1_PROCESS_ID            = "L1_ProcessId"       # 4663 always has ProcessId
    L2_PID_NAME_MISMATCH     = "L2_PID_NameMismatch_ReviewReuse"
    L3_LOGONID_FALLBACK      = "L3_LogonId_Fallback"


class EventType(Enum):
    FILE_ACCESS  = "FileAccess"
    REGISTRY_MOD = "RegistryMod"


# ──────────────────────────────────────────────────────────────
# COMPOSITE KEY HELPERS
# These are the fleet-unique identifiers. Never use bare PID or LogonId.
# ──────────────────────────────────────────────────────────────

def make_process_key(machine: str, pid_hex: str) -> str:
    """
    Composite process identity — unique across the entire fleet.
    TRAP: PID 1234 on MACHINE-A is UNRELATED to PID 1234 on MACHINE-B.
    """
    return f"{machine}|{pid_hex}"


def make_logon_scope(machine: str, logon_id_hex: str) -> str:
    """
    Composite session identity — unique across the entire fleet.
    TRAP: LogonId 0x3A4F2 on MACHINE-A is UNRELATED to the same value on MACHINE-B.
    LogonId is only unique within one machine + one boot cycle.
    """
    return f"{machine}|{logon_id_hex}"


# ──────────────────────────────────────────────────────────────
# PRE-FLIGHT OUTPUT SCHEMAS
# ──────────────────────────────────────────────────────────────

@dataclass
class ClockSkewReport:
    """Output of CHECK_CLOCK_SKEW step."""
    machine: str
    avg_skew_s: float
    max_skew_s: float
    event_count: int
    has_issue: bool       # True if max_skew_s > DEFAULT_CLOCK_SKEW_MAX

    @property
    def adjusted_time_window(self) -> timedelta:
        """When has_issue=True, expand all time-window JOINs by this amount."""
        return timedelta(seconds=self.max_skew_s) if self.has_issue else timedelta(0)


@dataclass
class LogGapReport:
    """Output of CHECK_LOG_GAPS step."""
    machine: str
    min_record_id: int
    max_record_id: int
    actual_count: int
    expected_count: int
    gap_count: int
    # gap_count > 0 means 4688 events were dropped.
    # Orphan nodes on this machine may be false orphans caused by missing 4688.


# ──────────────────────────────────────────────────────────────
# CORE TABLE SCHEMAS
# ──────────────────────────────────────────────────────────────

@dataclass
class ProcessRecord:
    """
    One row in ProcessTable.
    Produced by BUILD_PROCESS_TABLE from Event 4688.
    Primary key: (machine, process_key)
    """
    birth_time:    datetime
    machine:       str
    process_key:   str           # make_process_key(machine, new_process_id_hex)
    parent_key:    str           # make_process_key(machine, parent_pid_hex)
    pid:           int
    parent_pid:    int
    proc_name:     str           # full image path
    cmd_line:      str           # may be empty — requires audit policy
    logon_scope:   str           # make_logon_scope(machine, subject_logon_id)
    logon_id:      str           # raw hex e.g. "0x3A4F2"
    user_name:     str
    user_sid:      str
    domain:        str
    spawning_tid:  int           # thread that called CreateProcess (from XML header)
    record_id:     int           # EventRecordId — for gap detection


@dataclass
class ProcessTreeRecord(ProcessRecord):
    """
    One row in ProcessTreeTable.
    Produced by BUILD_PROCESS_TREE (self-join of ProcessTable).

    JOIN: child.parent_key == parent.process_key
          AND child.birth_time >= parent.birth_time
    When multiple parent candidates exist (PID reuse), take the one
    with birth_time closest-but-before child.birth_time.
    """
    parent_name:         Optional[str] = None
    parent_cmd:          Optional[str] = None
    parent_user:         Optional[str] = None
    parent_logon_scope:  Optional[str] = None

    # ── Anomaly flags ──
    is_orphan: bool = False
    """
    True when no matching parent row found in ProcessTable.
    CAUSES (check in this order):
      1. Parent started before SEARCH_START window  (most common, benign)
      2. EventRecordId gap on this machine          (check LogGapReport)
      3. PPID Spoofing                              (see PPIDSpoofRecord)
    """

    possible_pid_reuse: bool = False
    """
    True when parent birth_time < PID_REUSE_GAP before child birth_time.
    Means two different processes shared this PID in rapid succession.
    Do NOT treat this as parent-child lineage — it is coincidental PID reuse.
    """


# ──────────────────────────────────────────────────────────────
# ENRICHED EVENT SCHEMA (output of ENRICH_* steps)
# ──────────────────────────────────────────────────────────────

@dataclass
class EnrichedEvent:
    """
    One row in FileAccessEnriched or RegistryEnriched.
    This is the primary atom of the correlation output.
    """
    event_type:     EventType
    machine:        str
    event_time:     datetime
    tid:            int

    # ── Process context ──
    process_key:    str
    process_name:   str
    command_line:   str
    parent_pid:     int
    parent_name:    Optional[str]
    parent_cmd:     Optional[str]

    # ── Identity ──
    process_owner:  str   # primary token of the process
    effective_user: str   # thread's impersonation token (may differ from process_owner)
    logon_scope:    str
    logon_id:       str

    # ── Event content ──
    detail:         str   # "file=<path> access=<mask>" or "reg_key=<key> op=<op>"

    # ── Quality / anomaly flags ──
    join_quality:       JoinQuality
    is_sequential:      bool
    """
    True when this event's ThreadID == the spawning_tid of the process.
    Meaning: the same OS thread that called CreateProcess also caused this event.
    This is CAUSAL evidence, not just temporal correlation.
    False = event happened on a different thread = concurrent, not necessarily caused by process creation.
    """

    logonid_mismatch:   bool
    """
    True when event's SubjectLogonId differs from the process's logon_scope.
    Indicates token impersonation: the thread is running as a different user
    than the process owner.
    When True: effective_user is the actual actor; process_owner is the host process.
    Report BOTH — they answer different forensic questions.
    """

    is_orphan:          bool   # inherited from ProcessTreeRecord
    possible_pid_reuse: bool   # inherited from ProcessTreeRecord

    # ── Registry-only fields (None for FileAccess) ──
    process_name_raw: Optional[str] = None
    """Raw ProcessName from 4657 event body. Compare with process_name from
    ProcessTable. Mismatch → join_quality should be L2."""


@dataclass
class TimelineRow(EnrichedEvent):
    """
    One row in the final EnrichedTimeline.
    Adds session context from Event 4624 (left-outer joined on logon_scope).
    """
    logon_type: Optional[str] = None   # None for service sessions (no 4624)
    source_ip:  Optional[str] = None   # None for local/service sessions


# ──────────────────────────────────────────────────────────────
# ANOMALY DETECTION OUTPUT SCHEMAS
# ──────────────────────────────────────────────────────────────

@dataclass
class PPIDSpoofRecord:
    """
    Output of DETECT_PPID_SPOOF.
    Detection rule:
      parent's 4689 (exit) death_time < child's 4688 birth_time
      → parent was dead before child was "born" → impossible without spoofing
    """
    birth_time:  datetime
    machine:     str
    child_pid:   int
    child_name:  str
    child_cmd:   str
    parent_pid:  int
    parent_name: Optional[str]
    parent_died: datetime
    severity:    str = "HIGH"


@dataclass
class UACTokenPair:
    """
    Output of DETECT_UAC_TOKEN_SPLIT.
    Links the two LogonId values Windows creates for one UAC-elevated login.
    Use this to merge logon_scope variants when building user-level timelines.
    """
    machine:        str
    user_name:      str
    standard_scope: str   # logon_scope of the non-elevated token
    elevated_scope: str   # logon_scope of the elevated (admin) token
    time_diff_s:    int


@dataclass
class LateralMovementLink:
    """
    Output of DETECT_LATERAL_MOVEMENT.
    Links the source machine's 4648 event to the target machine's 4624 event.
    After finding this link, join ProcessTreeTable of BOTH machines using
    SourceLogonScope and TargetLogonScope to build a unified kill-chain.
    """
    lateral_time:      datetime
    source_machine:    str
    source_logon_scope: str
    target_machine:    str
    target_logon_scope: str
    user:              str


@dataclass
class ThreadInjectionAlert:
    """Output of DETECT_THREAD_INJECTION (Sysmon Event 8)."""
    time_created:  datetime
    machine:       str
    source_name:   Optional[str]
    source_tid:    str
    source_user:   Optional[str]
    target_name:   Optional[str]
    injected_tid:  str
    severity:      str  # "CRITICAL" if target is lsass/winlogon/csrss, else "HIGH"


@dataclass
class LOLBinAlert:
    """Output of DETECT_LOLBINS."""
    birth_time:       datetime
    machine:          str
    pid:              int
    process_name:     str
    command_line:     str
    user_name:        str
    parent_name:      Optional[str]
    suspicion_reason: str
    severity:         str = "HIGH"


# ──────────────────────────────────────────────────────────────
# IMPLEMENTATION CONTRACT
# ──────────────────────────────────────────────────────────────

AGENT_IMPL_ORDER = [
    # PHASE 1 — Pre-flight
    ("CHECK_CLOCK_SKEW",        "→ ClockSkewReport[]"),
    ("CHECK_LOG_GAPS",          "→ LogGapReport[]"),

    # PHASE 2 — Core tables
    ("BUILD_PROCESS_TABLE",     "→ ProcessRecord[]"),
    ("BUILD_PROCESS_TREE",      "→ ProcessTreeRecord[]"),

    # PHASE 3 — Enrichment (parallel after Phase 2)
    ("ENRICH_FILE_ACCESS",      "→ EnrichedEvent[]  (event_type=FileAccess)"),
    ("ENRICH_REGISTRY",         "→ EnrichedEvent[]  (event_type=RegistryMod)"),

    # PHASE 4 — Output
    ("BUILD_TIMELINE",          "→ TimelineRow[]"),

    # PHASE 5 — Anomaly detectors (independent)
    ("DETECT_PPID_SPOOF",       "→ PPIDSpoofRecord[]"),
    ("DETECT_UAC_TOKEN_SPLIT",  "→ UACTokenPair[]"),
    ("DETECT_LATERAL_MOVEMENT", "→ LateralMovementLink[]"),
    ("DETECT_THREAD_INJECTION", "→ ThreadInjectionAlert[]"),
    ("DETECT_LOG_TAMPERING",    "→ dict (timestamp, machine, type)"),
    ("DETECT_LOLBINS",          "→ LOLBinAlert[]"),
]

KEY_INVARIANTS = [
    "Every EnrichedEvent.machine is non-empty",
    "Every logon_scope matches r'^[^|]+\\|0x[0-9a-fA-F]+'",
    "No logon_id in WELL_KNOWN_LOGON_IDS appears in TimelineRow output",
    "join_quality is always a valid JoinQuality enum value",
    "event_time >= birth_time for every EnrichedEvent",
    "process_key always starts with the machine value (composite key integrity)",
    "parent_key always has the same machine prefix as process_key",
]

DATA_MODEL = """
ProcessRecord       1 ──────< ProcessTreeRecord   (self-referencing parent-child tree)
ProcessTreeRecord   1 ──────< EnrichedEvent        (via process_key)
                             (FileAccess: always process_key JOIN)
                             (RegistryMod: process_key JOIN L1/L2, logon_scope JOIN L3)
EnrichedEvent       * ──────> TimelineRow           (+ session info via logon_scope)
SessionInfo (4624)  1 ──────< TimelineRow           (left-outer via logon_scope)
UACTokenPair        * ──────> logon_scope merge     (use when building user timelines)
LateralMovementLink * ──────> cross-machine join    (link two ProcessTreeRecord sets)
"""
