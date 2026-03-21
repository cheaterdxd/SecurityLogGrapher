from __future__ import annotations

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta

from threatgraph.correlation.types import (
    ProcessTreeRecord, JoinQuality, make_process_key, make_logon_scope,
    DEFAULT_PID_REUSE_GAP, DEFAULT_REG_TIME_WINDOW, WELL_KNOWN_LOGON_IDS,
    LogGapReport, ClockSkewReport
)

logger = logging.getLogger(__name__)

class CorrelationEngine:
    def __init__(self, machine: str = "LOCAL"):
        self.machine = machine
        self.process_history: Dict[str, List[ProcessTreeRecord]] = {}
        self.sessions: Dict[str, str] = {} # logon_scope -> process_key format for D3 (e.g., logon_0x3e7)
        self.exits: Dict[str, datetime] = {} # process_key -> exit_time

    def _parse_time(self, ts_str: str) -> datetime:
        try:
            ts = ts_str.replace("Z", "+00:00")
            return datetime.fromisoformat(ts)
        except Exception:
            return datetime.min

    def process_event(self, event: dict) -> dict:
        event_id = event.get("event_id")
        if event_id == "4624":
            return self._handle_logon(event)
        elif event_id == "4689":
            return self._handle_exit(event)
        elif event_id == "4688":
            return self._handle_process_create(event)
        elif event_id == "4663":
            return self._handle_file_access(event)
        elif event_id == "4657":
            return self._handle_registry_mod(event)
        return event

    def _handle_logon(self, event: dict) -> dict:
        logon_id = event.get("logon_id", "0x0")
        scope = make_logon_scope(self.machine, logon_id)
        linked = event.get("linked_id", "0x0")
        
        out = event.copy()
        out["process_key"] = f"logon_{logon_id}"
        out["parent_key"] = None
        self.sessions[scope] = out["process_key"]
        
        # UAC Token Split Anomaly
        out["anomaly_uac_split"] = False
        if linked and linked != "0x0" and linked != "0":
            linked_scope = make_logon_scope(self.machine, linked)
            if linked_scope in self.sessions:
                out["anomaly_uac_split"] = True
                
        return out
        
    def _handle_exit(self, event: dict) -> dict:
        ev_time = self._parse_time(event.get("timestamp", ""))
        ppid = event.get("ppid", "0")
        ev_process_key = make_process_key(self.machine, ppid)
        
        # Record exit time for PPID Spoofing checks
        if ev_process_key in self.process_history:
            valid = [p for p in self.process_history[ev_process_key] if p.birth_time <= ev_time]
            if valid:
                proc = max(valid, key=lambda p: p.birth_time)
                # Store exit time against the specific process run (approximate using tuple or dict)
                self.exits[f"{ev_process_key}_{proc.birth_time.timestamp()}"] = ev_time
        
        out = event.copy()
        out["process_key"] = event.get("pid")
        out["parent_key"] = ev_process_key
        return out

    def _handle_process_create(self, event: dict) -> dict:
        birth_time = self._parse_time(event.get("timestamp", ""))
        pid = event.get("pid", "0")
        ppid = event.get("ppid", "0")
        logon_id = event.get("logon_id", "0x0")
        
        process_key = make_process_key(self.machine, pid)
        parent_key = make_process_key(self.machine, ppid)

        parent_record: Optional[ProcessTreeRecord] = None
        is_orphan = True
        possible_pid_reuse = False
        anomaly_ppid_spoof = False
        
        if parent_key in self.process_history:
            candidates = self.process_history[parent_key]
            valid = [p for p in candidates if p.birth_time <= birth_time]
            if valid:
                parent_record = max(valid, key=lambda p: p.birth_time)
                is_orphan = False
                
                if (birth_time - parent_record.birth_time) < DEFAULT_PID_REUSE_GAP:
                    possible_pid_reuse = True
                    
                # PPID Spoofing Check: did parent exit before child was born?
                exit_key = f"{parent_key}_{parent_record.birth_time.timestamp()}"
                if exit_key in self.exits and self.exits[exit_key] < birth_time:
                    anomaly_ppid_spoof = True
                    
        cmd = event.get("command_line", "").lower()
        proc_name = event.get("process_name", "").lower()
        anomaly_lolbin = False
        if proc_name in ["certutil.exe", "powershell.exe", "cmd.exe", "mshta.exe"]:
            if any(k in cmd for k in ["-urlcache", "downloadstring", "invoke-webrequest", "enc", "javascript:"]):
                anomaly_lolbin = True
        
        record = ProcessTreeRecord(
            birth_time=birth_time,
            machine=self.machine,
            process_key=process_key,
            parent_key=parent_key,
            pid=int(pid, 16) if pid.startswith("0x") else int(pid) if pid.lstrip("-").isdigit() else 0,
            parent_pid=int(ppid, 16) if ppid.startswith("0x") else int(ppid) if ppid.lstrip("-").isdigit() else 0,
            proc_name=event.get("process_name", ""),
            cmd_line=event.get("command_line", ""),
            logon_scope=make_logon_scope(self.machine, logon_id),
            logon_id=logon_id,
            user_name="",
            user_sid="",
            domain="",
            spawning_tid=event.get("tid", 0),
            record_id=event.get("record_id", 0),
            parent_name=parent_record.proc_name if parent_record else None,
            parent_cmd=parent_record.cmd_line if parent_record else None,
            is_orphan=is_orphan,
            possible_pid_reuse=possible_pid_reuse
        )
        self.process_history.setdefault(process_key, []).append(record)
        
        out = event.copy()
        out["process_key"] = process_key
        # Force all orphans to group under their Logon Session to avoid scattered processes
        if is_orphan and logon_id and logon_id not in ("0x0", "0"):
            out["parent_key"] = f"logon_{logon_id}"
        else:
            out["parent_key"] = parent_key
            
        out["is_orphan"] = is_orphan
        out["possible_pid_reuse"] = possible_pid_reuse
        out["anomaly_ppid_spoof"] = anomaly_ppid_spoof
        out["anomaly_lolbin"] = anomaly_lolbin
        return out

    def _handle_file_access(self, event: dict) -> dict:
        ev_time = self._parse_time(event.get("timestamp", ""))
        ppid = event.get("ppid", "0") 
        ev_process_key = make_process_key(self.machine, ppid)
        ev_logon_scope = make_logon_scope(self.machine, event.get("logon_id", "0x0"))
        ev_tid = event.get("tid", 0)
        
        out = event.copy()
        out["process_key"] = ev_process_key
        out["parent_key"] = ev_process_key 
        out["join_quality"] = JoinQuality.L1_PROCESS_ID.value
        out["is_sequential"] = False
        out["logonid_mismatch"] = False

        if ev_process_key in self.process_history:
            valid = [p for p in self.process_history[ev_process_key] if p.birth_time <= ev_time]
            if valid:
                proc = max(valid, key=lambda p: p.birth_time)
                out["is_sequential"] = (ev_tid == proc.spawning_tid)
                out["logonid_mismatch"] = (ev_logon_scope != proc.logon_scope)
                
        return out

    def _handle_registry_mod(self, event: dict) -> dict:
        ev_time = self._parse_time(event.get("timestamp", ""))
        ppid = event.get("ppid", "0") 
        ev_process_key = make_process_key(self.machine, ppid)
        ev_logon_scope = make_logon_scope(self.machine, event.get("logon_id", "0x0"))
        ev_proc_name_raw = event.get("process_name_raw")
        ev_tid = event.get("tid", 0)
        
        out = event.copy()
        out["process_key"] = ev_process_key
        out["parent_key"] = ev_process_key 
        out["is_sequential"] = False
        out["logonid_mismatch"] = False
        
        join_quality = JoinQuality.L3_LOGONID_FALLBACK.value
        
        if ppid and ppid != "0":
            if ev_process_key in self.process_history:
                valid = [p for p in self.process_history[ev_process_key] if p.birth_time <= ev_time]
                if valid:
                    proc = max(valid, key=lambda p: p.birth_time)
                    out["is_sequential"] = (ev_tid == proc.spawning_tid)
                    out["logonid_mismatch"] = (ev_logon_scope != proc.logon_scope)
                    
                    if not ev_proc_name_raw or ev_proc_name_raw == proc.proc_name:
                        join_quality = JoinQuality.L1_PID_AND_NAME.value
                    else:
                        join_quality = JoinQuality.L2_PID_NAME_MISMATCH.value
        
        out["join_quality"] = join_quality
        return out
