## Context

The current `ThreatGraph-MVP` uses a FastAPI backend with `pyevtx-rs` for ultra-fast streaming via SSE, while the Vanilla JS frontend (`app.js`) handles D3 rendering and basic parent-child linking. The current linking relies purely on bare PIDs, leading to broken graphs when PIDs are reused or when analyzing multiple machines.

## Goals / Non-Goals

**Goals:**
- Shift correlation logic into a robust Python `CorrelationEngine` on the backend (as defined in `docs/correlation_types.py`).
- Implement composite identity keys (`machine|pid` and `machine|logon_id`) for global uniqueness.
- Correlate File Access (4663) and Registry (4657) events to specific process nodes with documented join qualities.
- Stream fully enriched elements via the existing SSE endpoint to the frontend.
- Update `app.js` to render the enriched elements and anomaly flags without crashing on circular references.

**Non-Goals:**
- Fully migrating to direct JSON parsing via `pyevtx-rs` native methods (we will stick to the current XML/`lxml` step for now, focusing solely on the correlation logic upgrade).

## Decisions

- **Backend Correlation**: We will implement the KQL specifications entirely in Python. The `stream_evtx` endpoint will buffer rows, run them through the `CorrelationEngine`, and then stream the enriched structured data to the frontend.
- **Join Strategies**:
  - File Access (4663) always joins on `process_key`.
  - Registry (4657) uses a 3-level cascading join: `process_key` + `process_name` (L1), `process_key` with mismatching name (L2), and `logon_scope` + time window fallback (L3).
- **Frontend D3 Updates**: The `childrenMap` and `parentMap` in `app.js` will be refactored to use the composite `process_key` instead of bare PIDs. 

## Risks / Trade-offs

- **Memory Consumption in Backend**: By moving correlation to the backend, the `ProcessTable` must be kept in Python memory until the EVTX stream completes. 
  *Mitigation*: We will use dataclasses (`docs/correlation_types.py`) to minimize memory overhead compared to heavy dicts.
- **Latency on SSE Stream**: Buffering events for time-window correlations (like PID reuse gaps) may delay the initial SSE chunks.
  *Mitigation*: Event streams will be processed strictly chronologically, allowing us to flush events to the client once they pass the time-window threshold.
