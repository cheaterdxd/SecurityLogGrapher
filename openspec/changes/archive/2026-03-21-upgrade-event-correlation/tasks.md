## 1. Backend: Core Correlation Engine

- [x] 1.1 Create `threatgraph/correlation/engine.py` using the dataclasses from `docs/correlation_types.py`.
- [x] 1.2 Implement `BUILD_PROCESS_TABLE` and `BUILD_PROCESS_TREE` to construct the core graphs with composite keys (`machine|pid`).
- [x] 1.3 Implement clock skew (`CHECK_CLOCK_SKEW`) and log gap (`CHECK_LOG_GAPS`) pre-flight checks.

## 2. Backend: Event Enrichment & Anomalies

- [x] 2.1 Implement `ENRICH_FILE_ACCESS` (Event 4663) correlation logic.
- [x] 2.2 Implement `ENRICH_REGISTRY` (Event 4657) correlation logic with L1/L2/L3 cascade joins.
- [x] 2.3 Implement User Session integration (`BUILD_TIMELINE`) using Event 4624 and 4689.
- [x] 2.4 Implement anomaly detectors (PPID Spoofing, LOLBins, UAC Token Split).

## 3. API Pipeline Integration

- [x] 3.1 Update `normalize/events.py` to extract necessary XML attributes (e.g., `ThreadID`, `EventRecordID`).
- [x] 3.2 Refactor `stream_evtx` in `server.py` to pipe normalized events through the `CorrelationEngine` before yielding SSE chunks.

## 4. Frontend & Visualization Updates

- [x] 4.1 Update `app.js` state management to map nodes via composite `process_key` instead of bare `pid`.
- [x] 4.2 Update D3.js rendering logic to display new node types gracefully based on the enriched `TimelineRow` data.
- [x] 4.3 Add visual indicators (e.g., tooltip tags, varying stroke colors) for detected anomalies (PPID Spoofing, Logon Mismatch).
