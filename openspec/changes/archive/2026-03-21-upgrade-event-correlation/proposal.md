## Why

The current ThreatGraph-MVP web application parses Event 4688 to build a basic process tree directly in-memory on the frontend (`app.js`). However, this approach lacks the accurate event correlation principles required for robust security analysis. Specifically, it does not handle composite keys (machine + PID), PID reuse, or clock skew, and it does not correlate other critical events like file access (4663), registry modifications (4657), or session logons (4624). Upgrading the correlation module by introducing a Python-based `CorrelationEngine` on the backend will produce a causally-correct enriched timeline that accurately links every action to its source process and user session without false lineages, before streaming to the UI.

## What Changes

- Implement composite keys (`machine|pid` and `machine|logon_id`) to correctly correlate events across fleets without collisions.
- Add clock skew and log gap checks to prevent mis-ordering and identify false orphans.
- Upgrade the backend to handle PID reuse by matching based on the closest preceding `birth_time`.
- Introduce file access correlation (Event 4663) and registry modification correlation (Event 4657) with cascade joins in Python.
- Correlate user sessions (Event 4624) to track `logon_scope` and token impersonation.
- Add anomaly detection layers (e.g., PPID Spoofing, LOLBins, UAC Token Split).
- Update the D3.js frontend to visualize these new enriched data models and anomaly flags.

## Capabilities

### New Capabilities
- `process-tree-correlation`: Robust process tree generation correctly handling PID reuse, clock skew, and composite keys.
- `file-access-correlation`: Linking Event 4663 to the exact process instance and thread.
- `registry-correlation`: Linking Event 4657 to processes using a 3-level fallback join.
- `session-correlation`: Link process events with Event 4624 to establish `logon_scope`.
- `anomaly-detection`: Detect anomalies such as PPID Spoofing, Log Tampering, and Lateral Movement.

### Modified Capabilities
- (None - no existing specs are present)

## Impact

- **Affected Code**: 
  - Backend: `threatgraph/normalize/events.py`, `threatgraph/server.py` (integrating the new Python `CorrelationEngine`).
  - Frontend: `threatgraph/static/js/app.js` (updating rendering logic for composite keys and anomaly flags).
- **Architecture**: Shifts the heavy lifting of graph correlation from the Vanilla JS frontend into a dedicated Python `CorrelationEngine` on the backend. The SSE stream will now yield fully formed `TimelineRow` or `EnrichedEvent` objects to the D3.js UI.
