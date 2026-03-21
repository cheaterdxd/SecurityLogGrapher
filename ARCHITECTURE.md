# Architecture Overview

This document serves as the long-term context memory regarding how **SecurityLogGrapher** is structured and why certain design decisions were made.

## 1. System Components

The application follows a **Lightweight Backend / Heavy Frontend** architecture.

### Backend (Python / FastAPI)
- **Role:** File receiving, parsing `.evtx`, data normalization, and streaming chunks.
- **Core Library:** `evtx` (pyevtx-rs). Using this instead of `python-evtx` improved parsing speeds by ~650x because it avoids pure Python XML overhead and leverages Rust multi-threading capabilities.
- **Data Flow:**
  - Client uploads `file.evtx` via `POST /api/upload` -> File saved to `/tmp`.
  - Client requests `GET /api/stream/{file_id}`.
  - Backend uses `PyEvtxParser(file_path)` to read records sequentially.
  - Events are parsed via `lxml` and matched against supported Event IDs (`4688`, `4663`, `4657`).
  - Normalization extracts required fields (`node_type`, `pid`, `ppid`, `object_name`).
  - Records are yielded to the client via **Server-Sent Events (SSE)**.

### Frontend (Vanilla JS + D3.js + HTML/CSS)
- **Role:** State management, filtering, and visual rendering.
- **Files:** `index.html`, `app.js`, `app.css`.
- **State (`nodes`, `childrenMap`, `parentMap`):**
  - All parsed nodes are maintained strictly in-memory (`app.js`).
  - The UI does not require pagination API calls; the search happens synchronously across the dataset.
- **Tree Panel (Left):** 
  - Provides a hierarchical representation of spawned processes and accessed objects.
  - Has a `500ms` debounce search on text input.
  - Includes cycle-detection (`visited` sets) to prevent infinite loops when rendering `evtx` data with circular parent-child ID issues.
- **Graph Viewer (Right + D3.js):**
  - Node types dictate visuals (`F` = Green File, `RG` = Purple Registry, `P` = Blue/Red Process).
  - Graph is updated via `d3.forceSimulation()` based on visible nodes from the tree filter.

## 2. Key Developer Gotchas & Past Bugs

1. **Circular References in EVTX Logs:** 
   - Windows audit logs sometimes result in processes that seem to spawn each other or themselves. In JS, recursive tree-walking functions (`buildNodeEl`, `collapseNode`, `subtreeMatches`) MUST maintain a `Set()` of visited IDs. Failure to do so caused `RangeError: Maximum call stack size exceeded`.
2. **Missing Node Meta-Data (`node_type`):**
   - The UI auto-falls back to Process (`P`) if properties like `node_type` or `object_name` aren't passed down. Ensure `events.py` and `app.js`'s `processEvent()` both properly handle new metadata assignments when extending support to new Event IDs.
3. **Mismatched Conda Environments:**
   - The project strictly relies on `python=3.11` to match the exact compiled wheels of `evtx` and other libraries. Running the backend outside the `threatgraph` environment will immediately yield `ModuleNotFoundError`. Always ensure the prompt prefix is `(threatgraph)`.

## 3. Future Improvements
- **JSON Parsing Optimization:** `pyevtx-rs` supports native JSON parsing (`records_json()`). Switching the backend away from `lxml` XML generation towards direct JSON parsing could significantly lower memory footprint and CPU time.
- **Web Workers:** Shifting the `app.js` filtering mechanism to a Web Worker would prevent UI blocking when searching over 50,000+ nodes.
