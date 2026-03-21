## Context

The offline CLI `ThreatGraph-MVP` uses a FastAPI backend (`server.py`) with a threaded launcher in `main.py`. Small race conditions and input handling flaws currently affect its robustness.

## Goals / Non-Goals

**Goals:**
- Secure the `/api/stream/{task_id}` endpoint from directory traversal.
- Prevent dangling temporary `.evtx` files if an upload drops.
- Ensure the user's browser opens only when the UI is actually ready to load.

**Non-Goals:**
- A comprehensive rewrite or refactoring of the server framework.

## Decisions

- **Path traversal mitigation**: We will enforce `task_id == Path(task_id).name` and ensure it ends with `.evtx` to prevent navigation outside `gettempdir()`.
- **Upload cleanup**: We will use a `try...except Exception` block in `upload_evtx` to cleanly `unlink()` the temp file before re-raising an `HTTPException`.
- **Browser launch**: In `main.py`, instead of `time.sleep(1.5)`, we will wrap `socket.create_connection` in a loop with a small timeout (e.g., up to 10 attempts over 5 seconds).

## Risks / Trade-offs

- **Polling deadlocks**: Polling the socket could block forever if the server crashes on boot. We will limit the polling loop to a maximum duration (e.g., 20 retries * 0.25s) before giving up quietly.
