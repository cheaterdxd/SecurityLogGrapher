## Why

The current web CLI has minor reliability and security flaws: a potential path traversal vulnerability in the SSE event streaming, a resource leak during file uploads, and a race condition when auto-opening the browser. Fixing these issues will improve the overall security and robust operation of ThreatGraph-MVP.

## What Changes

- Add strict validation to `task_id` endpoints to prevent directory traversal.
- Ensure the uploaded `.evtx` temporary file is properly deleted if an exception occurs mid-upload.
- Implement a TCP socket probe to wait for the HTTP server to bind before auto-opening the browser, instead of a blind sleep.

## Capabilities

### New Capabilities
- `server-hardening`: Validation and resource handling to harden the web application.

## Impact

- `threatgraph/server.py`: Changes to `upload_evtx` and `stream_evtx`.
- `threatgraph/main.py`: Replaces `time.sleep` with socket polling in the thread.
