from __future__ import annotations

import logging
from pathlib import Path
from tempfile import NamedTemporaryFile

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from threatgraph.parser.evtx_parser import parse_evtx
from threatgraph.normalize.events import normalize_event
import json
import asyncio

logger = logging.getLogger("threatgraph.server")

app = FastAPI(title="ThreatGraph Web UI")

# Mount static files
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main index.html file."""
    index_file = static_dir / "index.html"
    if not index_file.exists():
        raise HTTPException(status_code=404, detail="index.html not found in static folder.")
    return index_file.read_text(encoding="utf-8")


@app.post("/api/upload")
async def upload_evtx(file: UploadFile = File(...)):
    """
    Receive an uploaded .evtx file, save it temporarily, and return a task ID.
    The frontend will connect via SSE to stream the parse progress.
    """
    if not file.filename.lower().endswith(".evtx"):
        raise HTTPException(status_code=400, detail="Only .evtx files are supported.")

    tmp_path = None
    try:
        tmp = NamedTemporaryFile(delete=False, suffix=".evtx")
        tmp_path = tmp.name
        chunk = await file.read(1024 * 1024)  # 1MB chunks
        while chunk:
            tmp.write(chunk)
            chunk = await file.read(1024 * 1024)
        tmp.close()
        
        task_id = Path(tmp_path).name
        logger.info("Saved upload to %s, task ID: %s", tmp_path, task_id)
        return {"task_id": task_id}
    except Exception as e:
        logger.error("Failed to save uploaded file: %s", e)
        if tmp_path:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
        raise HTTPException(status_code=500, detail="Failed to save uploaded file.")


@app.get("/api/stream/{task_id}")
async def stream_evtx(task_id: str):
    """
    Server-Sent Events endpoint.
    Parses the EVTX file record by record and yields batches of parsed events.
    Deletes the temporary file upon completion.
    """
    import tempfile
    
    # Secure task_id against directory traversal
    task_id = Path(task_id).name
    if not task_id.endswith(".evtx"):
        raise HTTPException(status_code=400, detail="Invalid task ID")
        
    tmp_path = Path(tempfile.gettempdir()) / task_id

    if not tmp_path.exists() or not str(tmp_path).endswith(".evtx"):
        raise HTTPException(status_code=404, detail="Task ID not found or invalid.")

    async def event_generator():
        from threatgraph.correlation.engine import CorrelationEngine
        engine = CorrelationEngine()
        
        try:
            raw_events = parse_evtx(str(tmp_path))
            
            batch = []
            count = 0
            
            for raw_xml in raw_events:
                event = normalize_event(raw_xml)
                if event is not None:
                    enriched_event = engine.process_event(event)
                    batch.append(enriched_event)
                    count += 1
                
                # yield batch every 200 events to prevent massive JSON lines and keep UI snappy
                if len(batch) >= 200:
                    yield f"data: {json.dumps(batch)}\n\n"
                    # Small sleep to allow HTTP stream chunking
                    await asyncio.sleep(0.01)
                    batch = []

            # Flush remaining events
            if batch:
                yield f"data: {json.dumps(batch)}\n\n"
                
            # Signal completion
            logger.info("Streaming complete for %s. Delivered %d events.", task_id, count)
            yield "event: done\ndata: {}\n\n"
            
        except Exception as e:
            logger.exception("Error during SSE streaming:")
            yield f"event: error\ndata: {json.dumps({'detail': str(e)})}\n\n"
        finally:
            # Always clean up the temporary file
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return StreamingResponse(event_generator(), media_type="text/event-stream")
