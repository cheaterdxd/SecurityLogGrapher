"""
ThreatGraph-MVP CLI Entry Point
Parse Windows Event Log → Build Process Graph → Visualize
"""
from __future__ import annotations

import itertools
import logging
import webbrowser
import uvicorn
import typer
import threading
import time

app = typer.Typer(
    help="ThreatGraph - Visualize Windows Process Execution from EVTX logs",
    add_completion=False,
)


@app.command()
def run(
    port: int = typer.Option(
        8050,
        "--port",
        "-p",
        help="Port to run the ThreatGraph web dashboard on",
    ),
    host: str = typer.Option(
        "127.0.0.1",
        "--host",
        help="Host interface to bind the web server to",
    ),
) -> None:
    """
    Launch the ThreatGraph interactive web application.
    Opens entirely in your browser with upload capabilities.
    """
    url = f"http://{host}:{port}"
    typer.echo(f"Starting ThreatGraph web server at {url}")
    typer.echo("Open this URL in your browser. (Opening automatically...)")
    
    # Poll the server until it responds, then open browser
    def _open_browser():
        import urllib.request
        import time
        for _ in range(20):
            try:
                urllib.request.urlopen(url, timeout=0.1)
                break
            except Exception:
                time.sleep(0.25)
        webbrowser.open(url)
        
    threading.Thread(target=_open_browser, daemon=True).start()
    
    # Run FastAPI app via Uvicorn
    uvicorn.run("threatgraph.server:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    app()
