# SecurityLogGrapher

SecurityLogGrapher is a fast, web-based tool for visualizing Windows Event Logs (`.evtx`). It parses security events (like Process Creation and Object Access) and renders them as an interactive graph to help analyze threats and execution chains.

## Features
- **Ultra-fast Parsing:** Powered by the Rust-based `evtx` library (via `pyevtx-rs`) for parsing EVTX files rapidly without heavy memory overhead.
- **Real-time Streaming:** Uses Server-Sent Events (SSE) to stream parsed logs to the frontend and render the graph progressively.
- **Interactive Visualization:** Powered by D3.js. Supports zooming, panning, and expanding/collapsing process nodes.
- **Deep Filtering:** Instant client-side search by Process Name, Process ID, Event ID, and Command Line.
- **Event Support:**
  - `4688`: Process Creation (Process Nodes `P`)
  - `4663`: File Server Object Access (File Nodes `F`)
  - `4657`: Registry Value Modified (Registry Nodes `RG`) 

## Setup Instructions

### 1. Prerequisites
You need **Conda / Miniconda** installed on your system.
This project uses **Python 3.11**.

### 2. Environment Setup
We use the `environment.yml` and `requirements.txt` to guarantee reproducibility.

```bash
# Create the environment from the config file
conda env create -f environment.yml

# Or if the environment already exists, activate and install:
conda activate threatgraph
pip install -r requirements.txt
```

### 3. Running the Application

Always ensure your environment is activated:
```bash
conda activate threatgraph
```

Start the FastAPI web server:
```bash
python -m threatgraph.main
```

The application will start on `http://127.0.0.1:8050`. Open it in your browser, upload an `.evtx` file, and start exploring.

## Code Structure (Overview)
- `threatgraph.main`: Typer CLI and Unicorn entry point.
- `threatgraph.server`: FastAPI endpoints (upload, SSE streaming API).
- `threatgraph.parser.evtx_parser`: Invokes the Rust-based `PyEvtxParser` to yield XML strings rapidly.
- `threatgraph.normalize.events`: Normalizes XML into Python dictionary objects (extracting PIDs, Command Lines, node types).
- `threatgraph.static.js.app.js`: Vanilla JavaScript handling tree rendering, search filtering, and D3 graph logic.

*(For a deeper view into the architecture and internal design, see `ARCHITECTURE.md`)*
