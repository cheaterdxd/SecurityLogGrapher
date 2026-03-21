# ThreatGraph-MVP — Walkthrough

## What Was Built

A Python CLI tool that parses Windows Event Log (.evtx) files, extracts Process Creation events (Event ID 4688), builds a parent→child process tree, and exports an interactive HTML graph.

## Project Structure

```
SecurityLogGrapher/
├── requirements.txt
├── docs/
│   ├── task.md
│   └── implementation_plan.md
├── threatgraph/
│   ├── __init__.py
│   ├── main.py                    # CLI entry point (Typer)
│   ├── parser/
│   │   └── evtx_parser.py         # EVTX streaming parser
│   ├── normalize/
│   │   └── event_4688.py          # Event 4688 XML → dict normalizer
│   ├── graph/
│   │   └── builder.py             # NetworkX directed graph builder
│   └── visualize/
│       └── pyvis_render.py        # PyVis HTML renderer
└── tests/
    ├── test_normalizer.py         # 6 tests
    ├── test_graph_builder.py      # 9 tests (incl. 5 PID helper tests)
    └── test_integration.py        # 2 end-to-end tests
```

## Environment

- **Conda env:** `threatgraph` (Python 3.12)
- **Activate:** `conda activate threatgraph`

## Usage

```bash
conda activate threatgraph
python -m threatgraph.main run --input security.evtx --output graph.html
```

## Test Results

```
22 passed in 0.85s ✅
```

## Next Step

Provide a real `.evtx` file (export from Windows Event Viewer → Security log) to test end-to-end.
