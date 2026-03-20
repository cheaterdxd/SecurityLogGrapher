# ThreatGraph-MVP — Implementation Plan

**Mục tiêu:** Xây dựng CLI tool offline bằng Python, parse file Windows Event Log (.evtx), trích xuất Event ID 4688 (Process Creation), xây dựng process tree (parent→child) dưới dạng directed graph, và xuất ra file HTML tương tác.

## Proposed Changes

### Component 1: Project Scaffold

#### [NEW] [requirements.txt](file:///c:/Users/ANM-TUANLT26/code/SecurityLogGrapher/requirements.txt)
```txt
python-evtx
networkx
pyvis
typer
lxml
pytest
```

#### [NEW] Package directories
Tạo cấu trúc thư mục theo spec:
```
threatgraph/
├── __init__.py
├── parser/
│   ├── __init__.py
│   └── evtx_parser.py
├── normalize/
│   ├── __init__.py
│   └── event_4688.py
├── graph/
│   ├── __init__.py
│   └── builder.py
├── visualize/
│   ├── __init__.py
│   └── pyvis_render.py
└── main.py
```

---

### Component 2: EVTX Parser — `parser/evtx_parser.py`

- Sử dụng thư viện `python-evtx`
- **Streaming** — yield từng record, không load toàn bộ file vào RAM
- Bỏ qua (skip) các record bị lỗi/malformed

---

### Component 3: Event Normalizer — `normalize/event_4688.py`

- Sử dụng `lxml.etree` để parse XML
- Chỉ xử lý Event ID `4688`, trả về `None` cho các event khác
- Handle missing `CommandLine` (set `None`)
- Cast PID/PPID về `int` (hex → int)

---

### Component 4: Graph Builder — `graph/builder.py`

- Mỗi process là 1 **node** (id = `pid_{pid}`)
- Mỗi quan hệ parent→child là 1 **edge** (type = `CREATED`)
- Node attributes: `label`, `pid`, `command_line`

---

### Component 5: Visualization — `visualize/pyvis_render.py`

- Node label = `process_name`, tooltip = PID + command_line
- Interactive: zoom, drag, click
- Output: self-contained HTML file

---

### Component 6: CLI Entry Point — `main.py`

- CLI interface sử dụng `typer`
- Pipeline: `parse → normalize → filter → build graph → render`
- Generator/lazy evaluation cho ≥ 100k events

---

## Verification Plan

### Automated Tests
```bash
pytest tests/ -v
```

### Manual Verification
1. Chạy: `python -m threatgraph.main run --input <file>.evtx --output graph.html`
2. Mở `graph.html` trong trình duyệt
3. Verify: graph nodes, zoom/drag, hover tooltip
