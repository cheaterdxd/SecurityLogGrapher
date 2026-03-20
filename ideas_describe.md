Hiểu đúng yêu cầu:
👉 MVP của bạn **chỉ tập trung vào 1 việc duy nhất**:

> **Windows Security Log → Process Graph → Visualize**

# 🧠 PROJECT SPEC (MVP - GRAPH ONLY)

## 1. Overview

**Tên:** ThreatGraph-MVP
**Loại:** CLI tool (offline)
**Mục tiêu:**

> Parse Windows Event Log (EVTX) → xây dựng **process graph (parent-child)** → visualize graph

---

## 2. Scope (STRICT)

### ✅ Bao gồm:

* Parse `.evtx`
* Extract Event ID 4688
* Build process tree (parent → child)
* Export graph HTML

### ❌ Không bao gồm:

* Detection
* Rule engine
* ML
* Multi-event correlation
* UI web app

---

## 3. Input Specification

### Input

* File `.evtx`

### Target Event

* Event ID: `4688`

---

## 4. Normalized Schema (tối giản)

```python
NormalizedEvent = {
    "timestamp": str,
    "pid": int,
    "ppid": int,
    "process_name": str,
    "command_line": str | None
}
```

👉 Lưu ý:

* Không cần user
* Không cần host (MVP)

---

## 5. Graph Model

### Graph type

* Directed Graph

---

### Node

```python
{
    "id": "pid_1234",
    "label": "powershell.exe",
    "pid": 1234,
    "command_line": "powershell -enc ..."
}
```

---

### Edge

```python
{
    "source": "pid_1000",
    "target": "pid_1234",
    "type": "CREATED"
}
```

---

## 6. Project Structure

```bash
threatgraph/
│
├── parser/
│   └── evtx_parser.py
│
├── normalize/
│   └── event_4688.py
│
├── graph/
│   └── builder.py
│
├── visualize/
│   └── pyvis_render.py
│
├── main.py
└── requirements.txt
```

---

## 7. Module Specification

---

## 7.1 parser/evtx_parser.py

```python
def parse_evtx(file_path: str):
    """
    Input: path to .evtx
    Output: generator of raw XML strings
    """
```

### Implementation requirement

* Use `python-evtx`
* Yield từng event (KHÔNG load full file)

---

## 7.2 normalize/event_4688.py

```python
def normalize_event(xml_event: str) -> dict | None:
    """
    Parse XML → extract fields for Event ID 4688
    Return normalized dict or None if not 4688
    """
```

### Extract fields:

* EventID
* TimeCreated
* NewProcessId
* ProcessId (parent)
* NewProcessName
* CommandLine

---

## 7.3 graph/builder.py

```python
import networkx as nx

class GraphBuilder:
    def __init__(self):
        self.graph = nx.DiGraph()

    def add_event(self, event: dict):
        """
        Add nodes + edge from event
        """

    def build(self, events):
        """
        Iterate events → build graph
        return graph
        """
```

---

### Logic

```python
parent_id = f"pid_{event['ppid']}"
child_id = f"pid_{event['pid']}"

# Add parent node if not exists
# Add child node if not exists
# Add edge parent → child
```

---

## 7.4 visualize/pyvis_render.py

```python
from pyvis.network import Network

def render_graph(graph, output_file: str):
    """
    Convert networkx graph → HTML visualization
    """
```

---

### Requirements

* Node label = process_name
* Tooltip:

  * PID
  * command_line

---

## 7.5 main.py

### Framework

* `typer`

---

### Command

```bash
python main.py run --input security.evtx --output graph.html
```

---

### Logic

```python
events = parse_evtx(input)
normalized = (normalize_event(e) for e in events)
filtered = (e for e in normalized if e is not None)

graph = GraphBuilder().build(filtered)

render_graph(graph, output)
```

---

## 8. Dependencies

```txt
python-evtx
networkx
pyvis
typer
lxml
```

---

## 9. Performance Requirements

* Streaming processing (generator)
* Không load toàn bộ log vào RAM
* Handle ≥ 100k events

---

## 10. Output

### File HTML

Graph interactive:

* Zoom / drag
* Node clickable
* Hover → show command line

---

## 11. Constraints

* No database
* No web server
* Offline only
* Python 3.10+

---

## 12. Implementation Notes

* Use `lxml` để parse XML nhanh hơn built-in
* Ignore malformed events
* Ensure PID cast về int
* Handle missing command_line (set None)

---

# 🔥 Minimal Working Flow

```python
parse → normalize → build graph → render
```

Không branching, không logic phức tạp.
