"""
Interactive Web Visualization Module
Generate a self-contained HTML file with D3.js for interactive graph exploration.
Supports: zoom, pan, click-to-inspect node details, timeline layout.
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime

import networkx as nx

logger = logging.getLogger(__name__)


def _parse_timestamp(ts: str):
    """Parse ISO timestamp string, return ISO string or empty."""
    if not ts:
        return ""
    try:
        ts = ts.rstrip("Z")
        if "." in ts:
            base, frac = ts.split(".", 1)
            frac = frac[:6]
            ts = f"{base}.{frac}"
        dt = datetime.fromisoformat(ts)
        return dt.isoformat()
    except (ValueError, TypeError):
        return ""


def _short_name(label: str) -> str:
    """Extract just the executable name from full path."""
    if "\\" in label:
        label = label.rsplit("\\", 1)[-1]
    if "/" in label:
        label = label.rsplit("/", 1)[-1]
    return label


def _graph_to_json(graph: nx.DiGraph) -> dict:
    """Convert NetworkX graph to D3-compatible JSON."""
    nodes = []
    for node_id, data in graph.nodes(data=True):
        label = data.get("label", str(node_id))
        nodes.append({
            "id": node_id,
            "label": label,
            "short_name": _short_name(label),
            "pid": data.get("pid", ""),
            "command_line": data.get("command_line", "") or "",
            "timestamp": _parse_timestamp(data.get("timestamp", "")),
            "event_order": data.get("event_order", 0),
            "is_root": graph.in_degree(node_id) == 0,
            "children_count": graph.out_degree(node_id),
        })

    links = []
    for src, dst, data in graph.edges(data=True):
        links.append({
            "source": src,
            "target": dst,
            "type": data.get("type", "CREATED"),
            "timestamp": _parse_timestamp(data.get("timestamp", "")),
        })

    return {"nodes": nodes, "links": links}


# ── HTML Template ───────────────────────────────────────────────────────────
_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatGraph — Process Tree Timeline</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: #0d1117;
    color: #e6edf3;
    overflow: hidden;
    height: 100vh;
    display: flex;
  }

  /* ── Sidebar ── */
  #sidebar {
    width: 380px;
    min-width: 380px;
    background: #161b22;
    border-right: 1px solid #30363d;
    display: flex;
    flex-direction: column;
    z-index: 10;
  }

  #sidebar-header {
    padding: 16px 20px;
    border-bottom: 1px solid #30363d;
    background: #0d1117;
  }

  #sidebar-header h1 {
    font-size: 16px;
    font-weight: 600;
    color: #58a6ff;
    margin-bottom: 6px;
  }

  #sidebar-header .stats {
    font-size: 12px;
    color: #8b949e;
  }

  #sidebar-header .stats span {
    color: #58a6ff;
    font-weight: 600;
  }

  /* Search */
  #search-box {
    padding: 12px 20px;
    border-bottom: 1px solid #30363d;
  }

  #search-input {
    width: 100%;
    padding: 8px 12px;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #e6edf3;
    font-size: 13px;
    outline: none;
    transition: border-color 0.2s;
  }

  #search-input:focus {
    border-color: #58a6ff;
  }

  #search-input::placeholder {
    color: #484f58;
  }

  /* Detail Panel */
  #detail-panel {
    flex: 1;
    overflow-y: auto;
    padding: 0;
  }

  #detail-panel::-webkit-scrollbar { width: 6px; }
  #detail-panel::-webkit-scrollbar-track { background: #161b22; }
  #detail-panel::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }

  .detail-empty {
    padding: 40px 20px;
    text-align: center;
    color: #484f58;
    font-size: 13px;
  }

  .detail-empty .icon { font-size: 36px; margin-bottom: 12px; }

  .detail-content {
    padding: 16px 20px;
  }

  .detail-content h2 {
    font-size: 15px;
    color: #f0f6fc;
    margin-bottom: 4px;
    word-break: break-all;
  }

  .detail-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 600;
    margin-bottom: 16px;
  }

  .badge-root { background: rgba(231, 76, 60, 0.2); color: #e74c3c; }
  .badge-child { background: rgba(52, 152, 219, 0.2); color: #58a6ff; }

  .detail-section {
    margin-bottom: 14px;
  }

  .detail-section label {
    display: block;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: #8b949e;
    margin-bottom: 4px;
  }

  .detail-section .value {
    font-size: 13px;
    color: #e6edf3;
    background: #0d1117;
    padding: 8px 10px;
    border-radius: 6px;
    border: 1px solid #21262d;
    word-break: break-all;
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    line-height: 1.5;
  }

  .detail-section .value.empty {
    color: #484f58;
    font-style: italic;
  }

  /* Children list */
  .children-list {
    list-style: none;
    padding: 0;
  }

  .children-list li {
    padding: 6px 10px;
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    margin-bottom: 4px;
    font-size: 12px;
    cursor: pointer;
    transition: all 0.15s;
    display: flex;
    justify-content: space-between;
  }

  .children-list li:hover {
    border-color: #58a6ff;
    background: #161b22;
  }

  .children-list li .name { color: #e6edf3; }
  .children-list li .time { color: #8b949e; font-family: monospace; font-size: 11px; }

  /* ── Graph Container ── */
  #graph-container {
    flex: 1;
    position: relative;
    overflow: hidden;
  }

  #graph-container svg {
    width: 100%;
    height: 100%;
  }

  /* Tooltip */
  #tooltip {
    position: absolute;
    pointer-events: none;
    background: #1c2128;
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 8px 12px;
    font-size: 12px;
    color: #e6edf3;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    z-index: 100;
    opacity: 0;
    transition: opacity 0.15s;
    max-width: 300px;
  }

  #tooltip .tt-name { font-weight: 600; color: #58a6ff; margin-bottom: 2px; }
  #tooltip .tt-pid { color: #8b949e; font-size: 11px; }
  #tooltip .tt-time { color: #8b949e; font-size: 11px; }

  /* Time axis labels */
  .time-label {
    fill: #484f58;
    font-family: 'Cascadia Code', 'Fira Code', monospace;
    font-size: 10px;
  }

  .time-grid {
    stroke: #21262d;
    stroke-width: 1;
    stroke-dasharray: 4 4;
  }

  /* Controls overlay */
  #controls {
    position: absolute;
    bottom: 16px;
    right: 16px;
    display: flex;
    gap: 6px;
    z-index: 10;
  }

  #controls button {
    width: 36px;
    height: 36px;
    border-radius: 8px;
    border: 1px solid #30363d;
    background: #161b22;
    color: #e6edf3;
    font-size: 16px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all 0.15s;
  }

  #controls button:hover {
    background: #21262d;
    border-color: #58a6ff;
  }

  /* Timeline indicator */
  #time-indicator {
    position: absolute;
    top: 16px;
    left: 16px;
    background: rgba(22, 27, 34, 0.9);
    border: 1px solid #30363d;
    border-radius: 8px;
    padding: 8px 14px;
    font-size: 12px;
    color: #8b949e;
    z-index: 10;
  }

  #time-indicator .arrow { color: #58a6ff; font-weight: bold; }
</style>
</head>
<body>

<div id="sidebar">
  <div id="sidebar-header">
    <h1>🔍 ThreatGraph</h1>
    <div class="stats">
      <span id="stat-nodes">0</span> nodes · <span id="stat-edges">0</span> edges
    </div>
  </div>

  <div id="search-box">
    <input id="search-input" type="text" placeholder="Search process name, PID, command...">
  </div>

  <div id="detail-panel">
    <div class="detail-empty">
      <div class="icon">👈</div>
      Click a node to inspect details
    </div>
  </div>
</div>

<div id="graph-container">
  <svg id="graph-svg"></svg>

  <div id="tooltip"></div>

  <div id="time-indicator">
    <span class="arrow">▲</span> Earlier &nbsp;&mdash;&nbsp; Later <span class="arrow">▼</span>
  </div>

  <div id="controls">
    <button id="btn-zoom-in" title="Zoom In">+</button>
    <button id="btn-zoom-out" title="Zoom Out">−</button>
    <button id="btn-reset" title="Reset View">⟳</button>
  </div>
</div>

<script>
// ── Graph Data (injected by Python) ──
const GRAPH_DATA = %%GRAPH_JSON%%;

// ── Setup ──
const svg = d3.select("#graph-svg");
const container = document.getElementById("graph-container");
const tooltip = document.getElementById("tooltip");
const width = container.clientWidth;
const height = container.clientHeight;

document.getElementById("stat-nodes").textContent = GRAPH_DATA.nodes.length;
document.getElementById("stat-edges").textContent = GRAPH_DATA.links.length;

// ── Zoom ──
const zoom = d3.zoom()
  .scaleExtent([0.1, 8])
  .on("zoom", (event) => g.attr("transform", event.transform));
svg.call(zoom);

const g = svg.append("g");

// ── Compute Timeline Positions ──
function computePositions(nodes, links) {
  // Sort nodes by timestamp, then event_order
  const sorted = [...nodes].sort((a, b) => {
    if (a.timestamp && b.timestamp) {
      if (a.timestamp < b.timestamp) return -1;
      if (a.timestamp > b.timestamp) return 1;
    } else if (a.timestamp && !b.timestamp) return 1;
    else if (!a.timestamp && b.timestamp) return -1;
    return a.event_order - b.event_order;
  });

  const ROW_HEIGHT = 50;
  const COL_WIDTH = 180;
  const MARGIN_TOP = 60;
  const MARGIN_LEFT = 160;

  // Assign Y by time groups, X by parent relationship
  const timeGroups = new Map();  // timestamp -> group index
  let groupIdx = 0;

  sorted.forEach(n => {
    const key = n.timestamp || `_order_${n.event_order}`;
    if (!timeGroups.has(key)) {
      timeGroups.set(key, groupIdx++);
    }
  });

  // Build parent->children map
  const childrenOf = new Map();
  links.forEach(l => {
    const src = typeof l.source === 'object' ? l.source.id : l.source;
    const tgt = typeof l.target === 'object' ? l.target.id : l.target;
    if (!childrenOf.has(src)) childrenOf.set(src, []);
    childrenOf.get(src).push(tgt);
  });

  // Count siblings at each Y level
  const levelCounts = new Map();

  sorted.forEach(n => {
    const key = n.timestamp || `_order_${n.event_order}`;
    const yGroup = timeGroups.get(key);
    const y = MARGIN_TOP + yGroup * ROW_HEIGHT;

    if (!levelCounts.has(y)) levelCounts.set(y, 0);
    const xIdx = levelCounts.get(y);
    levelCounts.set(y, xIdx + 1);

    n.x = MARGIN_LEFT + xIdx * COL_WIDTH;
    n.y = y;
  });

  // Center each row
  const rowNodes = new Map();
  sorted.forEach(n => {
    if (!rowNodes.has(n.y)) rowNodes.set(n.y, []);
    rowNodes.get(n.y).push(n);
  });

  rowNodes.forEach((nodesInRow, y) => {
    const totalWidth = (nodesInRow.length - 1) * COL_WIDTH;
    const startX = MARGIN_LEFT + Math.max(0, (width - 400 - totalWidth) / 2);
    nodesInRow.forEach((n, i) => {
      n.x = startX + i * COL_WIDTH;
    });
  });

  return sorted;
}

const positionedNodes = computePositions(GRAPH_DATA.nodes, GRAPH_DATA.links);
const nodeMap = new Map(positionedNodes.map(n => [n.id, n]));

// ── Time grid lines and labels ──
const timeGroups = new Map();
positionedNodes.forEach(n => {
  if (n.timestamp && !timeGroups.has(n.y)) {
    timeGroups.set(n.y, n.timestamp);
  }
});

const maxX = d3.max(positionedNodes, d => d.x) + 200;

timeGroups.forEach((ts, y) => {
  // Grid line
  g.append("line")
    .attr("class", "time-grid")
    .attr("x1", 0)
    .attr("x2", maxX)
    .attr("y1", y)
    .attr("y2", y);

  // Time label
  const date = new Date(ts);
  const timeStr = date.toLocaleTimeString('en-US', { hour12: false });
  g.append("text")
    .attr("class", "time-label")
    .attr("x", 8)
    .attr("y", y + 4)
    .text(timeStr);
});

// ── Draw edges ──
const linkGroup = g.append("g").attr("class", "links");
const edgeElements = linkGroup.selectAll("path")
  .data(GRAPH_DATA.links)
  .join("path")
  .attr("d", d => {
    const src = nodeMap.get(typeof d.source === 'object' ? d.source.id : d.source);
    const tgt = nodeMap.get(typeof d.target === 'object' ? d.target.id : d.target);
    if (!src || !tgt) return "";
    const midY = (src.y + tgt.y) / 2;
    return `M${src.x},${src.y} C${src.x},${midY} ${tgt.x},${midY} ${tgt.x},${tgt.y}`;
  })
  .attr("fill", "none")
  .attr("stroke", "#4a90d9")
  .attr("stroke-width", 1.5)
  .attr("stroke-opacity", 0.4)
  .attr("marker-end", "url(#arrowhead)");

// Arrow marker
svg.append("defs").append("marker")
  .attr("id", "arrowhead")
  .attr("viewBox", "0 -5 10 10")
  .attr("refX", 18)
  .attr("refY", 0)
  .attr("markerWidth", 6)
  .attr("markerHeight", 6)
  .attr("orient", "auto")
  .append("path")
  .attr("d", "M0,-5L10,0L0,5")
  .attr("fill", "#4a90d9");

// ── Draw nodes ──
const nodeGroup = g.append("g").attr("class", "nodes");
const nodeElements = nodeGroup.selectAll("g")
  .data(positionedNodes)
  .join("g")
  .attr("transform", d => `translate(${d.x},${d.y})`)
  .style("cursor", "pointer");

// Node circles
nodeElements.append("circle")
  .attr("r", d => d.is_root ? 10 : 7)
  .attr("fill", d => d.is_root ? "#e74c3c" : "#3498db")
  .attr("stroke", "#fff")
  .attr("stroke-width", d => d.is_root ? 2 : 1)
  .attr("opacity", 0.9);

// Node labels
nodeElements.append("text")
  .text(d => d.short_name)
  .attr("dx", 14)
  .attr("dy", 4)
  .attr("fill", "#c9d1d9")
  .attr("font-size", "11px")
  .attr("font-family", "Segoe UI, system-ui, sans-serif");

// ── Node interactions ──
let selectedNode = null;

nodeElements.on("click", (event, d) => {
  event.stopPropagation();
  selectNode(d);
});

nodeElements.on("mouseover", (event, d) => {
  const rect = container.getBoundingClientRect();
  const [mx, my] = d3.pointer(event, container);

  tooltip.innerHTML = `
    <div class="tt-name">${d.short_name}</div>
    <div class="tt-pid">PID: ${d.pid}</div>
    ${d.timestamp ? `<div class="tt-time">${new Date(d.timestamp).toLocaleString()}</div>` : ''}
  `;
  tooltip.style.left = (mx + 16) + "px";
  tooltip.style.top = (my - 10) + "px";
  tooltip.style.opacity = 1;

  // Highlight connected edges
  edgeElements.attr("stroke-opacity", e => {
    const srcId = typeof e.source === 'object' ? e.source.id : e.source;
    const tgtId = typeof e.target === 'object' ? e.target.id : e.target;
    return (srcId === d.id || tgtId === d.id) ? 0.9 : 0.15;
  }).attr("stroke-width", e => {
    const srcId = typeof e.source === 'object' ? e.source.id : e.source;
    const tgtId = typeof e.target === 'object' ? e.target.id : e.target;
    return (srcId === d.id || tgtId === d.id) ? 2.5 : 1;
  });
});

nodeElements.on("mouseout", () => {
  tooltip.style.opacity = 0;
  if (!selectedNode) {
    edgeElements.attr("stroke-opacity", 0.4).attr("stroke-width", 1.5);
  }
});

svg.on("click", () => {
  deselectNode();
});

// ── Detail panel ──
function selectNode(d) {
  selectedNode = d;

  // Highlight node
  nodeElements.select("circle")
    .attr("stroke", n => n.id === d.id ? "#f0c674" : "#fff")
    .attr("stroke-width", n => n.id === d.id ? 3 : (n.is_root ? 2 : 1));

  // Highlight edges
  edgeElements.attr("stroke-opacity", e => {
    const srcId = typeof e.source === 'object' ? e.source.id : e.source;
    const tgtId = typeof e.target === 'object' ? e.target.id : e.target;
    return (srcId === d.id || tgtId === d.id) ? 0.9 : 0.1;
  }).attr("stroke-width", e => {
    const srcId = typeof e.source === 'object' ? e.source.id : e.source;
    const tgtId = typeof e.target === 'object' ? e.target.id : e.target;
    return (srcId === d.id || tgtId === d.id) ? 2.5 : 1;
  });

  // Find children and parent
  const children = GRAPH_DATA.links
    .filter(l => (typeof l.source === 'object' ? l.source.id : l.source) === d.id)
    .map(l => nodeMap.get(typeof l.target === 'object' ? l.target.id : l.target))
    .filter(Boolean);

  const parents = GRAPH_DATA.links
    .filter(l => (typeof l.target === 'object' ? l.target.id : l.target) === d.id)
    .map(l => nodeMap.get(typeof l.source === 'object' ? l.source.id : l.source))
    .filter(Boolean);

  const timeStr = d.timestamp ? new Date(d.timestamp).toLocaleString() : 'N/A';

  let html = `<div class="detail-content">`;
  html += `<h2>${d.label}</h2>`;
  html += `<span class="detail-badge ${d.is_root ? 'badge-root' : 'badge-child'}">${d.is_root ? 'ROOT' : 'CHILD'}</span>`;

  html += `<div class="detail-section"><label>Process ID (PID)</label><div class="value">${d.pid}</div></div>`;
  html += `<div class="detail-section"><label>Timestamp</label><div class="value">${timeStr}</div></div>`;
  html += `<div class="detail-section"><label>Process Name</label><div class="value">${d.label || '<em>N/A</em>'}</div></div>`;

  if (d.command_line) {
    html += `<div class="detail-section"><label>Command Line</label><div class="value">${escapeHtml(d.command_line)}</div></div>`;
  } else {
    html += `<div class="detail-section"><label>Command Line</label><div class="value empty">Not captured</div></div>`;
  }

  // Parent
  if (parents.length > 0) {
    html += `<div class="detail-section"><label>Parent Process</label><ul class="children-list">`;
    parents.forEach(p => {
      const t = p.timestamp ? new Date(p.timestamp).toLocaleTimeString('en-US', {hour12: false}) : '';
      html += `<li data-id="${p.id}"><span class="name">${p.short_name} (PID ${p.pid})</span><span class="time">${t}</span></li>`;
    });
    html += `</ul></div>`;
  }

  // Children
  if (children.length > 0) {
    html += `<div class="detail-section"><label>Child Processes (${children.length})</label><ul class="children-list">`;
    children.forEach(c => {
      const t = c.timestamp ? new Date(c.timestamp).toLocaleTimeString('en-US', {hour12: false}) : '';
      html += `<li data-id="${c.id}"><span class="name">${c.short_name} (PID ${c.pid})</span><span class="time">${t}</span></li>`;
    });
    html += `</ul></div>`;
  }

  html += `</div>`;
  document.getElementById("detail-panel").innerHTML = html;

  // Make children/parent items clickable
  document.querySelectorAll(".children-list li").forEach(li => {
    li.addEventListener("click", () => {
      const targetId = li.getAttribute("data-id");
      const targetNode = nodeMap.get(targetId);
      if (targetNode) {
        selectNode(targetNode);
        // Pan to node
        const t = d3.zoomIdentity.translate(width/2 - targetNode.x, height/2 - targetNode.y);
        svg.transition().duration(500).call(zoom.transform, t);
      }
    });
  });
}

function deselectNode() {
  selectedNode = null;
  nodeElements.select("circle")
    .attr("stroke", "#fff")
    .attr("stroke-width", d => d.is_root ? 2 : 1);
  edgeElements.attr("stroke-opacity", 0.4).attr("stroke-width", 1.5);
  document.getElementById("detail-panel").innerHTML =
    '<div class="detail-empty"><div class="icon">👈</div>Click a node to inspect details</div>';
}

function escapeHtml(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

// ── Search ──
const searchInput = document.getElementById("search-input");
searchInput.addEventListener("input", () => {
  const q = searchInput.value.toLowerCase().trim();
  if (!q) {
    nodeElements.attr("opacity", 1);
    edgeElements.attr("stroke-opacity", 0.4);
    return;
  }

  nodeElements.attr("opacity", d => {
    const match = d.short_name.toLowerCase().includes(q)
      || String(d.pid).includes(q)
      || (d.command_line && d.command_line.toLowerCase().includes(q))
      || d.label.toLowerCase().includes(q);
    return match ? 1 : 0.1;
  });
});

// ── Controls ──
document.getElementById("btn-zoom-in").onclick = () =>
  svg.transition().duration(300).call(zoom.scaleBy, 1.4);
document.getElementById("btn-zoom-out").onclick = () =>
  svg.transition().duration(300).call(zoom.scaleBy, 0.7);
document.getElementById("btn-reset").onclick = () =>
  svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity);

// ── Initial fit ──
setTimeout(() => {
  const bounds = g.node().getBBox();
  const fullW = bounds.width + 80;
  const fullH = bounds.height + 80;
  const scale = Math.min(width / fullW, height / fullH, 1.5);
  const tx = (width - fullW * scale) / 2 - bounds.x * scale;
  const ty = (height - fullH * scale) / 2 - bounds.y * scale;
  svg.transition().duration(600)
    .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
}, 100);
</script>
</body>
</html>"""


def render_web_graph(graph: nx.DiGraph, output_file: str) -> None:
    """
    Render graph as an interactive HTML file using D3.js.

    Args:
        graph: NetworkX DiGraph with attributes: label, pid, command_line, timestamp
        output_file: Path for the output HTML file
    """
    if graph.number_of_nodes() == 0:
        logger.warning("Empty graph, nothing to render.")
        return

    data = _graph_to_json(graph)
    json_str = json.dumps(data, ensure_ascii=False)

    html = _HTML_TEMPLATE.replace("%%GRAPH_JSON%%", json_str)

    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("Interactive graph saved to %s (%d nodes, %d edges)",
                output_file, graph.number_of_nodes(), graph.number_of_edges())
