"""
Lazy Expand Tree + Chain Graph Visualization
Left panel: Tree explorer with lazy-expand (roots → click to expand children)
Right panel: D3.js graph showing the chain of the selected node + node detail on click
"""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime

import networkx as nx

logger = logging.getLogger(__name__)


def _parse_ts(ts: str) -> str:
    if not ts:
        return ""
    try:
        ts = ts.rstrip("Z")
        if "." in ts:
            base, frac = ts.split(".", 1)
            ts = f"{base}.{frac[:6]}"
        return datetime.fromisoformat(ts).isoformat()
    except (ValueError, TypeError):
        return ""


def _short(label: str) -> str:
    if "\\" in label:
        label = label.rsplit("\\", 1)[-1]
    if "/" in label:
        label = label.rsplit("/", 1)[-1]
    return label


def _build_tree_data(graph: nx.DiGraph) -> dict:
    nodes = {}
    for nid, data in graph.nodes(data=True):
        label = data.get("label", str(nid))
        nodes[nid] = {
            "id": nid,
            "label": label,
            "short_name": _short(label),
            "pid": data.get("pid", ""),
            "command_line": data.get("command_line", "") or "",
            "timestamp": _parse_ts(data.get("timestamp", "")),
            "event_order": data.get("event_order", 0),
            "is_root": graph.in_degree(nid) == 0,
            "children_count": graph.out_degree(nid),
            "raw_xml": data.get("raw_xml", ""),
        }

    children_map = {}
    for src, dst, data in graph.edges(data=True):
        if src not in children_map:
            children_map[src] = []
        children_map[src].append({
            "id": dst,
            "timestamp": _parse_ts(data.get("timestamp", "")),
        })

    for parent_id in children_map:
        children_map[parent_id].sort(
            key=lambda c: (c["timestamp"] or "", nodes.get(c["id"], {}).get("event_order", 0))
        )
        children_map[parent_id] = [c["id"] for c in children_map[parent_id]]

    parent_map = {}
    for src, dst in graph.edges():
        parent_map[dst] = src

    roots = sorted(
        [nid for nid in graph.nodes() if graph.in_degree(nid) == 0],
        key=lambda nid: (nodes[nid]["timestamp"] or "", nodes[nid]["event_order"]),
    )

    return {
        "nodes": nodes,
        "children_map": children_map,
        "parent_map": parent_map,
        "roots": roots,
        "total_nodes": graph.number_of_nodes(),
        "total_edges": graph.number_of_edges(),
    }


_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ThreatGraph — Process Tree Explorer</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
  * { margin:0; padding:0; box-sizing:border-box; }

  body {
    font-family: 'Inter', system-ui, sans-serif;
    background: #0d1117; color: #e6edf3;
    height: 100vh; display: flex; overflow: hidden;
  }

  /* ── LEFT: Tree Panel ── */
  #tree-panel {
    width: 400px; min-width: 400px;
    display: flex; flex-direction: column;
    border-right: 1px solid #30363d;
    background: #0d1117;
  }
  #tree-header {
    padding: 12px 16px;
    border-bottom: 1px solid #30363d;
    background: #161b22;
  }
  #tree-header h1 {
    font-size: 14px; font-weight: 700; color: #58a6ff;
    margin-bottom: 4px;
  }
  .stats-bar {
    display: flex; gap: 14px;
    font-size: 11px; color: #8b949e;
  }
  .stats-bar span { color: #58a6ff; font-weight: 600; }

  #search-box { padding: 8px 16px; border-bottom: 1px solid #21262d; }
  #search-input {
    width: 100%; padding: 7px 10px 7px 30px;
    background: #161b22; border: 1px solid #30363d;
    border-radius: 6px; color: #e6edf3; font-size: 12px;
    font-family: 'Inter', sans-serif; outline: none;
  }
  #search-input:focus { border-color: #58a6ff; }
  #search-input::placeholder { color: #484f58; }
  .search-wrapper { position: relative; }
  .search-icon {
    position: absolute; left: 8px; top: 50%;
    transform: translateY(-50%); color: #484f58; font-size: 12px;
  }

  .action-bar {
    padding: 5px 16px; border-bottom: 1px solid #21262d;
    display: flex; gap: 6px;
  }
  .action-btn {
    padding: 3px 8px; border-radius: 5px;
    border: 1px solid #30363d; background: #161b22;
    color: #8b949e; font-size: 10px; cursor: pointer;
    font-family: 'Inter', sans-serif;
  }
  .action-btn:hover { background: #21262d; color: #e6edf3; }

  #tree-container { flex: 1; overflow-y: auto; padding: 4px 0; }
  #tree-container::-webkit-scrollbar { width: 5px; }
  #tree-container::-webkit-scrollbar-track { background: transparent; }
  #tree-container::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }

  .tree-node { user-select: none; }
  .tree-node-row {
    display: flex; align-items: center;
    padding: 3px 10px 3px 0; cursor: pointer;
    transition: background 0.1s;
  }
  .tree-node-row:hover { background: #161b22; }
  .tree-node-row.selected {
    background: #1f2937; border-left: 3px solid #58a6ff;
  }
  .tree-node-row.selected .node-name { color: #58a6ff; }

  .expand-btn {
    width: 18px; height: 18px;
    display: flex; align-items: center; justify-content: center;
    font-size: 9px; color: #484f58; flex-shrink: 0;
    transition: transform 0.15s; border-radius: 3px;
  }
  .expand-btn:hover { color: #e6edf3; background: #21262d; }
  .expand-btn.expanded { transform: rotate(90deg); color: #8b949e; }
  .expand-btn.leaf { visibility: hidden; }

  .node-icon {
    width: 16px; height: 16px; border-radius: 3px;
    display: flex; align-items: center; justify-content: center;
    font-size: 9px; flex-shrink: 0; margin-right: 6px;
  }
  .icon-root { background: rgba(231,76,60,0.2); color: #e74c3c; }
  .icon-child { background: rgba(52,152,219,0.2); color: #58a6ff; }

  .node-name {
    font-size: 12px; color: #c9d1d9; font-weight: 500;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1;
  }
  .node-meta {
    font-size: 10px; color: #484f58;
    font-family: 'JetBrains Mono', monospace;
    margin-left: 6px; flex-shrink: 0;
  }
  .node-badge {
    font-size: 9px; padding: 1px 5px; border-radius: 8px;
    margin-left: 4px; flex-shrink: 0; font-weight: 600;
    background: rgba(88,166,255,0.15); color: #58a6ff;
  }

  .tree-children { overflow: hidden; }
  .tree-children.collapsed { max-height: 0 !important; }

  .indent-guide {
    display: inline-block; width: 18px; flex-shrink: 0; position: relative;
  }
  .indent-guide::before {
    content: ''; position: absolute; left: 8px; top: 0; bottom: 0;
    width: 1px; background: #21262d;
  }

  #visible-bar {
    padding: 5px 16px; border-top: 1px solid #21262d;
    font-size: 10px; color: #484f58; background: #161b22;
    display: flex; justify-content: space-between;
  }
  #visible-bar span { color: #58a6ff; font-weight: 600; }

  .search-match { background: rgba(240,198,116,0.25); border-radius: 2px; }

  /* ── RIGHT: Graph + Detail ── */
  #right-panel {
    flex: 1; display: flex; flex-direction: column;
    background: #0d1117; overflow: hidden;
  }

  /* Graph area */
  #graph-area {
    flex: 1; position: relative; overflow: hidden;
    border-bottom: 1px solid #30363d;
    min-height: 200px;
  }
  #graph-area svg { width: 100%; height: 100%; }

  #graph-empty {
    position: absolute; inset: 0;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    color: #30363d; font-size: 13px; text-align: center;
    pointer-events: none;
  }
  #graph-empty .ge-icon { font-size: 48px; margin-bottom: 10px; opacity: 0.4; }

  #graph-controls {
    position: absolute; bottom: 10px; right: 10px;
    display: flex; gap: 4px; z-index: 10;
  }
  #graph-controls button {
    width: 28px; height: 28px; border-radius: 6px;
    border: 1px solid #30363d; background: #161b22;
    color: #e6edf3; font-size: 14px; cursor: pointer;
    display: flex; align-items: center; justify-content: center;
  }
  #graph-controls button:hover { background: #21262d; border-color: #58a6ff; }

  #graph-label {
    position: absolute; top: 8px; left: 12px;
    font-size: 11px; color: #484f58; z-index: 10;
    background: rgba(13,17,23,0.8); padding: 4px 10px;
    border-radius: 6px; border: 1px solid #21262d;
  }
  #graph-label span { color: #58a6ff; font-weight: 600; }

  /* Tooltip on graph */
  #graph-tooltip {
    position: absolute; pointer-events: none;
    background: #1c2128; border: 1px solid #30363d;
    border-radius: 8px; padding: 8px 12px;
    font-size: 11px; color: #e6edf3;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    z-index: 100; opacity: 0; max-width: 280px;
  }
  #graph-tooltip .tt-name { font-weight: 600; color: #58a6ff; }
  #graph-tooltip .tt-sub { color: #8b949e; font-size: 10px; margin-top: 2px; }

  /* Detail area */
  #detail-area {
    height: 220px; min-height: 140px;
    overflow-y: auto; padding: 14px 20px;
    background: #161b22;
  }
  #detail-area::-webkit-scrollbar { width: 5px; }
  #detail-area::-webkit-scrollbar-track { background: transparent; }
  #detail-area::-webkit-scrollbar-thumb { background: #30363d; border-radius: 3px; }

  .detail-empty-sm {
    display: flex; align-items: center; justify-content: center;
    height: 100%; color: #30363d; font-size: 12px;
  }

  .detail-title {
    font-size: 13px; font-weight: 600; color: #e6edf3;
    margin-bottom: 10px; display: flex; align-items: center; gap: 8px;
  }
  .detail-title .tag {
    font-size: 9px; padding: 2px 7px; border-radius: 10px; font-weight: 600;
  }
  .tag-root { background: rgba(231,76,60,0.15); color: #e74c3c; }
  .tag-child { background: rgba(52,152,219,0.15); color: #58a6ff; }

  .detail-row {
    display: flex; gap: 12px; margin-bottom: 8px; flex-wrap: wrap;
  }
  .detail-item label {
    display: block; font-size: 9px; text-transform: uppercase;
    letter-spacing: 0.6px; color: #8b949e; font-weight: 600; margin-bottom: 2px;
  }
  .detail-item .dv {
    font-size: 12px; color: #e6edf3;
    background: #0d1117; padding: 6px 10px;
    border-radius: 6px; border: 1px solid #21262d;
    word-break: break-all;
    font-family: 'JetBrains Mono', monospace; line-height: 1.5;
  }
  .detail-item .dv.muted { color: #484f58; font-style: italic; }
  .detail-item.full { flex: 1 1 100%; }
  .detail-item.half { flex: 1 1 45%; min-width: 120px; }

  /* Resize handle */
  #resize-handle {
    height: 4px; background: #21262d; cursor: row-resize;
    transition: background 0.15s;
  }
  #resize-handle:hover { background: #58a6ff; }
</style>
</head>
<body>

<!-- LEFT PANEL: Tree Explorer -->
<div id="tree-panel">
  <div id="tree-header">
    <h1>🔍 ThreatGraph Explorer</h1>
    <div class="stats-bar">
      <div>Total: <span id="stat-total">0</span></div>
      <div>Roots: <span id="stat-roots">0</span></div>
      <div>Visible: <span id="stat-visible">0</span></div>
    </div>
  </div>
  <div id="search-box">
    <div class="search-wrapper">
      <span class="search-icon">🔎</span>
      <input id="search-input" type="text" placeholder="Search process, PID, command...">
    </div>
  </div>
  <div class="action-bar">
    <button class="action-btn" id="btn-expand-all">▸ Expand All</button>
    <button class="action-btn" id="btn-collapse-all">◂ Collapse All</button>
  </div>
  <div id="tree-container"></div>
  <div id="visible-bar">
    <div>Showing <span id="vis-count">0</span> / <span id="vis-total">0</span></div>
    <div>Click ▸ to expand</div>
  </div>
</div>

<!-- RIGHT PANEL: Graph + Detail -->
<div id="right-panel">
  <!-- Chain Graph -->
  <div id="graph-area">
    <svg id="graph-svg"></svg>
    <div id="graph-empty">
      <div class="ge-icon">🔗</div>
      <div>Select a node from the tree<br>to view its process chain graph</div>
    </div>
    <div id="graph-label" style="display:none;">
      Chain: <span id="chain-name">—</span>
      (<span id="chain-count">0</span> nodes)
    </div>
    <div id="graph-tooltip"></div>
    <div id="graph-controls" style="display:none;">
      <button id="gc-zin" title="Zoom In">+</button>
      <button id="gc-zout" title="Zoom Out">−</button>
      <button id="gc-fit" title="Fit">⊡</button>
    </div>
  </div>

  <!-- Resize -->
  <div id="resize-handle"></div>

  <!-- Node Detail -->
  <div id="detail-area">
    <div class="detail-empty-sm">Click a node in the graph to see details</div>
  </div>
</div>

<script>
const D = %%GRAPH_JSON%%;
const nodes = D.nodes;
const childrenMap = D.children_map;
const parentMap = D.parent_map;
const roots = D.roots;

document.getElementById("stat-total").textContent = D.total_nodes;
document.getElementById("stat-roots").textContent = roots.length;
document.getElementById("vis-total").textContent = D.total_nodes;

// ════════════════════════════════════════════════
// TREE EXPLORER (left panel) — same as before
// ════════════════════════════════════════════════
const expanded = new Set();
let selectedTreeId = null;
let visibleCount = 0;
let currentFilter = "";
const treeContainer = document.getElementById("tree-container");

function renderTree(filterText) {
  treeContainer.innerHTML = "";
  visibleCount = 0;
  const frag = document.createDocumentFragment();
  roots.forEach(rid => {
    const el = buildNodeEl(rid, 0, filterText);
    if (el) frag.appendChild(el);
  });
  treeContainer.appendChild(frag);
  document.getElementById("stat-visible").textContent = visibleCount;
  document.getElementById("vis-count").textContent = visibleCount;
}

function buildNodeEl(nodeId, depth, filterText) {
  const node = nodes[nodeId];
  if (!node) return null;
  const children = childrenMap[nodeId] || [];
  const hasChildren = children.length > 0;
  const isExpanded = expanded.has(nodeId);
  const matchesFilter = !filterText || matchNode(node, filterText);
  const childrenMatchFilter = filterText && hasChildren &&
    children.some(cid => subtreeMatches(cid, filterText));
  if (filterText && !matchesFilter && !childrenMatchFilter) return null;
  visibleCount++;

  const wrapper = document.createElement("div");
  wrapper.className = "tree-node";

  const row = document.createElement("div");
  row.className = "tree-node-row" + (selectedTreeId === nodeId ? " selected" : "");

  for (let i = 0; i < depth; i++) {
    const g = document.createElement("span");
    g.className = "indent-guide";
    row.appendChild(g);
  }

  const eb = document.createElement("span");
  eb.className = "expand-btn" + (hasChildren ? (isExpanded ? " expanded" : "") : " leaf");
  eb.textContent = "▶";
  if (hasChildren) {
    eb.addEventListener("click", e => { e.stopPropagation(); toggleExpand(nodeId); });
  }
  row.appendChild(eb);

  const ic = document.createElement("span");
  ic.className = "node-icon " + (node.is_root ? "icon-root" : "icon-child");
  ic.textContent = node.is_root ? "R" : "C";
  row.appendChild(ic);

  const nm = document.createElement("span");
  nm.className = "node-name";
  if (filterText && matchesFilter) {
    nm.innerHTML = highlightText(node.short_name, filterText);
  } else {
    nm.textContent = node.short_name;
  }
  row.appendChild(nm);

  if (node.timestamp) {
    const mt = document.createElement("span");
    mt.className = "node-meta";
    mt.textContent = new Date(node.timestamp).toLocaleTimeString("en-US", {hour12:false});
    row.appendChild(mt);
  }

  if (hasChildren) {
    const bd = document.createElement("span");
    bd.className = "node-badge";
    bd.textContent = children.length;
    row.appendChild(bd);
  }

  row.addEventListener("click", () => selectTreeNode(nodeId));
  wrapper.appendChild(row);

  if (hasChildren) {
    const cc = document.createElement("div");
    cc.className = "tree-children" + (isExpanded ? "" : " collapsed");
    if (isExpanded || (filterText && childrenMatchFilter)) {
      children.forEach(cid => {
        const ce = buildNodeEl(cid, depth + 1, filterText);
        if (ce) cc.appendChild(ce);
      });
      if (filterText && childrenMatchFilter) cc.classList.remove("collapsed");
    }
    wrapper.appendChild(cc);
  }
  return wrapper;
}

function matchNode(n, t) {
  const q = t.toLowerCase();
  return n.short_name.toLowerCase().includes(q)
    || n.label.toLowerCase().includes(q)
    || String(n.pid).includes(q)
    || (n.command_line && n.command_line.toLowerCase().includes(q));
}
function subtreeMatches(nid, t) {
  const n = nodes[nid];
  if (!n) return false;
  if (matchNode(n, t)) return true;
  return (childrenMap[nid] || []).some(c => subtreeMatches(c, t));
}
function highlightText(text, q) {
  const i = text.toLowerCase().indexOf(q.toLowerCase());
  if (i === -1) return esc(text);
  return esc(text.slice(0,i)) + '<span class="search-match">' + esc(text.slice(i,i+q.length)) + '</span>' + esc(text.slice(i+q.length));
}
function esc(s) { const d = document.createElement("div"); d.textContent = s; return d.innerHTML; }

function toggleExpand(nid) {
  if (expanded.has(nid)) collapseNode(nid); else expanded.add(nid);
  renderTree(currentFilter);
}
function collapseNode(nid) {
  expanded.delete(nid);
  (childrenMap[nid] || []).forEach(c => collapseNode(c));
}

function selectTreeNode(nodeId) {
  selectedTreeId = nodeId;
  renderTree(currentFilter);
  renderChainGraph(nodeId);
  setTimeout(() => {
    const sr = treeContainer.querySelector(".tree-node-row.selected");
    if (sr) sr.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, 50);
}

document.getElementById("search-input").addEventListener("input", function() {
  clearTimeout(this._t);
  this._t = setTimeout(() => { currentFilter = this.value.trim(); renderTree(currentFilter); }, 200);
});
document.getElementById("btn-expand-all").onclick = () => { roots.forEach(r => expanded.add(r)); renderTree(currentFilter); };
document.getElementById("btn-collapse-all").onclick = () => { expanded.clear(); renderTree(currentFilter); };

// ════════════════════════════════════════════════
// CHAIN GRAPH (right panel — D3.js)
// ════════════════════════════════════════════════
const graphSvg = d3.select("#graph-svg");
const graphArea = document.getElementById("graph-area");
const tooltip = document.getElementById("graph-tooltip");
let graphG = graphSvg.append("g");
let graphZoom;
let graphNodeId = null;  // currently inspected node in graph

// Build the chain: ancestors → selected → all descendants
function getChainNodes(selectedId) {
  const chainIds = new Set();
  // ancestors
  let cur = selectedId;
  while (cur) { chainIds.add(cur); cur = parentMap[cur]; }
  // descendants (BFS, max depth)
  const queue = [{ id: selectedId, depth: 0 }];
  while (queue.length > 0) {
    const { id, depth } = queue.shift();
    chainIds.add(id);
    if (depth < 50) {
      (childrenMap[id] || []).forEach(cid => {
        if (!chainIds.has(cid)) {
          chainIds.add(cid);
          queue.push({ id: cid, depth: depth + 1 });
        }
      });
    }
  }
  return chainIds;
}

function renderChainGraph(selectedId) {
  // Clear
  graphG.selectAll("*").remove();
  document.getElementById("graph-empty").style.display = "none";
  document.getElementById("graph-label").style.display = "";
  document.getElementById("graph-controls").style.display = "";

  const chainIds = getChainNodes(selectedId);
  const chainNodes = [...chainIds].map(id => nodes[id]).filter(Boolean);
  const chainLinks = [];

  chainIds.forEach(id => {
    (childrenMap[id] || []).forEach(cid => {
      if (chainIds.has(cid)) {
        chainLinks.push({ source: id, target: cid });
      }
    });
  });

  const sel = nodes[selectedId];
  document.getElementById("chain-name").textContent = sel ? sel.short_name : selectedId;
  document.getElementById("chain-count").textContent = chainNodes.length;

  // Layout: tree top→down based on depth from root
  const depthMap = new Map();
  const levelNodes = new Map();

  // Find root of this chain
  let chainRoot = selectedId;
  while (parentMap[chainRoot] && chainIds.has(parentMap[chainRoot])) {
    chainRoot = parentMap[chainRoot];
  }

  // BFS from root to assign depths
  const bfsQueue = [chainRoot];
  depthMap.set(chainRoot, 0);
  const visited = new Set([chainRoot]);

  while (bfsQueue.length > 0) {
    const nid = bfsQueue.shift();
    const depth = depthMap.get(nid);
    if (!levelNodes.has(depth)) levelNodes.set(depth, []);
    levelNodes.get(depth).push(nid);

    (childrenMap[nid] || []).forEach(cid => {
      if (chainIds.has(cid) && !visited.has(cid)) {
        visited.add(cid);
        depthMap.set(cid, depth + 1);
        bfsQueue.push(cid);
      }
    });
  }

  // Also add any chain nodes not visited (disconnected ancestors)
  chainIds.forEach(id => {
    if (!visited.has(id)) {
      const d = -1;
      depthMap.set(id, d);
      if (!levelNodes.has(d)) levelNodes.set(d, []);
      levelNodes.get(d).push(id);
    }
  });

  const ROW_H = 70;
  const COL_W = 140;
  const MARGIN_TOP = 50;
  const MARGIN_LEFT = 40;
  const areaW = graphArea.clientWidth;

  const posMap = new Map();
  levelNodes.forEach((ids, depth) => {
    const totalW = (ids.length - 1) * COL_W;
    const startX = Math.max(MARGIN_LEFT, (areaW - totalW) / 2);
    ids.forEach((id, i) => {
      posMap.set(id, {
        x: startX + i * COL_W,
        y: MARGIN_TOP + depth * ROW_H,
      });
    });
  });

  // Arrow marker
  graphSvg.select("defs").remove();
  graphSvg.append("defs").append("marker")
    .attr("id", "arrow")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 20).attr("refY", 0)
    .attr("markerWidth", 6).attr("markerHeight", 6)
    .attr("orient", "auto")
    .append("path").attr("d", "M0,-5L10,0L0,5").attr("fill", "#4a90d9");

  // Edges
  graphG.selectAll("path.edge")
    .data(chainLinks)
    .join("path")
    .attr("class", "edge")
    .attr("d", d => {
      const s = posMap.get(d.source);
      const t = posMap.get(d.target);
      if (!s || !t) return "";
      const my = (s.y + t.y) / 2;
      return `M${s.x},${s.y} C${s.x},${my} ${t.x},${my} ${t.x},${t.y}`;
    })
    .attr("fill", "none")
    .attr("stroke", "#4a90d9")
    .attr("stroke-width", 1.5)
    .attr("stroke-opacity", 0.35)
    .attr("marker-end", "url(#arrow)");

  // Nodes
  const nodeGs = graphG.selectAll("g.gnode")
    .data(chainNodes, d => d.id)
    .join("g")
    .attr("class", "gnode")
    .attr("transform", d => {
      const p = posMap.get(d.id);
      return p ? `translate(${p.x},${p.y})` : "";
    })
    .style("cursor", "pointer");

  // Circle
  nodeGs.append("circle")
    .attr("r", d => d.id === selectedId ? 12 : (d.is_root ? 10 : 8))
    .attr("fill", d => {
      if (d.id === selectedId) return "#f0c674";
      if (d.is_root) return "#e74c3c";
      return "#3498db";
    })
    .attr("stroke", d => d.id === selectedId ? "#fff" : "rgba(255,255,255,0.3)")
    .attr("stroke-width", d => d.id === selectedId ? 2.5 : 1);

  // Label
  nodeGs.append("text")
    .text(d => d.short_name)
    .attr("dy", d => {
      const p = posMap.get(d.id);
      const hasAbove = chainLinks.some(l => l.target === d.id);
      return hasAbove ? 22 : -16;
    })
    .attr("text-anchor", "middle")
    .attr("fill", d => d.id === selectedId ? "#f0c674" : "#c9d1d9")
    .attr("font-size", "10px")
    .attr("font-family", "Inter, sans-serif")
    .attr("font-weight", d => d.id === selectedId ? "600" : "400");

  // Interactions
  nodeGs.on("click", (e, d) => {
    e.stopPropagation();
    graphNodeId = d.id;
    showNodeDetail(d.id);
    // Update highlight
    nodeGs.select("circle")
      .attr("stroke", n => n.id === d.id ? "#f0c674" : "rgba(255,255,255,0.3)")
      .attr("stroke-width", n => n.id === d.id ? 3 : 1);
    // Highlight connected edges
    graphG.selectAll("path.edge")
      .attr("stroke-opacity", l => (l.source === d.id || l.target === d.id) ? 0.8 : 0.15)
      .attr("stroke-width", l => (l.source === d.id || l.target === d.id) ? 2.5 : 1);
  });

  nodeGs.on("mouseover", (e, d) => {
    const [mx, my] = d3.pointer(e, graphArea);
    const ts = d.timestamp ? new Date(d.timestamp).toLocaleString() : "";
    tooltip.innerHTML = `<div class="tt-name">${esc(d.short_name)}</div>`
      + `<div class="tt-sub">PID: ${d.pid}${ts ? ' · ' + ts : ''}</div>`;
    tooltip.style.left = (mx + 14) + "px";
    tooltip.style.top = (my - 8) + "px";
    tooltip.style.opacity = 1;
  });

  nodeGs.on("mouseout", () => { tooltip.style.opacity = 0; });

  graphSvg.on("click", () => {
    graphNodeId = null;
    clearDetail();
    nodeGs.select("circle")
      .attr("stroke", d => d.id === selectedId ? "#fff" : "rgba(255,255,255,0.3)")
      .attr("stroke-width", d => d.id === selectedId ? 2.5 : 1);
    graphG.selectAll("path.edge").attr("stroke-opacity", 0.35).attr("stroke-width", 1.5);
  });

  // Zoom
  graphZoom = d3.zoom()
    .scaleExtent([0.1, 6])
    .on("zoom", e => graphG.attr("transform", e.transform));
  graphSvg.call(graphZoom);

  // Fit
  fitGraph();

  // Show detail for the selected tree node
  showNodeDetail(selectedId);
}

function fitGraph() {
  setTimeout(() => {
    const bbox = graphG.node().getBBox();
    if (bbox.width === 0) return;
    const aW = graphArea.clientWidth;
    const aH = graphArea.clientHeight;
    const pad = 60;
    const scale = Math.min(aW / (bbox.width + pad), aH / (bbox.height + pad), 1.5);
    const tx = (aW - bbox.width * scale) / 2 - bbox.x * scale;
    const ty = (aH - bbox.height * scale) / 2 - bbox.y * scale;
    graphSvg.transition().duration(400)
      .call(graphZoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
  }, 50);
}

document.getElementById("gc-zin").onclick = () => graphSvg.transition().duration(200).call(graphZoom.scaleBy, 1.4);
document.getElementById("gc-zout").onclick = () => graphSvg.transition().duration(200).call(graphZoom.scaleBy, 0.7);
document.getElementById("gc-fit").onclick = fitGraph;

// ════════════════════════════════════════════════
// NODE DETAIL (bottom pane)
// ════════════════════════════════════════════════
function showNodeDetail(nodeId) {
  const node = nodes[nodeId];
  if (!node) return;
  const area = document.getElementById("detail-area");
  const ts = node.timestamp ? new Date(node.timestamp).toLocaleString() : "N/A";

  let h = `<div class="detail-title">
    ${esc(node.short_name)}
    <span class="tag ${node.is_root ? 'tag-root' : 'tag-child'}">${node.is_root ? 'ROOT' : 'CHILD'}</span>
  </div>`;

  h += '<div class="detail-row">';
  h += `<div class="detail-item half"><label>PID</label><div class="dv">${node.pid}</div></div>`;
  h += `<div class="detail-item half"><label>Timestamp</label><div class="dv">${ts}</div></div>`;
  h += '</div>';

  h += '<div class="detail-row">';
  h += `<div class="detail-item full"><label>Process Path</label><div class="dv">${esc(node.label)}</div></div>`;
  h += '</div>';

  h += '<div class="detail-row">';
  if (node.command_line) {
    h += `<div class="detail-item full"><label>Command Line</label><div class="dv">${esc(node.command_line)}</div></div>`;
  } else {
    h += `<div class="detail-item full"><label>Command Line</label><div class="dv muted">Not captured</div></div>`;
  }
  h += '</div>';

  area.innerHTML = h;
}

function clearDetail() {
  document.getElementById("detail-area").innerHTML =
    '<div class="detail-empty-sm">Click a node in the graph to see details</div>';
}

// ════════════════════════════════════════════════
// RESIZE HANDLE
// ════════════════════════════════════════════════
const resizeHandle = document.getElementById("resize-handle");
const detailArea = document.getElementById("detail-area");
let resizing = false;

resizeHandle.addEventListener("mousedown", e => {
  resizing = true;
  e.preventDefault();
});
document.addEventListener("mousemove", e => {
  if (!resizing) return;
  const rightPanel = document.getElementById("right-panel");
  const rect = rightPanel.getBoundingClientRect();
  const newDetailH = rect.bottom - e.clientY;
  detailArea.style.height = Math.max(80, Math.min(newDetailH, rect.height - 200)) + "px";
});
document.addEventListener("mouseup", () => { resizing = false; });

// ── Init ──
renderTree("");
</script>
</body>
</html>"""


def render_lazy_tree(graph: nx.DiGraph, output_file: str) -> None:
    if graph.number_of_nodes() == 0:
        logger.warning("Empty graph, nothing to render.")
        return

    data = _build_tree_data(graph)
    json_str = json.dumps(data, ensure_ascii=False)
    html = _HTML_TEMPLATE.replace("%%GRAPH_JSON%%", json_str)

    output_dir = os.path.dirname(output_file)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    logger.info("Lazy tree + chain graph saved to %s (%d nodes, %d edges, %d roots)",
                output_file, graph.number_of_nodes(), graph.number_of_edges(), len(data["roots"]))
