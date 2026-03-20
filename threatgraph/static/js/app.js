// ════════════════════════════════════════════════
// UPLOAD & API STATE
// ════════════════════════════════════════════════
let graphData = { total_nodes: 0 };
let roots = new Set();
let nodes = {};
let childrenMap = {};
let parentMap = {};
let eventCount = 0;
let eventSource = null;
let renderTimeout = null;

const uploadScreen = document.getElementById("upload-screen");
const workspace = document.getElementById("workspace");
const fileInput = document.getElementById("file-input");
const uploadZone = document.getElementById("upload-zone");
const progressDiv = document.getElementById("upload-progress");
const streamStatusDiv = document.getElementById("stream-status");
const streamStatsDiv = document.getElementById("stream-stats");
const errDiv = document.getElementById("upload-error");


uploadZone.addEventListener("dragover", e => { e.preventDefault(); uploadZone.classList.add("dragover"); });
uploadZone.addEventListener("dragleave", () => uploadZone.classList.remove("dragover"));
uploadZone.addEventListener("drop", e => {
  e.preventDefault(); uploadZone.classList.remove("dragover");
  if (e.dataTransfer.files.length) handleFile(e.dataTransfer.files[0]);
});
fileInput.addEventListener("change", e => {
  if (e.target.files.length) handleFile(e.target.files[0]);
});
document.getElementById("btn-new-file").addEventListener("click", () => {
  uploadScreen.style.display = "flex";
  workspace.style.display = "none";
  errDiv.style.display = "none";
  progressDiv.style.display = "none";
  fileInput.value = "";
  if (eventSource) eventSource.close();
});

async function handleFile(file) {
  if (!file.name.toLowerCase().endsWith(".evtx")) {
    showError("Please upload a Windows Event Log (.evtx) file.");
    return;
  }
  
  errDiv.style.display = "none";
  uploadZone.style.display = "none";
  progressDiv.style.display = "block";
  streamStatusDiv.textContent = "Uploading file...";
  streamStatsDiv.style.display = "none";

  // Reset State
  nodes = {};
  childrenMap = {};
  parentMap = {};
  roots = new Set();
  eventCount = 0;
  expanded.clear();
  selectedTreeId = null;

  const fd = new FormData();
  fd.append("file", file);

  try {
    const res = await fetch("/api/upload", { method: "POST", body: fd });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    
    // Switch UI to stream loading
    streamStatusDiv.textContent = "Streaming events & building graph...";
    streamStatsDiv.style.display = "block";
    uploadScreen.style.display = "none";
    workspace.style.display = "flex";
    
    // Prepare workspace for live streaming
    document.getElementById("graph-empty").style.display = "flex";
    document.getElementById("graph-label").style.display = "none";
    document.getElementById("graph-controls").style.display = "none";
    clearDetail();

    startSSE(data.task_id);

  } catch (err) {
    showError(err.message || "Failed to upload.");
  }
}

function startSSE(taskId) {
  eventSource = new EventSource('/api/stream/' + taskId);
  
  eventSource.onmessage = (e) => {
    const batch = JSON.parse(e.data);
    batch.forEach(processEvent);
    
    // Update live stats
    document.getElementById("stat-extracted").textContent = eventCount;
    document.getElementById("stat-tree-count").textContent = roots.size;

    // Throttle rendering so UI doesn't freeze
    if (!renderTimeout) {
      renderTimeout = setTimeout(() => {
        debouncedUpdate();
        renderTimeout = null;
      }, 500); 
    }
  };

  eventSource.addEventListener("done", () => {
    eventSource.close();
    eventSource = null;
    debouncedUpdate(); // final render
    console.log("Streaming finished. Total events:", eventCount);
  });

  eventSource.addEventListener("error", (e) => {
    console.error("SSE Error:", e);
    eventSource.close();
    eventSource = null;
    debouncedUpdate();
  });
}

function processEvent(ev) {
  eventCount++;
  const childId = `pid_${ev.pid}`;
  const parentId = `pid_${ev.ppid}`;
  
  // 1. Child node creation/update
  if (!nodes[childId]) {
    nodes[childId] = { is_root: false };
  }
  Object.assign(nodes[childId], {
    id: childId,
    pid: ev.pid,
    label: ev.process_name,
    short_name: shortName(ev.process_name),
    command_line: ev.command_line || "",
    timestamp: ev.timestamp,
    raw_xml: ev.raw_xml,
    is_root: false
  });
  roots.delete(childId); // definitely not a root

  // 2. Parent node creation if missing
  if (!nodes[parentId]) {
    nodes[parentId] = {
      id: parentId,
      label: `PID ${ev.ppid}`,
      short_name: `PID ${ev.ppid}`,
      pid: ev.ppid,
      timestamp: ev.timestamp,
      is_root: true
    };
    roots.add(parentId);
  }

  // 3. Edges
  if (!childrenMap[parentId]) childrenMap[parentId] = [];
  if (!childrenMap[parentId].includes(childId)) {
    childrenMap[parentId].push(childId);
  }
  parentMap[childId] = parentId;
}

function shortName(label) {
  if (label.includes("\\")) label = label.substring(label.lastIndexOf("\\") + 1);
  if (label.includes("/")) label = label.substring(label.lastIndexOf("/") + 1);
  return label;
}

function debouncedUpdate() {
  document.getElementById("stat-total").textContent = Object.keys(nodes).length;
  document.getElementById("stat-roots").textContent = roots.size;
  document.getElementById("vis-total").textContent = Object.keys(nodes).length;
  renderTree(currentFilter);
  if (selectedTreeId) renderChainGraph(selectedTreeId);
}

function showError(msg) {
  progressDiv.style.display = "none";
  uploadZone.style.display = "block";
  errDiv.textContent = msg;
  errDiv.style.display = "block";
}


// ════════════════════════════════════════════════
// TREE EXPLORER (left panel)
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
  
  // Convert roots Set to array and sort chronologically based on oldest child
  const sortedRoots = Array.from(roots).sort((a,b) => {
    const ta = nodes[a]?.timestamp || "";
    const tb = nodes[b]?.timestamp || "";
    return ta.localeCompare(tb);
  });

  sortedRoots.forEach(rid => {
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
  let iconClass = node.is_root ? "icon-root" : "icon-child";
  let iconText = node.is_root ? "R" : "C";
  
  if (node.node_type === "file") {
    iconClass = "icon-file"; 
    iconText = "F"; 
  } else if (node.node_type === "registry" || node.node_type === "key") {
    iconClass = "icon-registry";
    iconText = "K";
  }
  
  ic.className = "node-icon " + iconClass;
  ic.textContent = iconText;
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

  row.addEventListener("click", () => {
    graphNodeId = null;
    selectTreeNode(nodeId);
  });
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
let currentPosMap = new Map();

// --- Floating Box Drag Logic ---
let draggingBox = null;
let dragStartX = 0, dragStartY = 0;
let dragInitOffX = 0, dragInitOffY = 0;

document.addEventListener('mousemove', (e) => {
  if (!draggingBox) return;
  const dx = e.clientX - dragStartX;
  const dy = e.clientY - dragStartY;
  draggingBox.offsetX = dragInitOffX + dx;
  draggingBox.offsetY = dragInitOffY + dy;
  updateInfoBoxesLoc(d3.zoomTransform(graphSvg.node()));
});

document.addEventListener('mouseup', () => {
  if (draggingBox) {
    draggingBox.style.opacity = "1";
    draggingBox = null;
  }
});

function updateInfoBoxesLoc(transform) {
  document.querySelectorAll('.multi-info-box').forEach(box => {
    const nid = box.__nodeId;
    const npos = currentPosMap.get(nid);
    if (npos) {
      const offX = box.offsetX !== undefined ? box.offsetX : 20;
      const offY = box.offsetY !== undefined ? box.offsetY : -20;
      const sx = transform.applyX(npos.x);
      const sy = transform.applyY(npos.y);
      box.style.transform = `translate(${sx + offX}px, ${sy + offY}px)`;
    }
  });
}

let graphZoom = d3.zoom().scaleExtent([0.1, 6]).on("zoom", e => {
  graphG.attr("transform", e.transform);
  updateInfoBoxesLoc(e.transform);
});
graphSvg.call(graphZoom);

function getChainNodes(selectedId) {
  const chainIds = new Set();
  chainIds.add(selectedId);

  // Traverse UP (parents) -> max depth n-2
  let cur = selectedId;
  let up = 0;
  while (parentMap[cur] && up < 2) {
    cur = parentMap[cur];
    chainIds.add(cur);
    up++;
  }

  // Traverse DOWN (children) -> max depth n+2
  const queue = [{ id: selectedId, depth: 0 }];
  while (queue.length > 0) {
    const { id, depth } = queue.shift();
    if (depth < 2) {
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
  graphG.selectAll("*").remove();
  document.getElementById("graph-empty").style.display = "none";
  document.getElementById("graph-label").style.display = "";
  document.getElementById("graph-controls").style.display = "";

  const chainIds = getChainNodes(selectedId);
  const chainNodes = [...chainIds].map(id => nodes[id]).filter(Boolean);
  const chainLinks = [];
  chainIds.forEach(id => {
    (childrenMap[id] || []).forEach(cid => { if (chainIds.has(cid)) chainLinks.push({ source: id, target: cid }); });
  });

  const sel = nodes[selectedId];
  document.getElementById("chain-name").textContent = sel ? sel.short_name : selectedId;
  document.getElementById("chain-count").textContent = chainNodes.length;

  let chainRoot = selectedId;
  while (parentMap[chainRoot] && chainIds.has(parentMap[chainRoot])) chainRoot = parentMap[chainRoot];

  const depthMap = new Map();
  const levelNodes = new Map();
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
        visited.add(cid); depthMap.set(cid, depth + 1); bfsQueue.push(cid);
      }
    });
  }
  chainIds.forEach(id => {
    if (!visited.has(id)) {
      depthMap.set(id, -1);
      if (!levelNodes.has(-1)) levelNodes.set(-1, []);
      levelNodes.get(-1).push(id);
    }
  });

  const ROW_H = 70, COL_W = 140, MARGIN_TOP = 50, MARGIN_LEFT = 40;
  const areaW = graphArea.clientWidth;
  currentPosMap.clear();
  levelNodes.forEach((ids, depth) => {
    const totalW = (ids.length - 1) * COL_W;
    const startX = Math.max(MARGIN_LEFT, (areaW - totalW) / 2);
    ids.forEach((id, i) => currentPosMap.set(id, { x: startX + i * COL_W, y: MARGIN_TOP + depth * ROW_H }));
  });

  graphSvg.select("defs").remove();
  graphSvg.append("defs").append("marker")
    .attr("id", "arrow").attr("viewBox", "0 -5 10 10")
    .attr("refX", 20).attr("refY", 0).attr("markerWidth", 6).attr("markerHeight", 6)
    .attr("orient", "auto").append("path").attr("d", "M0,-5L10,0L0,5").attr("fill", "#4a90d9");

  graphG.selectAll("path.edge")
    .data(chainLinks).join("path").attr("class", "edge")
    .attr("d", d => {
      const s = currentPosMap.get(d.source), t = currentPosMap.get(d.target);
      if (!s || !t) return "";
      const my = (s.y + t.y) / 2;
      return `M${s.x},${s.y} C${s.x},${my} ${t.x},${my} ${t.x},${t.y}`;
    })
    .attr("fill", "none").attr("stroke", "#4a90d9").attr("stroke-width", 1.5)
    .attr("stroke-opacity", 0.35).attr("marker-end", "url(#arrow)");

  const nodeGs = graphG.selectAll("g.gnode")
    .data(chainNodes, d => d.id).join("g").attr("class", "gnode")
    .attr("transform", d => `translate(${currentPosMap.get(d.id)?.x||0},${currentPosMap.get(d.id)?.y||0})`)
    .style("cursor", "pointer");

  nodeGs.append("circle")
    .attr("r", d => d.id === selectedId ? 16 : (d.is_root ? 14 : 12))
    .attr("fill", d => {
      if (d.id === selectedId) return "#f0c674";
      if (!d.node_type || d.node_type === 'process') return d.is_root ? "#e74c3c" : "#3498db";
      if (d.node_type === 'file') return "#2ea043"; // Git Green
      if (d.node_type === 'registry' || d.node_type === 'key') return "#a371f7"; // Git Purple
      return "#8b949e";
    })
    .attr("stroke", d => d.id === selectedId ? "#fff" : "rgba(255,255,255,0.3)")
    .attr("stroke-width", d => d.id === selectedId ? 2.5 : 1);

  nodeGs.append("text")
    .text(d => {
      if (d.node_type === 'file') return 'F';
      if (d.node_type === 'registry' || d.node_type === 'key') return 'RK';
      return 'P';
    })
    .attr("dy", "4")
    .attr("text-anchor", "middle")
    .attr("fill", d => d.id === selectedId ? "#24292e" : "#fff")
    .attr("font-size", d => d.id === selectedId ? "11px" : "9px")
    .attr("font-weight", "bold")
    .attr("font-family", "Inter, sans-serif")
    .style("pointer-events", "none");

  nodeGs.append("text")
    .text(d => d.short_name.length > 15 ? d.short_name.substring(0, 12) + "..." : d.short_name)
    .attr("dy", d => chainLinks.some(l => l.target === d.id) ? 28 : -22)
    .attr("text-anchor", "middle")
    .attr("fill", d => d.id === selectedId ? "#f0c674" : "#c9d1d9")
    .attr("font-size", "10px").attr("font-family", "Inter, sans-serif")
    .attr("font-weight", d => d.id === selectedId ? "600" : "400");

  nodeGs.on("click", (e, d) => {
    e.stopPropagation(); graphNodeId = d.id;
    // Visually highlight logic (wait for re-render actually)
    selectTreeNode(d.id); 
  });

  nodeGs.on("mouseover", (e, d) => {
    const [mx, my] = d3.pointer(e, graphArea);
    const ts = d.timestamp ? new Date(d.timestamp).toLocaleString() : "";
    let html = `<div class="tt-name">${esc(d.short_name)}</div>`;
    if (d.node_type === 'file' || d.node_type === 'registry' || d.node_type === 'key') {
      const pnode = parentMap[d.id] ? nodes[parentMap[d.id]] : null;
      html += `<div class="tt-sub">ProcessId: ${pnode ? pnode.pid : 'Unknown'}</div>`;
      html += `<div class="tt-sub">ProcessName: ${pnode ? esc(pnode.short_name) : 'Unknown'}</div>`;
      html += `<div class="tt-sub">ObjectName: ${esc(d.object_name || d.short_name)}</div>`;
      if (d.node_type === 'file') html += `<div class="tt-sub">AccessList: ${esc(d.access_list || 'None')}</div>`;
      else html += `<div class="tt-sub">NewValue: ${esc(d.new_value || 'None')}</div>`;
      if (ts) html += `<div class="tt-sub" style="margin-top:2px;">Time: ${ts}</div>`;
    } else {
      html += `<div class="tt-sub">PID: ${d.pid}${ts ? ' · ' + ts : ''}</div>`;
    }
    tooltip.innerHTML = html;
    tooltip.style.left = (mx + 14) + "px"; tooltip.style.top = (my - 8) + "px"; tooltip.style.opacity = 1;
  });
  nodeGs.on("mouseout", () => tooltip.style.opacity = 0);

  graphSvg.on("click", () => {
    graphNodeId = null; clearDetail();
    nodeGs.select("circle").attr("stroke", d => d.id === selectedId ? "#fff" : "rgba(255,255,255,0.3)")
      .attr("stroke-width", d => d.id === selectedId ? 2.5 : 1);
    graphG.selectAll("path.edge").attr("stroke-opacity", 0.35).attr("stroke-width", 1.5);
    document.querySelectorAll('.multi-info-box').forEach(el => el.remove());
  });

  fitGraph();
  showNodeDetail(selectedId);
  
  // Populate scattered info boxes natively ONLY if a graph node was explicitly clicked
  if (graphNodeId) {
    showInlineInfoBoxes(chainNodes);
  } else {
    document.querySelectorAll('.multi-info-box').forEach(el => el.remove());
  }
}

function showInlineInfoBoxes(chainNodes) {
  document.querySelectorAll('.multi-info-box').forEach(el => el.remove());
  const pane = document.getElementById("graph-area");

  chainNodes.forEach((snode, boxIndex) => {
    const isSelected = snode.id === graphNodeId;
    const pnode = parentMap[snode.id] ? nodes[parentMap[snode.id]] : null;
    const cnodes = (childrenMap[snode.id] || []).map(cid => nodes[cid]).filter(Boolean);
    
    const spid = pnode ? pnode.pid : "";
    const scmd = pnode ? pnode.command_line : "";
    const tpid = snode.pid;
    const tcmd = snode.command_line;
    const childPids = cnodes.map(c => c.pid).join(", ");
    
    let h = `<div class="title" style="margin-bottom: 6px; padding-bottom: 4px; border-bottom: 1px solid #30363d; font-weight: 600; color: ${isSelected ? '#f0c674' : '#58a6ff'}; user-select: none;">${esc(snode.short_name)} ${isSelected ? '<span style="font-size:9px;">(SELECTED)</span>' : ''}</div>`;
    
    if (snode.node_type === 'file' || snode.node_type === 'registry' || snode.node_type === 'key') {
      const parentName = pnode ? pnode.short_name : 'Unknown';
      h += `<div class="row" style="display:flex; justify-content:space-between; margin-bottom: 3px;"><div class="lbl" style="color:#8b949e; width: 40%;">ProcessId</div><div class="val" style="color:#c9d1d9; width: 60%; word-break: break-all;">${spid ? esc(spid) : '&nbsp;'}</div></div>`;
      h += `<div class="row" style="display:flex; justify-content:space-between; margin-bottom: 3px;"><div class="lbl" style="color:#8b949e; width: 40%;">ProcessName</div><div class="val" style="color:#c9d1d9; width: 60%; word-break: break-all;">${esc(parentName)}</div></div>`;
      h += `<div style="color:#8b949e; margin-top: 6px; margin-bottom: 2px;">ObjectName</div><div style="color:#c9d1d9; background:#0d1117; padding:4px; border-radius:4px; word-break:break-all;">${esc(snode.object_name || snode.short_name)}</div>`;
      if (snode.node_type === 'file') {
        h += `<div style="color:#8b949e; margin-top: 6px; margin-bottom: 2px;">AccessList</div><div style="color:#c9d1d9; background:#0d1117; padding:4px; border-radius:4px; word-break:break-all;">${esc(snode.access_list || 'None')}</div>`;
      } else {
        h += `<div style="color:#8b949e; margin-top: 6px; margin-bottom: 2px;">NewValue</div><div style="color:#c9d1d9; background:#0d1117; padding:4px; border-radius:4px; word-break:break-all;">${esc(snode.new_value || 'None')}</div>`;
      }
    } else {
      h += `<div class="row" style="display:flex; justify-content:space-between; margin-bottom: 3px;"><div class="lbl" style="color:#8b949e; width: 40%;">Node PID</div><div class="val" style="color:#c9d1d9; width: 60%; word-break: break-all;">${esc(tpid)}</div></div>`;
      h += `<div class="row" style="display:flex; justify-content:space-between; margin-bottom: 3px;"><div class="lbl" style="color:#8b949e; width: 40%;">Parent PID</div><div class="val" style="color:#c9d1d9; width: 60%; word-break: break-all;">${spid ? esc(spid) : '&nbsp;'}</div></div>`;
      h += `<div class="row" style="display:flex; justify-content:space-between; margin-bottom: 3px;"><div class="lbl" style="color:#8b949e; width: 40%;">Children PIDs</div><div class="val" style="color:#c9d1d9; width: 60%; word-break: break-all;">${childPids ? esc(childPids) : '&nbsp;'}</div></div>`;
      h += `<div style="color:#8b949e; margin-top: 6px; margin-bottom: 2px;">Source CmdLine</div><div style="color:#c9d1d9; background:#0d1117; padding:4px; border-radius:4px; word-break:break-all;">${scmd ? esc(scmd) : '&nbsp;'}</div>`;
      h += `<div style="color:#8b949e; margin-top: 6px; margin-bottom: 2px;">Target CmdLine</div><div style="color:#c9d1d9; background:#0d1117; padding:4px; border-radius:4px; word-break:break-all;">${tcmd ? esc(tcmd) : '&nbsp;'}</div>`;
    }
    
    const box = document.createElement("div");
    box.className = "inline-info-box multi-info-box";
    box.innerHTML = h;
    box.style.display = "block";
    box.style.position = "absolute";
    box.style.top = "0";
    box.style.left = "0";
    box.style.width = "270px";
    box.style.padding = "10px";
    box.style.pointerEvents = "auto";
    box.addEventListener("wheel", e => e.stopPropagation());
    box.addEventListener("mousedown", e => e.stopPropagation());
    box.addEventListener("dblclick", e => e.stopPropagation());
    box.__nodeId = snode.id;
    if (isSelected) {
      box.offsetX = 35;
      box.offsetY = -40;
      box.style.zIndex = "50";
    } else {
      const isLeft = (boxIndex % 2 !== 0);
      box.offsetX = isLeft ? -305 : 35;
      box.offsetY = -120 + (boxIndex * 70);
      box.style.zIndex = "10";
    }
    
    pane.appendChild(box);
    
    // Add Drag functionality to the title bar
    const titleEl = box.querySelector('.title');
    titleEl.style.cursor = 'move';
    titleEl.addEventListener('mousedown', (e) => {
      draggingBox = box;
      dragStartX = e.clientX;
      dragStartY = e.clientY;
      dragInitOffX = box.offsetX;
      dragInitOffY = box.offsetY;
      
      document.querySelectorAll('.multi-info-box').forEach(b => b.style.zIndex = "10");
      box.style.zIndex = "100";
      box.style.opacity = "0.8"; // Visual cue while dragging
      
      e.stopPropagation();
      e.preventDefault();
    });
  });
  
  setTimeout(() => {
    updateInfoBoxesLoc(d3.zoomTransform(graphSvg.node()));
  }, 50); // Give fitGraph time to calculate transform first
}

function fitGraph() {
  setTimeout(() => {
    const bbox = graphG.node().getBBox();
    if (bbox.width === 0) return;
    const aW = graphArea.clientWidth, aH = graphArea.clientHeight, pad = 60;
    const scale = Math.min(aW/(bbox.width+pad), aH/(bbox.height+pad), 1.5);
    const tx = (aW-bbox.width*scale)/2 - bbox.x*scale, ty = (aH-bbox.height*scale)/2 - bbox.y*scale;
    graphSvg.transition().duration(400).call(graphZoom.transform, d3.zoomIdentity.translate(tx,ty).scale(scale));
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

  // Format 100% of event log data
  h += '<div class="detail-row" style="margin-top: 20px; border-top: 1px dashed #30363d; padding-top: 10px;">';
  if (node.raw_xml) {
    try {
      // Basic formatting for XML viewing
      let cleanXml = node.raw_xml.replace(/</g, "&lt;").replace(/>/g, "&gt;");
      h += `<div class="detail-item full"><label>Raw Event Data (XML)</label><div class="dv code">${cleanXml}</div></div>`;
    } catch(e) {
      h += `<div class="detail-item full"><label>Raw Event Data (XML)</label><div class="dv code">${esc(node.raw_xml)}</div></div>`;
    }
  } else {
    h += `<div class="detail-item full"><label>Raw Event Data (XML)</label><div class="dv muted">No raw data available</div></div>`;
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
resizeHandle.addEventListener("mousedown", e => { resizing = true; e.preventDefault(); });
document.addEventListener("mousemove", e => {
  if (!resizing) return;
  const rightPanel = document.getElementById("right-panel");
  const rect = rightPanel.getBoundingClientRect();
  const newDetailH = rect.bottom - e.clientY;
  detailArea.style.height = Math.max(80, Math.min(newDetailH, rect.height - 150)) + "px";
});
document.addEventListener("mouseup", () => { resizing = false; });
