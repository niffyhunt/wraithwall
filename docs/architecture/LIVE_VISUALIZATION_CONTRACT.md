# Live Visualization Contract

**Generated:** 2026-07-09  
**Phase:** 6 — Runtime Telemetry Mapping  
**Canonical sources:** visualization_state.json, live_nodes.json, live_edges.json

---

## 1. Purpose

Defines the schema contract between the WraithWall runtime telemetry layer and the visualization engine (e.g., D3.js force-directed graph, vis.js, or custom canvas renderer). The visualization must be able to render the live graph from the state snapshots in visualization_state.json, live_nodes.json, and live_edges.json without additional transformation.

---

## 2. Node Schema

Each node in the graph represents either a subsystem, a blueprint, an infrastructure component (Redis), or an external API.

### 2.1 Internal Node (Subsystem / Blueprint)

```json
{
  "id": "uuid_or_slug",
  "label": "Human Readable Name",
  "type": "subsystem | blueprint",
  "file": "source_filename.py",
  "blueprint": "blueprint_name | null",
  "status": "active | degraded | down",
  "status_detail": "codebase_match | partial_mismatch | route_mismatch | missing_from_architecture",
  "cluster_id": "cluster_intake | cluster_canary | ...",
  "color": "#hex",
  "position": {"x": number, "y": number, "pinned": boolean},
  "shape": "rounded_rect",
  "size": {"width": 160, "height": 60},
  "font_size": 12,
  "border_width": 2,
  "opacity": 1.0,
  "health_probe": "GET /path or inline",
  "thread_pool": "description | null",
  "active_routes": number,
  "redis_keys": ["key:pattern:*"],
  "scheduler_jobs": ["job_name (every interval)"],
  "depends_on": ["id1", "id2"]
}
```

### 2.2 Infrastructure Node (Redis)

```json
{
  "id": "redis_instance",
  "label": "Redis",
  "type": "infrastructure",
  "color": "#c0392b",
  "shape": "circle",
  "size": 40
}
```

### 2.3 External Node (API / Service)

```json
{
  "id": "ext_name",
  "label": "Provider Name",
  "type": "external",
  "color": "#e67e22",
  "shape": "diamond",
  "size": {"width": 120, "height": 50}
}
```

---

## 3. Edge Schema

Each edge represents a verified runtime data flow.

### 3.1 Internal Edge (subsystem → subsystem)

```json
{
  "id": "e001",
  "source": "source_node_id",
  "target": "target_node_id",
  "protocol": "function_call | redis_write | https | websocket | message_queue",
  "flow": "Short description of what data flows",
  "verified": true,
  "evidence": "file.py: line reference",
  "arrow": "target",
  "style": "solid",
  "width": 1.5,
  "color": "#bdc3c7",
  "animated": false
}
```

### 3.2 Redis Edge (subsystem → Redis)

```json
{
  "id": "redis_xxx_001",
  "source": "subsystem_node_id",
  "target": "redis_instance",
  "protocol": "redis_write",
  "flow": "Writes key:pattern:* description",
  "verified": true,
  "evidence": "file.py: line reference",
  "color": "#e74c3c",
  "width": "varies by pressure (1.5=low, 3=critical)",
  "dash": "if unbounded: '5,5'",
  "animated": true,
  "label": "UNBOUNDED | NO TTL | CAPPED"
}
```

### 3.3 External Edge (subsystem → external API)

```json
{
  "id": "ext_xxx",
  "source": "subsystem_node_id",
  "target": "ext_name",
  "protocol": "https | websocket",
  "flow": "Description of API call",
  "verified": true,
  "color": "#2ecc71",
  "width": 1.0,
  "animated": true
}
```

---

## 4. Cluster / Group Schema

Clusters provide logical grouping for the force-directed layout.

```json
{
  "id": "cluster_name",
  "label": "Cluster Display Name",
  "color": "#hex",
  "nodes": ["node_id_1", "node_id_2"],
  "collapsed": false,
  "collapsed_visual": {
    "shape": "rounded_rect",
    "size": "200x80",
    "label": "Cluster Label (N nodes)",
    "badge_count": 3
  }
}
```

When `collapsed: true`:
- All member nodes are hidden
- A single placeholder node is rendered with cluster `label` + `"(N nodes)"`
- Edges from/to any member are redirected to the placeholder
- Expanded state restores individual nodes and edges

---

## 5. Color Coding

| Status / Condition | Color | Hex |
|---|---|---|
| Active, verified match | Green | `#2ecc71` |
| Active, partial mismatch | Orange | `#f39c12` |
| Active, route mismatch | Red | `#e74c3c` |
| Missing from architecture | Grey | `#7f8c8d` |
| Degraded | Yellow | `#f1c40f` |
| Down | Dark red | `#c0392b` |
| Redis (infra) | Dark red | `#c0392b` |
| External API | Orange | `#e67e22` |
| Edge (normal) | Light grey | `#bdc3c7` |
| Edge (unbounded/critical) | Red, dashed | `#e74c3c` |
| Edge (notification) | Green, animated | `#2ecc71` |

---

## 6. Legend

The visualization must include a rendered legend panel with:
- Status color swatches + labels
- Edge style swatches + labels
- Node shape meaning
- Cluster color meaning

Reference the `visualization_state.json.legend` array for canonical legend items.

---

## 7. Interaction Behaviors

### 7.1 Node Hover
- Highlight node (border glow)
- Highlight all edges from/to node
- Show tooltip with:
  - `label`
  - `status` + `status_detail`
  - `active_routes` count
  - `redis_keys` count
  - Health probe URL
  - Thread pool info

### 7.2 Node Click
- Expand/collapse if cluster node
- Open detail panel with full node JSON and edge list
- Navigate to source file (if file path is available)

### 7.3 Edge Hover
- Highlight edge
- Show tooltip with:
  - `protocol`
  - `flow`
  - `evidence` (file:line)
  - `verified` status

### 7.4 Drag
- Nodes are draggable
- `pinned: true` nodes stay in place on re-layout
- Double-click unpins

### 7.5 Zoom
- Mouse wheel zoom
- Fit-to-view button
- Reset zoom button

---

## 8. Layout Engine

- **Default:** `dagre` (directed graph, left-to-right flow)
- **Fallback:** Force-directed (d3-force) with cluster grouping
- **Direction:** Left (gateway/intake) → Right (notifications/external)
- **Cluster spacing:** 200px vertical gap between clusters
- **Node spacing:** 60px horizontal, 40px vertical within cluster

---

## 9. State Persistence

The visualization engine must be able to:
1. **Load initial state** from `visualization_state.json` (positions, clusters, collapsed states)
2. **Accept live updates** (node status changes, edge additions, cardinality changes)
3. **Emit state snapshots** on user interaction (collapsed/expanded clusters, pinned nodes)

State format for persistence:

```json
{
  "viewport": {"center": [x, y], "zoom": 1.0},
  "pinned_nodes": {"node_id": {"x": 100, "y": 200}},
  "collapsed_clusters": ["cluster_id_1"],
  "highlighted_edges": ["edge_id_1"]
}
```

---

## 10. Data Refresh Contract

### Pull-based (default)
- `/api/visualization/state` — returns full visualization_state.json
- `/api/visualization/nodes` — returns live_nodes.json
- `/api/visualization/edges` — returns live_edges.json
- `/api/visualization/metrics` — returns runtime_metrics.json (key cardinalities)

### Push-based (if SSE/WebSocket available)
- Channel: `vis:state-update`
- Event types:
  - `node_status_change` — `{"node_id": "...", "new_status": "degraded", "previous_status": "active"}`
  - `edge_cardinality_change` — `{"edge_id": "redis_log_001", "cardinality": 50000, "pressure": "critical"}`
  - `cluster_collapse` — `{"cluster_id": "...", "collapsed": true}`
  - `metric_alert` — `{"metric": "redis_memory_usage", "value": 0.85, "severity": "critical"}`

---

## 11. Rendering Performance Targets

| Item | Target |
|---|---|
| Node render limit | 200 nodes (current: 34) |
| Edge render limit | 500 edges (current: 87) |
| Initial load time | <2s |
| Live update latency | <500ms |
| Frame rate | 60fps (idle), 30fps (animating) |
| Memory (browser) | <50MB for full graph |

---

## 12. Error States

| Condition | Visual | Behavior |
|---|---|---|
| Node unreachable | Grey with "?" badge | Tooltip: "Health probe failed" |
| Edge data stale | Dashed, faded | Tooltip: "Last verified: timestamp" |
| Redis unreachable | All Redis edges dashed | Banner: "Redis connection lost" |
| Missing node | Orphan edges shown as "???" | Logged to console |
| State file missing | Load force-directed default | Emit warning event |
