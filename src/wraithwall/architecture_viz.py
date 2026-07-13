"""
Authenticated architecture corpus + graph query API for Phase 8 visualization.
Serves validated docs/architecture artifacts only — no inference, no public access.
"""
import json
import logging
import re
from pathlib import Path

from flask import Blueprint, jsonify, request, abort

logger = logging.getLogger(__name__)

architecture_viz_bp = Blueprint('architecture_viz', __name__)

CORPUS_DIR = Path(__file__).resolve().parent / 'docs' / 'architecture'

CORPUS_ALLOWLIST = frozenset([
    'architecture.json', 'runtime_graph.json', 'event_graph.json',
    'dependency_graph.json', 'blueprint_graph.json',
    'redis_graph.json', 'scheduler_graph.json', 'notification_graph.json',
    'api_surface.json', 'trust_boundaries.json', 'observability.json',
    'runtime_metrics.json', 'live_nodes.json', 'live_edges.json',
    'telemetry_catalog.json', 'visualization_state.json', 'api_runtime_contract.json',
    'visualization_architecture.json', 'frontend_component_map.json',
    'graph_rendering_plan.json',
])

GRAPH_VIEWS = {
    'system_architecture': {
        'files': ['dependency_graph.json'],
        'max_nodes': 200,
        'max_depth': 4,
    },
    'runtime_services': {
        'files': ['runtime_graph.json', 'live_nodes.json', 'live_edges.json'],
        'max_nodes': 100,
        'max_depth': 4,
    },
    'event_flow': {
        'files': ['event_graph.json'],
        'max_nodes': 150,
        'max_depth': 3,
    },
    'deception_mesh': {
        'files': ['live_nodes.json', 'live_edges.json', 'visualization_state.json'],
        'max_nodes': 80,
        'max_depth': 4,
        'cluster_filter': 'cluster_canary',
    },
    'redis_topology': {
        'files': ['redis_graph.json'],
        'max_nodes': 300,
        'max_depth': 2,
    },
    'scheduler_topology': {
        'files': ['scheduler_graph.json'],
        'max_nodes': 100,
        'max_depth': 2,
    },
    'trust_boundaries': {
        'files': ['trust_boundaries.json'],
        'max_nodes': 50,
        'max_depth': 1,
    },
    'cowrie_pipeline': {
        'files': ['live_nodes.json', 'live_edges.json'],
        'max_nodes': 30,
        'max_depth': 3,
        'node_filter': ['cowrie', 'd95445c2', 'c5de21e5'],
    },
    'campaign_correlation': {
        'files': ['dependency_graph.json'],
        'max_nodes': 500,
        'max_depth': 3,
        'node_filter': ['campaign', 'cowrie', 'fingerprint'],
    },
    'threat_intel_pipeline': {
        'files': ['dependency_graph.json'],
        'max_nodes': 50,
        'max_depth': 3,
        'node_filter': ['fingerprint', 'asn', 'bgp', 'cowrie', 'campaign'],
    },
    'executive_overview': {
        'files': ['architecture.json', 'runtime_metrics.json', 'visualization_state.json'],
        'max_nodes': 34,
        'max_depth': 1,
    },
}

TIER3_PATTERNS = re.compile(
    r'(secret|seed|password|credential_hash|signing_key|private_key_pem|canary_seed)',
    re.I,
)

def _require_login():

    if not is_logged_in():
        abort(401)

def _load_json(name):
    path = CORPUS_DIR / name
    if not path.is_file():
        return None
    with open(path, encoding='utf-8') as f:
        return json.load(f)

def _redact_tier3(obj):
    """Strip Tier-3 field names from nested dicts before API response."""
    if isinstance(obj, dict):
        return {
            k: _redact_tier3(v)
            for k, v in obj.items()
            if not TIER3_PATTERNS.search(k)
        }
    if isinstance(obj, list):
        return [_redact_tier3(i) for i in obj]
    return obj

def _extract_graph_nodes_edges(data, source_file):
    if 'nodes' in data and 'edges' in data:
        return data['nodes'], data['edges']
    if 'events' in data:
        nodes = [{'id': e.get('event_id', e.get('name')), 'label': e.get('name'), 'type': 'event', 'meta': e} for e in data['events']]
        edges = []
        for e in data['events']:
            for consumer in e.get('consumers', []):
                edges.append({'source': e.get('name'), 'target': consumer, 'type': 'event_flow'})
        return nodes, edges
    if 'key_patterns' in data:
        by_sub = {}
        for kp in data['key_patterns']:
            sub = kp.get('subsystem', 'unknown')
            by_sub.setdefault(sub, []).append(kp)
        nodes = [{'id': f'redis:{sub}', 'label': f'Redis:{sub}', 'type': 'redis_group', 'count': len(v)} for sub, v in by_sub.items()]
        edges = []
        return nodes, edges
    if 'apscheduler_jobs' in data:
        nodes = [{'id': j['job_id'], 'label': j['job_id'], 'type': 'scheduler_job', 'meta': j} for j in data['apscheduler_jobs']]
        daemon = data.get('daemon_threads', [])
        nodes += [{'id': d.get('thread_id', d.get('name', 'thread')), 'label': d.get('name', 'thread'), 'type': 'daemon_thread', 'meta': d} for d in daemon]
        return nodes, []
    if 'boundaries' in data:
        nodes = [{'id': b['name'], 'label': b['name'], 'type': 'trust_boundary', 'meta': b} for b in data['boundaries']]
        return nodes, []
    if 'subsystems' in data:
        nodes = [{'id': s.get('subsystem_id', s.get('display_name')), 'label': s.get('display_name'), 'type': 'subsystem'} for s in data['subsystems']]
        return nodes, []
    if 'clusters' in data:
        nodes = [{'id': c['id'], 'label': c['label'], 'type': 'cluster', 'meta': c} for c in data['clusters']]
        return nodes, []
    return [], []

def _apply_limits(nodes, edges, cfg):
    max_n = cfg.get('max_nodes', 200)
    nf = cfg.get('node_filter')
    if nf:
        nf_lower = [x.lower() for x in nf]
        nodes = [n for n in nodes if any(
            f in str(n.get('id', '')).lower() or f in str(n.get('label', '')).lower()
            for f in nf_lower
        )]
    if len(nodes) > max_n:
        nodes = nodes[:max_n]
    node_ids = {str(n.get('id')) for n in nodes}
    edges = [e for e in edges if str(e.get('source', '')) in node_ids or str(e.get('target', '')) in node_ids]
    if len(edges) > max_n * 2:
        edges = edges[: max_n * 2]
    return nodes, edges

@architecture_viz_bp.before_request
def _auth_gate():
    _require_login()

@architecture_viz_bp.route('/api/architecture/corpus')
def list_corpus():
    files = []
    for name in sorted(CORPUS_ALLOWLIST):
        path = CORPUS_DIR / name
        if path.is_file():
            meta = {}
            try:
                data = _load_json(name)
                if isinstance(data, dict):
                    meta = data.get('metadata', {})
                    if 'generated_at' in data and 'generated_at' not in meta:
                        meta['generated_at'] = data['generated_at']
            except Exception:
                pass
            files.append({'name': name, 'size': path.stat().st_size, 'metadata': meta})
    return jsonify({'files': files, 'count': len(files)})

@architecture_viz_bp.route('/api/architecture/corpus/<path:filename>')
def get_corpus_file(filename):
    if filename not in CORPUS_ALLOWLIST:
        abort(404)
    data = _load_json(filename)
    if data is None:
        abort(404)
    return jsonify(_redact_tier3(data))

@architecture_viz_bp.route('/api/architecture/graph/<view_id>')
def get_graph_view(view_id):
    cfg = GRAPH_VIEWS.get(view_id)
    if not cfg:
        abort(404)
    depth = min(int(request.args.get('depth', cfg.get('max_depth', 4))), cfg.get('max_depth', 4))
    all_nodes, all_edges = [], []
    for fname in cfg['files']:
        data = _load_json(fname)
        if not data:
            continue
        nodes, edges = _extract_graph_nodes_edges(data, fname)
        if cfg.get('cluster_filter') and fname == 'visualization_state.json':
            cf = cfg['cluster_filter']
            clusters = [c for c in data.get('clusters', []) if c.get('id') == cf]
            for c in clusters:
                for nid in c.get('nodes', []):
                    all_nodes.append({'id': nid, 'label': nid, 'type': 'subsystem', 'cluster': cf})
        else:
            all_nodes.extend(nodes)
            all_edges.extend(edges)
    if view_id == 'deception_mesh':
        all_nodes.extend([
            {'id': 'domain_production', 'label': 'Production Application', 'type': 'domain', 'domain': 'production'},
            {'id': 'domain_deception', 'label': 'Deception Blueprint', 'type': 'domain', 'domain': 'deception'},
            {'id': 'domain_cowrie_vps', 'label': 'Cowrie VPS', 'type': 'domain', 'domain': 'cowrie_vps'},
        ])
        all_edges.extend([
            {'source': 'domain_cowrie_vps', 'target': 'domain_deception', 'label': 'telemetry'},
            {'source': 'domain_deception', 'target': 'domain_production', 'label': 'correlation'},
        ])
    all_nodes, all_edges = _apply_limits(all_nodes, all_edges, cfg)
    return jsonify({
        'view_id': view_id,
        'depth': depth,
        'nodes': _redact_tier3(all_nodes),
        'edges': _redact_tier3(all_edges),
        'limits': {'max_nodes': cfg.get('max_nodes'), 'max_depth': cfg.get('max_depth')},
    })

def register_architecture_viz(app, limiter):
    """Called from main.py after limiter is initialized."""
    app.register_blueprint(architecture_viz_bp)
    limits = {
        'architecture_viz.list_corpus': '60 per minute',
        'architecture_viz.get_corpus_file': '120 per minute',
        'architecture_viz.get_graph_view': '30 per minute',
    }
    for endpoint, rule in limits.items():
        if endpoint in app.view_functions:
            app.view_functions[endpoint] = limiter.limit(rule)(app.view_functions[endpoint])