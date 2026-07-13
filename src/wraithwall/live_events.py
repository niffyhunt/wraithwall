"""
Multiplexed SSE feed for architecture visualization runtime overlays.
Streams: cowrie, deception, detections, bgp, system (per VISUALIZATION_PLAN §3).
"""
import json
import logging
import time
from datetime import datetime

from flask import Blueprint, Response, request, stream_with_context, abort

logger = logging.getLogger(__name__)

live_events_bp = Blueprint('live_events', __name__)

VALID_STREAMS = frozenset(['cowrie', 'deception', 'detections', 'bgp', 'system'])
THROTTLE_SEC = {
    'cowrie': 0.2,
    'deception': 0.5,
    'detections': 0.33,
    'bgp': 1.0,
    'system': 0.33,
}
_ip_connections = {}
_MAX_PER_IP = 5

def _require_login():

    if not is_logged_in():
        abort(401)

def _client_ip():
    from gateway import _client_ip as gw_ip
    return gw_ip()

def _check_connection_cap():
    ip = _client_ip()
    n = _ip_connections.get(ip, 0)
    if n >= _MAX_PER_IP:
        abort(429, description='Too many SSE connections')
    _ip_connections[ip] = n + 1

def _release_connection():
    ip = _client_ip()
    _ip_connections[ip] = max(0, _ip_connections.get(ip, 1) - 1)

def _get_redis():

    return get_redis()

def _cowrie_batch(r):
    out = {'events': [], 'metrics': {}}
    try:
        from cowrie_intelligence import get_pipeline
        pipe = get_pipeline()
        out['metrics'] = {
            'queue_size': pipe.event_queue.qsize(),
            'queue_max': 5000,
            **dict(pipe.metrics),
        }
    except Exception as e:
        out['note'] = str(e)[:120]
    if r:
        try:
            raw = r.lrange('cowrie_sessions:recent', 0, 4)
            for item in raw:
                try:
                    out['events'].append(json.loads(item) if item.startswith('{') else {'session_id': item})
                except Exception:
                    out['events'].append({'session_id': str(item)})
        except Exception:
            pass
    return out

def _bgp_batch(r):
    if not r:
        return {'alerts': []}
    try:
        alerts = []
        for key in r.scan_iter('bgp_monitor:alerts:*', count=20):
            val = r.get(key)
            if val:
                try:
                    alerts.append(json.loads(val))
                except Exception:
                    alerts.append({'key': key})
            if len(alerts) >= 5:
                break
        return {'alerts': alerts, 'count': len(alerts)}
    except Exception:
        return {'alerts': []}

def _system_batch(r):
    return {'ts': datetime.utcnow().isoformat(), 'redis': bool(r)}

def _deception_batch(r):
    out = {'ts': datetime.utcnow().isoformat(), 'events': [], 'total': 0}
    if not r:
        return out
    try:
        from deception_event_bus import get_recent_events
        out['events'] = get_recent_events(10)
        out['total'] = r.llen('deception:events')
    except Exception as e:
        out['note'] = str(e)[:120]
    return out

def _detections_batch(r):
    out = {'llmfw': 0, 'detonate': 0}
    if r:
        try:
            out['llmfw'] = len(list(r.scan_iter('llmfw:events:*', count=10)))
            out['detonate'] = r.llen('detonate:queue') or 0
        except Exception:
            pass
    return out

@live_events_bp.before_request
def _auth():
    _require_login()

@live_events_bp.route('/api/live/events')
def live_events_stream():
    """SSE multiplex — ?streams=cowrie,bgp,system (comma-separated)."""
    _check_connection_cap()
    requested = request.args.get('streams', 'cowrie,system')
    streams = [s.strip() for s in requested.split(',') if s.strip() in VALID_STREAMS]
    if not streams:
        streams = ['cowrie', 'system']

    def generate():
        last_emit = {s: 0.0 for s in streams}
        try:
            while True:
                now = time.time()
                r = _get_redis()
                payload = {'ts': datetime.utcnow().isoformat(), 'streams': {}}
                for s in streams:
                    if now - last_emit[s] < THROTTLE_SEC[s]:
                        continue
                    if s == 'cowrie':
                        payload['streams']['cowrie'] = _cowrie_batch(r)
                    elif s == 'bgp':
                        payload['streams']['bgp'] = _bgp_batch(r)
                    elif s == 'system':
                        payload['streams']['system'] = _system_batch(r)
                    elif s == 'deception':
                        payload['streams']['deception'] = _deception_batch(r)
                    elif s == 'detections':
                        payload['streams']['detections'] = _detections_batch(r)
                    last_emit[s] = now
                yield f"data: {json.dumps(payload)}\n\n"
                time.sleep(0.25)
        except GeneratorExit:
            pass
        finally:
            _release_connection()

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )

def register_live_events(app, limiter):
    app.register_blueprint(live_events_bp)
    if 'live_events.live_events_stream' in app.view_functions:
        app.view_functions['live_events.live_events_stream'] = limiter.limit('10 per minute')(
            app.view_functions['live_events.live_events_stream']
        )