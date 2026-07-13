"""
Deception event bus — unified telemetry for cross-VPS bait correlation.
Publishes to Redis deception:events (30d) per DECEPTION_PIPELINE.md / DEPLOYMENT_SEQUENCE.md.
"""
import json
import logging
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

import redis as redis_lib
from flask import Blueprint, jsonify, request, abort

logger = logging.getLogger(__name__)

deception_bus_bp = Blueprint('deception_bus', __name__)

REDIS_URL = __import__('os').environ.get('REDIS_URL', '')
EVENTS_KEY = 'deception:events'
EVENTS_TTL = 86400 * 30
EVENTS_MAX = 10000
IP_WINDOW_TTL = 86400
PIVOT_MIN_SOURCES = 2
ALERT_DEDUP_TTL = 300
CHAIN_KEY_PREFIX = 'deception:chain:'
CHAIN_TTL = 86400
CHAIN_ALERT_DEDUP_TTL = 3600

# Phase 4.3 — progression stages for chained pivot alerts (24h window)
CHAIN_STAGES = {
    'cowrie': frozenset({'cowrie_intelligence', 'cowrie_honeyfs'}),
    'beacon': frozenset({'canary_service'}),
    'reverse': frozenset({'reverse_canary', 'honey_token'}),
}

HONEYFS_BAIT_MAP = {
    '/root/.ssh/id_rsa': ('C-05', 'credential', 2),
    '/root/.aws/credentials': ('C-03', 'credential', 2),
    '/root/.docker/config.json': ('C-07', 'credential', 2),
    '/home/deploy/.git-credentials': ('C-04', 'credential', 2),
    '/home/deploy/.my.cnf': ('C-08', 'credential', 2),
    '/var/www/ezmcyber/.env': ('C-09', 'credential', 2),
    '/var/www/ezmcyber/.git/config': ('C-10', 'credential', 2),
    '/root/.bash_history': ('C-01', 'credential', 2),
    '/var/backups/db_dump_20260708.sql': ('S-07', 'credential', 2),
    '/var/backups/db_dump_20260708.sql.gz': ('S-07', 'credential', 2),
    '/var/log/nginx/access.log': ('S-08', 'beacon', 2),
    '/var/log/auth.log': ('S-09', 'beacon', 2),
    '/opt/docker-compose/docker-compose.yml': ('S-10', 'credential', 2),
}

@dataclass
class DeceptionEvent:
    event_id: str
    timestamp: float
    source: str
    bait_id: str
    bait_type: str
    trigger_type: str
    attacker_ip: str
    attacker_metadata: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    bait_layer: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeceptionEvent':
        return cls(
            event_id=data.get('event_id', ''),
            timestamp=float(data.get('timestamp', 0)),
            source=data.get('source', ''),
            bait_id=data.get('bait_id', ''),
            bait_type=data.get('bait_type', ''),
            trigger_type=data.get('trigger_type', ''),
            attacker_ip=data.get('attacker_ip', ''),
            attacker_metadata=data.get('attacker_metadata') or {},
            context=data.get('context') or {},
            bait_layer=int(data.get('bait_layer', 0)),
        )

def _redis():
    if not REDIS_URL:
        return None
    try:
        return redis_lib.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=3)
    except Exception:
        return None

def _require_login():

    if not is_logged_in():
        abort(401)

def _tier_safe_event(ev: DeceptionEvent) -> Dict[str, Any]:
    """API response — no Tier-3 fields in context."""
    d = ev.to_dict()
    ctx = dict(d.get('context') or {})
    for k in list(ctx.keys()):
        if any(x in k.lower() for x in ('password', 'secret', 'seed', 'private_key', 'credential_hash')):
            ctx[k] = '[redacted]'
    d['context'] = ctx
    return d

def publish_deception_event(
    source: str,
    bait_id: str,
    bait_type: str,
    trigger_type: str,
    attacker_ip: str,
    *,
    attacker_metadata: Optional[Dict] = None,
    context: Optional[Dict] = None,
    bait_layer: int = 0,
) -> Optional[DeceptionEvent]:
    """Publish to deception:events + per-IP index; pivot + immutable log on match."""
    if not attacker_ip:
        return None
    ev = DeceptionEvent(
        event_id=f"evt_{uuid.uuid4().hex}",
        timestamp=time.time(),
        source=source,
        bait_id=bait_id,
        bait_type=bait_type,
        trigger_type=trigger_type,
        attacker_ip=attacker_ip,
        attacker_metadata=attacker_metadata or {},
        context=context or {},
        bait_layer=bait_layer,
    )
    r = _redis()
    payload = json.dumps(ev.to_dict())
    if r:
        try:
            pipe = r.pipeline()
            pipe.lpush(EVENTS_KEY, payload)
            pipe.ltrim(EVENTS_KEY, 0, EVENTS_MAX - 1)
            pipe.expire(EVENTS_KEY, EVENTS_TTL)
            ip_key = f"deception:{attacker_ip}:events"
            pipe.lpush(ip_key, payload)
            pipe.ltrim(ip_key, 0, 499)
            pipe.expire(ip_key, IP_WINDOW_TTL)
            pipe.execute()
            _check_pivot(r, ev)
            _check_chain(r, ev)
        except Exception as e:
            logger.warning(f"deception bus redis write failed: {e}")

    try:

        write_immutable_log({
            'event': 'deception_event',
            'event_id': ev.event_id,
            'source': ev.source,
            'bait_id': ev.bait_id,
            'bait_type': ev.bait_type,
            'trigger_type': ev.trigger_type,
            'attacker_ip': ev.attacker_ip,
            'bait_layer': ev.bait_layer,
        })
    except Exception:
        pass

    try:
        from campaign_correlator import get_correlator
        get_correlator().ingest_deception_event(ev.to_dict())
    except Exception as e:
        logger.debug(f"deception→campaign ingest skipped: {e}")

    return ev

def _chain_stage(ev: DeceptionEvent) -> Optional[str]:
    src = ev.source or ''
    if src in CHAIN_STAGES['cowrie']:
        return 'cowrie'
    if src in CHAIN_STAGES['beacon'] or ev.bait_type == 'beacon':
        return 'beacon'
    if src in CHAIN_STAGES['reverse']:
        if src == 'honey_token' and ev.bait_type != 'reverse_canary':
            return None
        return 'reverse'
    return None

def _check_chain(r, ev: DeceptionEvent):
    """Phase 4.3 — alert when same IP hits cowrie → beacon → reverse within 24h."""
    stage = _chain_stage(ev)
    if not stage or not ev.attacker_ip:
        return
    key = f'{CHAIN_KEY_PREFIX}{ev.attacker_ip}'
    try:
        raw = r.get(key)
        chain = json.loads(raw) if raw else {}
    except Exception:
        chain = {}
    ts = ev.timestamp or time.time()
    if stage not in chain or ts < chain[stage]:
        chain[stage] = ts
    r.setex(key, CHAIN_TTL, json.dumps(chain))

    required = ('cowrie', 'beacon', 'reverse')
    if not all(s in chain for s in required):
        return
    oldest = min(chain[s] for s in required)
    if (ts - oldest) > CHAIN_TTL:
        return

    dedup_key = f'deception:chain:alert:{ev.attacker_ip}'
    if not r.set(dedup_key, '1', nx=True, ex=CHAIN_ALERT_DEDUP_TTL):
        return

    hours = (max(chain.values()) - min(chain.values())) / 3600
    order = []
    for s in required:
        order.append(f"{s} @ {time.strftime('%H:%M', time.gmtime(chain[s]))}Z")
    msg = (
        f"🚨 <b>PIVOT DETECTED — FULL CHAIN</b>\n"
        f"<b>IP:</b> <code>{ev.attacker_ip}</code>\n"
        f"<b>Progression:</b> Cowrie → beacon → reverse canary\n"
        f"<b>Span:</b> {hours:.1f} hours\n"
        f"<b>Stages:</b>\n" + '\n'.join(f"  • {line}" for line in order) + '\n'
        f"<b>Latest:</b> {ev.source} / {ev.bait_id}"
    )
    try:

        write_immutable_log({
            'event': 'deception_chain_pivot',
            'attacker_ip': ev.attacker_ip,
            'chain': {k: chain[k] for k in required},
            'span_hours': round(hours, 2),
        })
    except Exception:
        pass
    try:

        send_telegram_alert_bg(msg)
    except Exception:
        pass

def _check_pivot(r, ev: DeceptionEvent):
    ip_key = f"deception:{ev.attacker_ip}:events"
    raw = r.lrange(ip_key, 0, 99)
    sources = set()
    bait_types = set()
    for item in raw:
        try:
            d = json.loads(item)
            sources.add(d.get('source', ''))
            bait_types.add(d.get('bait_type', ''))
        except Exception:
            continue
    if len(sources) < PIVOT_MIN_SOURCES and len(bait_types) < PIVOT_MIN_SOURCES:
        return
    dedup_key = f"deception:pivot:alert:{ev.attacker_ip}"
    if not r.set(dedup_key, '1', nx=True, ex=ALERT_DEDUP_TTL):
        return
    msg = (
        f"🔗 <b>DECEPTION PIVOT</b>\n"
        f"<b>IP:</b> <code>{ev.attacker_ip}</code>\n"
        f"<b>Sources:</b> {', '.join(sorted(s for s in sources if s))}\n"
        f"<b>Bait types:</b> {', '.join(sorted(b for b in bait_types if b))}\n"
        f"<b>Latest:</b> {ev.source} / {ev.bait_id}"
    )
    try:

        send_telegram_alert_bg(msg)
    except Exception:
        pass

def get_recent_events(limit: int = 50) -> List[Dict]:
    r = _redis()
    if not r:
        return []
    limit = min(max(limit, 1), 200)
    out = []
    for item in r.lrange(EVENTS_KEY, 0, limit - 1):
        try:
            ev = DeceptionEvent.from_dict(json.loads(item))
            out.append(_tier_safe_event(ev))
        except Exception:
            continue
    return out

def detect_honeyfs_command(command: str) -> Optional[tuple]:
    cmd = (command or '').lower()
    for path, (bait_id, bait_type, layer) in HONEYFS_BAIT_MAP.items():
        if path.lower() in cmd:
            return bait_id, bait_type, layer, path
    return None

@deception_bus_bp.before_request
def _auth():
    _require_login()

@deception_bus_bp.route('/api/deception/events')
def list_events():
    limit = min(int(request.args.get('limit', 50)), 200)
    events = get_recent_events(limit)
    r = _redis()
    total = r.llen(EVENTS_KEY) if r else 0
    return jsonify({'ok': True, 'events': events, 'count': len(events), 'total': total})

@deception_bus_bp.route('/api/deception/events/<ip>')
def events_for_ip(ip):
    if len(ip) > 45:
        abort(400)
    r = _redis()
    if not r:
        return jsonify({'ok': True, 'events': [], 'ip': ip})
    out = []
    for item in r.lrange(f"deception:{ip}:events", 0, 99):
        try:
            ev = DeceptionEvent.from_dict(json.loads(item))
            out.append(_tier_safe_event(ev))
        except Exception:
            continue
    return jsonify({'ok': True, 'ip': ip, 'events': out, 'count': len(out)})

@deception_bus_bp.route('/api/deception/stats')
def deception_stats():
    r = _redis()
    if not r:
        return jsonify({'ok': True, 'total': 0, 'pivot_candidates': 0})
    total = r.llen(EVENTS_KEY)
    pivots = len(list(r.scan_iter('deception:pivot:alert:*', count=100)))
    chains = len(list(r.scan_iter('deception:chain:alert:*', count=100)))
    by_source = {}
    for item in r.lrange(EVENTS_KEY, 0, 199):
        try:
            s = json.loads(item).get('source', 'unknown')
            by_source[s] = by_source.get(s, 0) + 1
        except Exception:
            pass
    return jsonify({
        'ok': True, 'total': total, 'pivot_alerts': pivots,
        'chain_alerts': chains, 'by_source': by_source,
    })

def register_deception_event_bus(app, limiter):
    app.register_blueprint(deception_bus_bp)
    limits = {
        'deception_bus.list_events': '60 per minute',
        'deception_bus.events_for_ip': '30 per minute',
        'deception_bus.deception_stats': '60 per minute',
    }
    for endpoint, rule in limits.items():
        if endpoint in app.view_functions:
            app.view_functions[endpoint] = limiter.limit(rule)(app.view_functions[endpoint])