"""
WraithWall Sandbox Trial
========================

A self-serve 24-hour trial for authenticated users. A user starts ONE free
sandbox; for 24 hours they can exercise the *real* product endpoints (real data,
not mocked) from a guided console. When the window closes they are blocked and
prompted to contact the owner to pay and continue — the owner is alerted on
Telegram + email.

State lives entirely in Redis so expiry is automatic via TTL (no DB migration):
  sandbox:active:{user_id}   JSON {started_at, expires_at}    EX = 24h
  sandbox:used:{user_id}     "1"  (no expiry — marks the free trial as consumed)
  sandbox:runs:{user_id}     integer counter (abuse cap), expires with the session
  sandbox:continue:{user_id} JSON — set when the user requests to continue

Conventions mirror the other blueprints: bare blueprint, private _get_redis()
that degrades to None, lazy imports of feature modules to avoid circular imports,
structured jsonify() responses.
"""

import os
import json
import time
import logging
import threading
from datetime import datetime, timezone, timedelta
from wraithwall import thread_utils

from flask import Blueprint, request, jsonify, session, redirect, render_template

logger = logging.getLogger(__name__)

sandbox_bp = Blueprint('sandbox', __name__)

REDIS_URL = os.environ.get('REDIS_URL', '')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
OWNER_EMAIL = os.environ.get('SANDBOX_OWNER_EMAIL', 'contact@wraithwall.online')
SANDBOX_TTL = int(os.environ.get('SANDBOX_TTL_SECONDS', str(60 * 60 * 24)))  # 24h
RUN_CAP = int(os.environ.get('SANDBOX_RUN_CAP', '300'))  # max feature tests per session

_redis = None
_redis_tried = False

def _get_redis():
    global _redis, _redis_tried
    if _redis is not None or _redis_tried:
        return _redis
    _redis_tried = True
    if not REDIS_URL:
        return None
    try:
        import redis as redis_lib
        _redis = redis_lib.from_url(
            REDIS_URL, socket_connect_timeout=3, decode_responses=True, max_connections=5)
        _redis.ping()
    except Exception as e:
        logger.warning(f"[sandbox] Redis unavailable: {e}")
        _redis = None
    return _redis

def _now_iso():
    return datetime.now(timezone.utc).isoformat()

def _uid():
    try:

        if is_logged_in():
            uid = session.get('user_id')
            if uid:
                return uid
            email = session.get('user_email')
            if email:

                user = User.query.filter_by(email=email).first()
                if user:
                    session['user_id'] = user.id
                    return user.id
    except Exception:
        pass
    return None

def _email():
    try:

        if is_logged_in():
            email = session.get('user_email')
            if email:
                return email
            uid = session.get('user_id')
            if uid:

                user = User.query.get(int(uid))
                if user and user.email:
                    session['user_email'] = user.email
                    return user.email
    except Exception:
        pass
    return 'unknown'

def _is_admin():
    """Check if the current user is an admin — returns False for safety on any error."""
    try:

        return is_admin()
    except Exception:
        return False

# ---------------------------------------------------------------------------
# Feature dispatch — every entry returns REAL data from the live engines.
# Functions are imported lazily so a missing optional dep just disables one
# feature rather than breaking the blueprint.
# ---------------------------------------------------------------------------
def _run_llm_firewall(payload):
    from llm_firewall import analyze, ATLAS
    prompt = str(payload.get('prompt', ''))[:50000]
    context = str(payload.get('context', ''))[:50000]
    if not prompt.strip():
        return {'error': 'Enter a prompt to scan.'}, 400
    r = analyze(prompt, context)
    return {
        'verdict': r.verdict, 'confidence': r.confidence, 'category': r.category,
        'technique': r.technique, 'mitre_atlas': ATLAS.get(r.category, 'n/a'),
        'risk_score': r.risk_score, 'explanation': r.explanation,
        'detection_layer': r.layer,
    }, 200

def _run_url_scan(payload):
    from link_checker import run_full_scan
    raw = str(payload.get('input', '')).strip()[:2048]
    if not raw:
        return {'error': 'Enter a URL, domain, or IP to scan.'}, 400
    return run_full_scan(raw), 200

def _run_ip_intel(payload):
    from asn_intelligence import lookup_ip
    ip = str(payload.get('ip', '')).strip()[:64]
    if not ip:
        return {'error': 'Enter an IP address.'}, 400
    return (lookup_ip(ip) or {'ip': ip, 'note': 'No intelligence on record for this IP.'}), 200

def _run_bgp_check(payload):
    from bgp_monitor import is_ip_from_hijacked_prefix
    ip = str(payload.get('ip', '')).strip()[:64]
    if not ip:
        return {'error': 'Enter an IP address.'}, 400
    hit = is_ip_from_hijacked_prefix(ip)
    if hit:
        return {'ip': ip, 'in_hijacked_prefix': True, 'detail': hit}, 200
    return {'ip': ip, 'in_hijacked_prefix': False,
            'detail': 'IP is not within any currently-tracked hijacked prefix.'}, 200

def _run_sandbox_visit(payload):
    import base64
    import requests

    url = str(payload.get('url', '')).strip()[:2048]
    if not url:
        return {'error': 'Enter a URL to visit.'}, 400
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    if BROWSERLESS_API_KEY:
        try:
            desktop_res = requests.post(
                "https://chrome.browserless.io/screenshot",
                params={"token": BROWSERLESS_API_KEY},
                json={
                    "url": url,
                    "options": {"fullPage": True},
                    "viewport": {"width": 1920, "height": 1080},
                    "gotoOptions": {"waitUntil": "networkidle2", "timeout": 30000}
                },
                timeout=30
            )
            screenshot = base64.b64encode(desktop_res.content).decode('utf-8') if desktop_res.status_code == 200 else ""
            return {
                "url": url,
                "screenshot": screenshot,
                "content_type": desktop_res.headers.get('content-type', 'image/png') if desktop_res.status_code == 200 else ""
            }, 200
        except Exception as e:
            logger.error(f"[sandbox] Browserless render failed: {e}")
            return {'error': f'Browserless render failed: {str(e)[:200]}'}, 502
    return {'error': 'Browserless is not configured on this instance.'}, 503

FEATURES = {
    'llm_firewall': {
        'label': 'LLM Firewall', 'icon': 'fa-shield-halved',
        'desc': 'Scan a prompt for injection, jailbreak, exfiltration and 17 more attack classes.',
        'run': _run_llm_firewall,
    },
    'url_scan': {
        'label': 'URL / Domain / IP Reputation', 'icon': 'fa-link',
        'desc': 'Full reputation scan across the platform\'s threat-intel sources.',
        'run': _run_url_scan,
    },
    'ip_intel': {
        'label': 'IP / ASN Intelligence', 'icon': 'fa-diagram-project',
        'desc': 'Look up an IP\'s ASN, hosting profile, and abuse reputation.',
        'run': _run_ip_intel,
    },
    'bgp_check': {
        'label': 'BGP Hijack Check', 'icon': 'fa-route',
        'desc': 'Check whether an IP falls inside a currently-tracked hijacked prefix.',
        'run': _run_bgp_check,
    },
    'sandbox_visit': {
        'label': 'Browserless URL Render', 'icon': 'fa-globe',
        'desc': 'Visit a URL in a headless browser and capture a full-page screenshot.',
        'run': _run_sandbox_visit,
    },
}

# ---------------------------------------------------------------------------
# Session state helpers
# ---------------------------------------------------------------------------
def _state(uid):
    """Return (state, seconds_remaining, meta). state in none|active|expired."""
    r = _get_redis()
    if not r:
        return 'error', 0, {}
    ttl = r.ttl(f"sandbox:active:{uid}")
    if ttl and ttl > 0:
        raw = r.get(f"sandbox:active:{uid}")
        meta = {}
        try:
            meta = json.loads(raw) if raw else {}
        except Exception:
            meta = {}
        return 'active', ttl, meta
    if r.exists(f"sandbox:used:{uid}"):
        return 'expired', 0, {}
    return 'none', 0, {}

def _notify_owner(subject, body_text):
    """Alert the owner via Telegram + Resend email. Best-effort, off-thread."""
    def _send():
        try:

            send_telegram_alert_bg(f"\U0001F4B3 <b>{subject}</b>\n{body_text}")
        except Exception as e:
            logger.debug(f"[sandbox] telegram notify failed: {e}")
        if RESEND_API_KEY:
            try:
                import resend
                resend.api_key = RESEND_API_KEY
                resend.Emails.send({
                    "from": f"WraithWall Sandbox <{os.environ.get('FROM_EMAIL', 'noreply@wraithwall.online')}>",
                    "to": [OWNER_EMAIL],
                    "subject": subject,
                    "html": f"<p>{body_text}</p>",
                })
            except Exception as e:
                logger.debug(f"[sandbox] resend notify failed: {e}")
    thread_utils.spawn_request_thread(_send)

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@sandbox_bp.route('/sandbox')
def sandbox_page():
    # Authenticated surface; bounce to login carrying the deep link so the
    # post-login redirect (server-side, see main.py) returns the user here.
    try:

        if not is_logged_in():
            return redirect('/login?next=/sandbox')
    except Exception:
        return redirect('/login?next=/sandbox')
    return render_template('sandbox.html', user_email=_email(), owner_email=OWNER_EMAIL)

@sandbox_bp.route('/api/sandbox/status', methods=['GET'])
def sandbox_status():
    uid = _uid()
    if not uid:
        return jsonify({'error': 'Login required'}), 401
    r = _get_redis()
    if not r:
        return jsonify({'error': 'Sandbox store unavailable'}), 503
    state, remaining, meta = _state(uid)
    runs = int(r.get(f"sandbox:runs:{uid}") or 0)
    return jsonify({
        'state': state,
        'seconds_remaining': remaining,
        'started_at': meta.get('started_at'),
        'expires_at': meta.get('expires_at'),
        'runs_used': runs,
        'run_cap': RUN_CAP,
        'owner_email': OWNER_EMAIL,
        'features': [{'key': k, 'label': v['label'], 'icon': v['icon'], 'desc': v['desc']}
                     for k, v in FEATURES.items()],
    }), 200

@sandbox_bp.route('/api/sandbox/start', methods=['POST'])
def sandbox_start():
    uid = _uid()
    if not uid:
        return jsonify({'error': 'Login required'}), 401
    r = _get_redis()
    if not r:
        return jsonify({'error': 'Sandbox store unavailable'}), 503
    state, remaining, meta = _state(uid)
    is_admin_user = _is_admin()
    if state == 'active':
        return jsonify({'ok': True, 'state': 'active', 'seconds_remaining': remaining,
                        'message': 'Sandbox already running.'}), 200
    if state == 'expired':
        if not is_admin_user:
            _notify_owner('Sandbox re-activation interest',
                          f"User {_email()} (id {uid}) tried to restart an expired sandbox.")
            return jsonify({
                'ok': False, 'state': 'expired',
                'message': f'Your free 24-hour sandbox has ended. Contact {OWNER_EMAIL} to continue.',
                'owner_email': OWNER_EMAIL,
            }), 402
        # Admin override — clear the consumed flag and start fresh
        try:
            r.delete(f"sandbox:used:{uid}")
        except Exception:
            pass
    # Fresh trial.
    started = datetime.now(timezone.utc)
    expires = started + timedelta(seconds=SANDBOX_TTL)
    payload = json.dumps({'started_at': started.isoformat(), 'expires_at': expires.isoformat()})
    try:
        r.set(f"sandbox:active:{uid}", payload, ex=SANDBOX_TTL)
        r.set(f"sandbox:used:{uid}", '1')  # consumed — no second free trial
        r.set(f"sandbox:runs:{uid}", 0, ex=SANDBOX_TTL)
    except Exception as e:
        return jsonify({'error': f'Could not start sandbox: {e}'}), 500
    _notify_owner('New sandbox started',
                  f"User {_email()} (id {uid}) started a 24h sandbox trial.")
    return jsonify({'ok': True, 'state': 'active', 'seconds_remaining': SANDBOX_TTL,
                    'started_at': started.isoformat(), 'expires_at': expires.isoformat(),
                    'message': 'Sandbox started. You have 24 hours of full access.'}), 201

@sandbox_bp.route('/api/sandbox/run', methods=['POST'])
def sandbox_run():
    t0 = time.perf_counter()
    uid = _uid()
    if not uid:
        return jsonify({'error': 'Login required'}), 401
    r = _get_redis()
    if not r:
        return jsonify({'error': 'Sandbox store unavailable'}), 503
    is_admin_user = _is_admin()
    state, remaining, _ = _state(uid)
    if state == 'expired' and not is_admin_user:
        return jsonify({
            'error': 'sandbox_expired',
            'message': f'Your 24-hour sandbox has ended. Contact {OWNER_EMAIL} to continue.',
            'owner_email': OWNER_EMAIL,
        }), 402
    if state == 'expired' and is_admin_user:
        # Admin bypass — auto-restart the sandbox
        started = datetime.now(timezone.utc)
        expires = started + timedelta(seconds=SANDBOX_TTL)
        payload = json.dumps({'started_at': started.isoformat(), 'expires_at': expires.isoformat()})
        try:
            r.delete(f"sandbox:used:{uid}")
            r.set(f"sandbox:active:{uid}", payload, ex=SANDBOX_TTL)
            r.set(f"sandbox:runs:{uid}", 0, ex=SANDBOX_TTL)
            state, remaining, _ = 'active', SANDBOX_TTL, {}
        except Exception:
            pass
    if state != 'active':
        return jsonify({'error': 'no_sandbox', 'message': 'Start your sandbox first.'}), 403

    # Abuse cap.
    runs = r.incr(f"sandbox:runs:{uid}")
    if runs == 1:
        r.expire(f"sandbox:runs:{uid}", remaining or SANDBOX_TTL)
    if runs > RUN_CAP:
        return jsonify({'error': 'run_cap', 'message': 'Sandbox test limit reached for this session.'}), 429

    data = request.get_json(silent=True) or {}
    feature = str(data.get('feature', '')).strip()
    payload = data.get('payload', {}) or {}
    spec = FEATURES.get(feature)
    if not spec:
        return jsonify({'error': 'unknown_feature',
                        'message': f'Unknown feature "{feature}".'}), 400
    try:
        result, status = spec['run'](payload)
    except Exception as e:
        logger.warning(f"[sandbox] feature {feature} error: {e}")
        return jsonify({'error': 'feature_error', 'message': str(e)[:200]}), 502

    return jsonify({
        'ok': status == 200,
        'feature': feature,
        'result': result,
        'seconds_remaining': remaining,
        'runs_used': runs,
        'latency_ms': int((time.perf_counter() - t0) * 1000),
    }), status

@sandbox_bp.route('/api/sandbox/request-continue', methods=['POST'])
def sandbox_request_continue():
    uid = _uid()
    if not uid:
        return jsonify({'error': 'Login required'}), 401
    r = _get_redis()
    data = request.get_json(silent=True) or {}
    note = str(data.get('note', ''))[:500]
    if r:
        try:
            r.set(f"sandbox:continue:{uid}",
                  json.dumps({'email': _email(), 'note': note, 'at': _now_iso()}))
        except Exception:
            pass
    _notify_owner(
        'Sandbox: customer wants to pay & continue',
        f"User {_email()} (id {uid}) requested to continue after their sandbox."
        + (f"<br>Note: {note}" if note else ''))
    return jsonify({'ok': True,
                    'message': f'Thanks — we\'ve notified {OWNER_EMAIL}. You\'ll hear back shortly.'}), 200
