import os
import hmac
import hashlib
import secrets
import time
import json
import logging
from datetime import datetime, timezone
from flask import Blueprint, request, render_template, jsonify, redirect, make_response, current_app
import redis

# ─── Configuration ───────────────────────────────────────────────────────────
GATEWAY_SECRET   = os.getenv('GATEWAY_SECRET', secrets.token_hex(32))
COOKIE_NAME      = 'ezm_gw'
COOKIE_TTL       = 60 * 30          # 30 minutes
CHALLENGE_TTL    = 60 * 5           # 5 minutes
BLOCK_TTL        = 60 * 60 * 24     # 24 hours
POW_DIFFICULTY   = 4                # 4 leading hex zeros
SCORE_THRESHOLD  = 0.60
HARD_BLOCK_SCORE = 0.90
FAIL_WINDOW      = 60 * 60          # 1 hour
FAIL_THRESHOLD   = 3
VERIFY_RATE_LIMIT = 5               # per minute per IP

# ─── Redis (lazy — no connection at import time) ─────────────────────────────
_redis_client = None


def _redis():
    global _redis_client
    if _redis_client is not None:
        return _redis_client
    url = os.getenv("REDIS_URL", "")
    if not url:
        return None
    try:
        client = redis.from_url(url, decode_responses=True, socket_connect_timeout=2)
        client.ping()
        _redis_client = client
        return _redis_client
    except Exception:
        return None


# ─── Audit log (configurable path; stdout fallback) ──────────────────────────
audit_log = logging.getLogger("gateway.audit")
if not audit_log.handlers:
    _audit_path = os.getenv("GATEWAY_AUDIT_LOG", "")
    _handler = (
        logging.FileHandler(_audit_path, mode="a")
        if _audit_path
        else logging.StreamHandler()
    )
    _handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
    audit_log.addHandler(_handler)
    audit_log.setLevel(logging.INFO)

def _audit(event, ip, **kwargs):
    audit_log.info(json.dumps({
        'ts': datetime.now(timezone.utc).isoformat(),
        'event': event,
        'ip': ip,
        **kwargs,
    }))

# ─── Helpers ─────────────────────────────────────────────────────────────────
def _client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown').split(',')[0].strip()

def _sign(payload: str) -> str:
    return hmac.new(GATEWAY_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()

def _make_token(nonce: str, issued_at: int) -> str:
    body = f"{nonce}.{issued_at}"
    return f"{body}.{_sign(body)}"

def _verify_token(token: str, max_age: int = CHALLENGE_TTL):
    try:
        nonce, issued_at, sig = token.split('.')
        expected = _sign(f"{nonce}.{issued_at}")
        if not hmac.compare_digest(sig, expected):
            return None
        if int(time.time()) - int(issued_at) > max_age:
            return None
        return {'nonce': nonce, 'issued_at': int(issued_at)}
    except Exception:
        return None

def _make_cookie_value() -> str:
    issued_at = int(time.time())
    body = f"pass.{issued_at}"
    return f"{body}.{_sign(body)}"

def _has_valid_gateway_cookie() -> bool:
    cookie = request.cookies.get(COOKIE_NAME)
    if not cookie:
        return False
    try:
        prefix, issued_at, sig = cookie.split('.')
        if prefix != 'pass':
            return False
        expected = _sign(f"{prefix}.{issued_at}")
        if not hmac.compare_digest(sig, expected):
            return False
        if int(time.time()) - int(issued_at) > COOKIE_TTL:
            return False
        return True
    except Exception:
        return False

def is_ip_blocked(ip: str):
    """Returns block expiry timestamp if blocked, else None."""
    store = _redis()
    if not store:
        return None
    ttl = store.ttl(f"gateway:blocked:{ip}")
    if ttl and ttl > 0:
        return ttl
    return None

def _rate_limit_verify(ip: str) -> bool:
    store = _redis()
    if not store:
        return True
    key = f"gateway:verify_rl:{ip}"
    count = store.incr(key)
    if count == 1:
        store.expire(key, 60)
    return count <= VERIFY_RATE_LIMIT

def _get_session_tier(ip: str) -> str:
    """Compute read-only coarse risk tier for the adaptive verification flow.

    Derived exclusively from signals already collected by the gateway:
    - Presence of a gateway cookie (indicating a returning session attempt)
    - Recent failure count from Redis (existing rate-limit/fail tracking)

    Returns one of 'returning', 'new', or 'high-risk'. No new detection
    logic or data collection is introduced.

    No new environment variable is required.
    """
    if is_ip_blocked(ip):
        return 'high-risk'
    store = _redis()
    fails = int(store.get(f"gateway:fails:{ip}") or 0) if store else 0
    if fails >= 1:
        return 'high-risk'
    if request.cookies.get(COOKIE_NAME):
        return 'returning'
    return 'new'

# ─── PoW ─────────────────────────────────────────────────────────────────────
def _new_pow_challenge():
    nonce = secrets.token_hex(16)
    store = _redis()
    if store:
        store.setex(f"gateway:challenge:{nonce}", CHALLENGE_TTL, POW_DIFFICULTY)
    return {'nonce': nonce, 'difficulty': POW_DIFFICULTY}

def _verify_pow(nonce: str, counter, difficulty: int) -> bool:
    try:
        counter = str(counter)
        h = hashlib.sha256(f"{nonce}{counter}".encode()).hexdigest()
        return h.startswith('0' * difficulty)
    except Exception:
        return False

# ─── Scoring ─────────────────────────────────────────────────────────────────
def _score_signals(payload: dict, pow_ok: bool, token_ok: bool) -> tuple:
    score = 0.0
    breakdown = {}

    if pow_ok:
        score += 0.20; breakdown['pow'] = 0.20

    timing = payload.get('timing_ms', 0) or 0
    if 800 <= timing <= 30000:
        score += 0.15; breakdown['timing'] = 0.15

    mouse_entropy = payload.get('mouse_entropy', 0) or 0
    if mouse_entropy > 3.0:
        score += 0.15; breakdown['mouse'] = 0.15

    scroll = payload.get('scroll_dynamics') or {}
    if scroll.get('events', 0) > 0 or scroll.get('present'):
        score += 0.10; breakdown['scroll'] = 0.10

    if payload.get('canvas_hash') and len(payload['canvas_hash']) == 64:
        score += 0.10; breakdown['canvas'] = 0.10

    webgl = payload.get('webgl') or {}
    renderer = (webgl.get('renderer') or '').lower()
    if renderer and 'swiftshader' not in renderer and 'llvmpipe' not in renderer:
        score += 0.10; breakdown['webgl'] = 0.10

    audio_fp = payload.get('audio_fp')
    if audio_fp and len(audio_fp) >= 16:
        score += 0.10; breakdown['audio'] = 0.10

    motion_entropy = payload.get('motion_entropy', 0) or 0
    if motion_entropy > 1.0:
        score += 0.10; breakdown['motion'] = 0.10

    fonts = payload.get('fonts') or []
    if isinstance(fonts, list) and len(fonts) > 10:
        score += 0.05; breakdown['fonts'] = 0.05

    if payload.get('battery_present'):
        score += 0.05; breakdown['battery'] = 0.05

    return round(score, 3), breakdown

# ─── Blueprint ───────────────────────────────────────────────────────────────
gateway_bp = Blueprint('gateway', __name__)

@gateway_bp.route('/gateway')
def gateway_page():
    ip = _client_ip()
    if is_ip_blocked(ip):
        ttl = is_ip_blocked(ip)
        _audit('gateway_blocked_view', ip, ttl=ttl)
        return render_template('gateway_blocked.html', cooldown_seconds=ttl), 403

    challenge = _new_pow_challenge()
    issued_at = int(time.time())
    challenge_token = _make_token(challenge['nonce'], issued_at)

    _audit('gateway_view', ip, nonce=challenge['nonce'])

    tier = _get_session_tier(ip)
    return render_template(
        'gateway.html',
        challenge_token=challenge_token,
        pow_nonce=challenge['nonce'],
        pow_difficulty=challenge['difficulty'],
        tier=tier,
    )

@gateway_bp.route('/gateway/challenge', methods=['GET'])
def gateway_challenge():
    ip = _client_ip()
    if is_ip_blocked(ip):
        return jsonify({'error': 'blocked'}), 403

    challenge = _new_pow_challenge()
    issued_at = int(time.time())
    token = _make_token(challenge['nonce'], issued_at)
    tier = _get_session_tier(ip)
    return jsonify({
        'token': token,
        'nonce': challenge['nonce'],
        'difficulty': challenge['difficulty'],
        'tier': tier,
    })

@gateway_bp.route('/gateway/verify', methods=['POST'])
def gateway_verify():
    ip = _client_ip()

    # IP block check
    if is_ip_blocked(ip):
        return jsonify({'ok': False, 'reason': 'blocked'}), 403

    # Rate limit
    if not _rate_limit_verify(ip):
        _audit('gateway_rate_limited', ip)
        return jsonify({'ok': False, 'reason': 'rate_limited'}), 429

    data = request.get_json(silent=True) or {}
    token = data.get('token', '')
    pow_counter = data.get('pow_counter')
    pow_nonce = data.get('pow_nonce')

    # Token check (HMAC + age)
    token_data = _verify_token(token)
    token_ok = bool(token_data)

    # PoW verification (single hash compute, <1ms)
    pow_ok = False
    if token_ok and pow_nonce == token_data['nonce']:
        store = _redis()
        difficulty_str = store.get(f"gateway:challenge:{pow_nonce}") if store else None
        if difficulty_str is not None:
            difficulty = int(difficulty_str)
            # Single-use: delete immediately
            store.delete(f"gateway:challenge:{pow_nonce}")
            pow_ok = _verify_pow(pow_nonce, pow_counter, difficulty)

    # Score signals
    score, breakdown = _score_signals(data, pow_ok, token_ok)
    threat_score = round(1.0 - score, 3)
    passed = score >= SCORE_THRESHOLD and token_ok

    if passed:
        _audit('gateway_pass', ip, score=score, breakdown=breakdown)
        resp = make_response(jsonify({'ok': True, 'redirect': '/signup', 'score': score}))
        resp.set_cookie(
            COOKIE_NAME, _make_cookie_value(),
            max_age=COOKIE_TTL, httponly=True, samesite='Lax',
            secure=request.is_secure,
        )
        return resp

    # Failure tracking
    fail_key = f"gateway:fails:{ip}"
    store = _redis()
    fails = store.incr(fail_key) if store else 1
    if store and fails == 1:
        store.expire(fail_key, FAIL_WINDOW)

    _audit('gateway_fail', ip, score=score, threat=threat_score,
           breakdown=breakdown, fails=fails, pow_ok=pow_ok, token_ok=token_ok)

    # Hard block
    if threat_score >= HARD_BLOCK_SCORE and fails >= FAIL_THRESHOLD:
        if store:
            store.setex(f"gateway:blocked:{ip}", BLOCK_TTL, "1")
        _audit('gateway_hard_block', ip, threat=threat_score, fails=fails)
        return jsonify({'ok': False, 'reason': 'blocked', 'redirect': '/gateway/blocked'}), 403

    return jsonify({'ok': False, 'reason': 'failed', 'score': score}), 400

@gateway_bp.route('/gateway/blocked')
def gateway_blocked():
    ip = _client_ip()
    ttl = is_ip_blocked(ip) or 0
    return render_template('gateway_blocked.html', cooldown_seconds=ttl), 403


class Gateway:
    """Public API for gateway blocklist and verification helpers."""

    @staticmethod
    def is_ip_blocked(ip: str):
        """Return remaining block TTL seconds, or None if not blocked."""
        return is_ip_blocked(ip)

    @staticmethod
    def configure(*, audit_log_path: str | None = None, redis_url: str | None = None) -> None:
        """Override gateway storage and audit destinations at runtime."""
        global _redis_client
        if redis_url is not None:
            os.environ["REDIS_URL"] = redis_url
            _redis_client = None
        if audit_log_path is not None:
            os.environ["GATEWAY_AUDIT_LOG"] = audit_log_path
