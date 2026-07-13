"""
ai_runtime_security.py — WraithWall AI Runtime Security Platform (AIRS).

A runtime firewall for LLM / agent applications. Customer backends call our
versioned API server-to-server with an API key; we inspect the prompt, context,
RAG chunks, and tool calls, score the risk, evaluate the customer's policy, and
return an allow / flag / block verdict — logging every decision and alerting on
high-risk events.

This module is ADDITIVE and feature-flagged: it is only imported + registered in
main.py when ENABLE_AI_RUNTIME_SECURITY=true, so it cannot affect existing
functionality when off. It reuses existing engines rather than reinventing them:
  - llm_honeypot.classify_injection()  → prompt-injection detection (MITRE ATLAS)
  - main.send_telegram_alert_bg / Discord → Alerting Pipeline
  - main.write_immutable_log            → tamper-evident Audit Logging
  - main.verify_api_signature / has_permission → API-key auth (scope ai:threat)
  - asn_intelligence.IPEnrichmentEngine → Threat Intelligence (deep path only)

The 12 modules in the spec map to functions/sections below:
  1 Prompt Inspection Engine ...... inspect() orchestrator
  2 Prompt Injection Detection ..... _detect_injection()  (reuses classify_injection)
  3 Jailbreak Detection ............ _detect_jailbreak()
  4 Indirect Prompt Injection ...... _detect_indirect()
  5 RAG Content Inspection ......... _detect_rag()
  6 Tool Abuse Detection ........... _detect_tool_abuse()
  7 Risk Scoring Engine ............ _score()
  8 Policy Engine .................. _evaluate_policy()
  9 Threat Intelligence Engine ..... _enrich_actor() / _track_actor()
 10 Audit Logging .................. _record_detection() + write_immutable_log
 11 Detection Dashboard ............ /detections, /dashboard/stats + airs-dashboard.html
 12 Alerting Pipeline .............. _fire_alert()

All API routes are versioned under /api/airs/v1.
"""
import os
import re
import json
import time
import hashlib
import logging
import threading
from datetime import datetime, timedelta
from wraithwall import thread_utils

from flask import Blueprint, request, jsonify, session, render_template

logger = logging.getLogger(__name__)

ai_runtime_bp = Blueprint('ai_runtime_security', __name__)

API_VERSION = 'v1'
AIRS_SCOPE = 'ai:threat'           # existing scope in main.VALID_SCOPES
DEDUP_TTL = 300                    # per owner+technique alert collapse window (s)
RL_BURST_TTL = 60                  # per-key burst window (s)
RL_BURST_MAX = int(os.getenv('AIRS_BURST_PER_MIN', '120'))
MAX_INPUT_LEN = 100_000            # hard cap to keep inspection bounded
STORE_PREVIEW_DEFAULT = os.getenv('AIRS_STORE_PREVIEW', 'false').lower() == 'true'

# ────────────────────────────────────────────────────────────
# small helpers
# ────────────────────────────────────────────────────────────
def _redis():
    try:

        return get_redis()
    except Exception:
        return None

def _err(msg, code):
    return jsonify({"ok": False, "error": msg}), code

def _now():
    return datetime.utcnow()

def _sha(s):
    return hashlib.sha256((s or '').encode('utf-8', 'replace')).hexdigest()

def _as_text(v, limit=MAX_INPUT_LEN):
    if v is None:
        return ''
    if not isinstance(v, str):
        try:
            v = json.dumps(v)
        except Exception:
            v = str(v)
    return v[:limit]

# ────────────────────────────────────────────────────────────
# auth — mirrors main.require_permission('ai:threat') but callable inline
# (blueprints here import from main lazily to avoid the circular import)
# ────────────────────────────────────────────────────────────
def _auth_customer():
    """Authenticate a customer API call. Allows a logged-in session OR a valid
    API key carrying the ai:threat scope. Returns (ctx, err_response).
    ctx = {'user_id': int, 'api_key_id': int|None}."""

                      log_audit, db, APIKeyUsage)
    # session path (dashboard "try it" / first-party)
    if is_logged_in():
        user = User.query.filter_by(email=session.get('user_email')).first()
        if not user:
            return None, _err("User not found", 404)
        return {'user_id': user.id, 'api_key_id': None}, None

    # API-key path
    ok, result = verify_api_signature()
    if not ok:
        log_audit(None, 'airs_auth_failed', False, details=result)
        return None, _err(result, 401)
    key = result
    if not has_permission(key, AIRS_SCOPE):
        log_audit(None, 'airs_permission_denied', False,
                  details=f"key missing scope {AIRS_SCOPE}")
        return None, _err(f"API key lacks '{AIRS_SCOPE}' scope", 403)

    # daily quota (reuse the existing APIKeyUsage mechanism)
    try:
        today = _now().date()
        usage = APIKeyUsage.query.filter_by(api_key_id=key.id, date=today).first()
        if usage and usage.request_count >= (key.rate_limit or 1000):
            return None, _err("Rate limit exceeded", 429)
        if not usage:
            usage = APIKeyUsage(api_key_id=key.id, date=today, request_count=0)
            db.session.add(usage)
        usage.request_count += 1
        key.last_used = _now()
        db.session.commit()
    except Exception:
        db_rollback()

    # burst limit (Redis) — protects against a single key hammering us
    r = _redis()
    if r:
        try:
            bkey = f"airs:rl:{key.id}"
            n = r.incr(bkey)
            if n == 1:
                r.expire(bkey, RL_BURST_TTL)
            if n > RL_BURST_MAX:
                return None, _err("Burst rate limit exceeded", 429)
        except Exception:
            pass
    return {'user_id': key.user_id, 'api_key_id': key.id}, None

def _auth_session():
    """Dashboard endpoints: require a logged-in user. Returns (user, err)."""

    if not is_logged_in():
        return None, _err("Login required", 401)
    user = User.query.filter_by(email=session.get('user_email')).first()
    if not user:
        return None, _err("User not found", 404)
    return user, None

def db_rollback():
    try:

        db.session.rollback()
    except Exception:
        pass

def _client_ip():
    """The API caller's IP (the customer's server), via the trusted proxy."""
    try:

        return get_real_ip()
    except Exception:
        return (request.remote_addr or 'unknown')

# ────────────────────────────────────────────────────────────
# MODULE 2 — Prompt Injection Detection (reuses llm_honeypot)
# ────────────────────────────────────────────────────────────
def _detect_injection(text):
    """Reuse the existing MITRE-ATLAS prompt-injection classifier."""
    if not text:
        return {"hit": False, "score": 0, "techniques": [], "primary": None}
    try:
        from llm_honeypot import classify_injection
        res = classify_injection(text)
        return {
            "hit": bool(res.get("is_injection")),
            "score": int(res.get("confidence") or 0),
            "techniques": res.get("techniques") or [],
            "primary": res.get("primary_technique"),
            "threat_level": res.get("threat_level", "none"),
        }
    except Exception as e:
        logger.error(f"airs injection detector error: {e}")
        return {"hit": False, "score": 0, "techniques": [], "primary": None}

# ────────────────────────────────────────────────────────────
# MODULE 3 — Jailbreak Detection
# ────────────────────────────────────────────────────────────
_JAILBREAK_PATTERNS = [
    (re.compile(r'\b(do anything now|^dan\b|stay in dan mode|dan mode)\b', re.I), 'dan_persona', 'AML.T0054', 90),
    (re.compile(r'\bdeveloper mode (enabled|on)\b', re.I), 'developer_mode', 'AML.T0054', 88),
    (re.compile(r'\b(you are|act as|pretend to be|roleplay as)\b.{0,40}\b(unfiltered|uncensored|no rules|no restrictions|evil|jailbroken)\b', re.I), 'persona_override', 'AML.T0054', 86),
    (re.compile(r'\bignore (all|any|your|previous|prior) (instructions|guidelines|rules|policies)\b', re.I), 'instruction_override', 'AML.T0051', 92),
    (re.compile(r'\b(disregard|forget|override) (the above|previous|all prior|your) (instructions|rules|system prompt)\b', re.I), 'context_reset', 'AML.T0051', 90),
    (re.compile(r'\bwithout (any )?(ethical|safety|moral|content) (filter|guidelines|restrictions|considerations)\b', re.I), 'safety_bypass', 'AML.T0054', 85),
    (re.compile(r'\b(grandma|grandmother|deceased relative) .{0,40}(used to|would) (tell|read|recite)\b', re.I), 'emotional_exploit', 'AML.T0054', 78),
    (re.compile(r'\b(hypothetically|in a fictional (world|story|scenario)|for educational purposes only).{0,60}\b(make|build|synthesize|exploit|bypass)\b', re.I), 'fiction_framing', 'AML.T0054', 72),
    (re.compile(r'\b(base64|rot13|reverse the|decode this)\b.{0,40}\b(instruction|prompt|command)\b', re.I), 'encoding_evasion', 'AML.T0051', 80),
]

def _detect_jailbreak(text):
    if not text:
        return {"hit": False, "score": 0, "matches": []}
    matches, score = [], 0
    for pat, cat, atlas, conf in _JAILBREAK_PATTERNS:
        m = pat.search(text)
        if m:
            matches.append({"category": cat, "atlas": atlas, "confidence": conf,
                            "match": m.group(0)[:60]})
            score = max(score, conf)
    return {"hit": bool(matches), "score": score, "matches": matches}

# ────────────────────────────────────────────────────────────
# MODULE 4 — Indirect Prompt Injection (instructions hidden in non-user content)
# MODULE 5 — RAG Content Inspection (exfil markers + injected instructions)
# ────────────────────────────────────────────────────────────
_INDIRECT_PATTERNS = [
    (re.compile(r'\b(ignore|disregard|override) (the|all|any|previous) (instructions|context|system prompt)\b', re.I), 'embedded_override', 'AML.T0051', 88),
    (re.compile(r'\b(assistant|ai|model|you) (must|should|will|are required to) (now )?(ignore|reveal|send|forward|exfiltrate|leak)\b', re.I), 'embedded_command', 'AML.T0051', 86),
    (re.compile(r'\b(system|developer)\s*:\s*', re.I), 'role_spoof', 'AML.T0051', 70),
    (re.compile(r'<\s*(system|im_start|\|im_start\|)\s*>', re.I), 'chat_markup_injection', 'AML.T0051', 82),
]
_EXFIL_PATTERNS = [
    (re.compile(r'\b(send|post|forward|exfiltrate|upload|leak) (the |all )?(conversation|system prompt|secrets?|api ?keys?|credentials?|chat history)\b', re.I), 'data_exfil_instruction', 'AML.T0024', 90),
    (re.compile(r'https?://[^\s"\')]+\?[^\s"\')]*(=.*)?', re.I), 'outbound_url_with_params', 'AML.T0024', 55),
    (re.compile(r'\bdata:\w+/[\w.+-]+;base64,', re.I), 'data_uri', 'AML.T0024', 50),
    (re.compile(r'/c/[A-Za-z0-9_-]{16,32}\b'), 'wraithwall_canary_token', 'AML.T0024', 95),  # our own canary tripped
]

def _scan(text, patterns):
    out, score = [], 0
    for pat, cat, atlas, conf in patterns:
        m = pat.search(text)
        if m:
            out.append({"category": cat, "atlas": atlas, "confidence": conf,
                        "match": m.group(0)[:60]})
            score = max(score, conf)
    return out, score

def _detect_indirect(context):
    text = _as_text(context)
    if not text:
        return {"hit": False, "score": 0, "matches": []}
    matches, score = _scan(text, _INDIRECT_PATTERNS)
    return {"hit": bool(matches), "score": score, "matches": matches}

def _detect_rag(rag_chunks):
    if not rag_chunks:
        return {"hit": False, "score": 0, "matches": [], "chunks_scanned": 0}
    if isinstance(rag_chunks, str):
        rag_chunks = [rag_chunks]
    all_matches, score, scanned = [], 0, 0
    for i, chunk in enumerate(rag_chunks[:50]):
        text = _as_text(chunk, 20_000)
        scanned += 1
        inj, s1 = _scan(text, _INDIRECT_PATTERNS)
        exf, s2 = _scan(text, _EXFIL_PATTERNS)
        for m in (inj + exf):
            m = dict(m); m["chunk_index"] = i
            all_matches.append(m)
        score = max(score, s1, s2)
    return {"hit": bool(all_matches), "score": score,
            "matches": all_matches[:30], "chunks_scanned": scanned}

# ────────────────────────────────────────────────────────────
# MODULE 6 — Tool Abuse Detection (dangerous agent tool calls)
# ────────────────────────────────────────────────────────────
_PRIVATE_HOST_RE = re.compile(
    r'(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.\d+\.\d+|metadata\.google|169\.254\.169\.254'
    r'|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|::1|\.internal\b)', re.I)
_TOOL_ARG_PATTERNS = [
    (re.compile(r'\brm\s+-rf\b|\bmkfs\b|\bdd\s+if=', re.I), 'destructive_shell', 'AML.T0050', 92),
    (re.compile(r'\bdrop\s+table\b|\btruncate\s+table\b|;\s*delete\s+from\b', re.I), 'destructive_sql', 'AML.T0050', 88),
    (re.compile(r'\.\./|\.\.\\|/etc/passwd|/etc/shadow|\bfile://', re.I), 'path_traversal_lfi', 'AML.T0050', 84),
    (re.compile(r'\b(curl|wget|fetch|requests?\.(get|post))\b', re.I), 'outbound_fetch', 'AML.T0024', 45),
    (re.compile(r'\$\(|\bsubprocess\b|\bos\.system\b|\beval\(|\bexec\(', re.I), 'code_exec', 'AML.T0050', 80),
]

def _detect_tool_abuse(tool_calls):
    if not tool_calls:
        return {"hit": False, "score": 0, "matches": []}
    if isinstance(tool_calls, dict):
        tool_calls = [tool_calls]
    matches, score = [], 0
    for i, call in enumerate(tool_calls[:50]):
        try:
            name = (call.get('name') if isinstance(call, dict) else '') or ''
            args = call.get('arguments') if isinstance(call, dict) else call
        except Exception:
            name, args = '', call
        blob = _as_text(args, 10_000)
        # SSRF: any URL-ish arg pointing at an internal/loopback/link-local host
        if _PRIVATE_HOST_RE.search(blob):
            matches.append({"tool": name, "category": "ssrf_internal_target",
                            "atlas": "AML.T0024", "confidence": 88,
                            "match": _PRIVATE_HOST_RE.search(blob).group(0)[:60]})
            score = max(score, 88)
        found, s = _scan(blob, _TOOL_ARG_PATTERNS)
        for m in found:
            m = dict(m); m["tool"] = name; m["call_index"] = i
            matches.append(m)
        score = max(score, s)
    return {"hit": bool(matches), "score": score, "matches": matches[:30]}

# ────────────────────────────────────────────────────────────
# MODULE 7 — Risk Scoring Engine
# ────────────────────────────────────────────────────────────
# Weighted ceiling: indirect/RAG/tool findings are weighted slightly higher than
# a direct user prompt because they're harder to spot and more likely malicious.
_DETECTOR_WEIGHTS = {
    "injection": 1.0,
    "jailbreak": 1.0,
    "indirect":  1.05,
    "rag":       1.05,
    "tool_abuse":1.1,
}

def _score(detectors):
    """Aggregate per-detector scores into 0..100 + threat level. Uses a weighted
    max (the single worst signal dominates) plus a small bump when multiple
    independent detectors fire, since corroboration raises confidence."""
    weighted = []
    fired = 0
    for name, det in detectors.items():
        s = int(det.get("score") or 0)
        if s > 0:
            fired += 1
            weighted.append(min(100, s * _DETECTOR_WEIGHTS.get(name, 1.0)))
    if not weighted:
        return 0, "none"
    base = max(weighted)
    corroboration = min(10, (fired - 1) * 4) if fired > 1 else 0
    score = int(min(100, base + corroboration))
    if score >= 90:
        level = "critical"
    elif score >= 80:
        level = "high"
    elif score >= 50:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "none"
    return score, level

def _primary_technique(detectors):
    best_conf, best = -1, None
    for det in detectors.values():
        for m in (det.get("techniques") or det.get("matches") or []):
            c = m.get("confidence", 0)
            if c > best_conf:
                best_conf, best = c, m.get("atlas") or m.get("primary")
        if det.get("primary") and det.get("score", 0) > best_conf:
            best_conf, best = det["score"], det["primary"]
    return best

# ────────────────────────────────────────────────────────────
# MODULE 8 — Policy Engine
# ────────────────────────────────────────────────────────────
def _get_policy(owner_user_id):

    pol = AIRSPolicy.query.filter_by(owner_user_id=owner_user_id).first()
    return pol

def _decide(risk_score, primary_technique, block_t, flag_t, mode, enabled, blocked_techs):
    """Pure policy decision (no DB) — returns (effective_verdict, summary).
    Kept side-effect-free so it is directly unit-testable."""
    if not enabled:
        return "allow", {"mode": mode, "enabled": False, "reason": "policy disabled"}
    verdict, reason = "allow", "below thresholds"
    if primary_technique and primary_technique in (blocked_techs or []):
        verdict, reason = "block", f"technique {primary_technique} on blocklist"
    elif risk_score >= block_t:
        verdict, reason = "block", f"risk {risk_score} >= block threshold {block_t}"
    elif risk_score >= flag_t:
        verdict, reason = "flag", f"risk {risk_score} >= flag threshold {flag_t}"
    # monitor mode never blocks — it downgrades block→flag so customers can
    # observe what *would* be blocked before enforcing.
    effective = "flag" if (mode == 'monitor' and verdict == 'block') else verdict
    return effective, {"mode": mode, "enabled": enabled, "verdict_raw": verdict,
                       "block_threshold": block_t, "flag_threshold": flag_t, "reason": reason}

def _evaluate_policy(owner_user_id, risk_score, threat_level, primary_technique):
    """Fetch the owner's policy (defaults when absent) and apply _decide()."""
    pol = _get_policy(owner_user_id)
    blocked_techs = []
    if pol and pol.blocked_techniques:
        try:
            blocked_techs = json.loads(pol.blocked_techniques)
        except Exception:
            blocked_techs = []
    return _decide(
        risk_score, primary_technique,
        pol.block_threshold if pol else 80,
        pol.flag_threshold if pol else 50,
        pol.mode if pol else 'enforce',
        pol.enabled if pol else True,
        blocked_techs,
    )

# ────────────────────────────────────────────────────────────
# MODULE 9 — Threat Intelligence Engine (actor tracking + optional enrichment)
# ────────────────────────────────────────────────────────────
def _track_actor(owner_user_id, client_ip, risk_score):
    """Increment repeat-offender counters for an end-user fingerprint. Cheap,
    DB-only; external IP enrichment is done separately on the /analyze path."""
    if not client_ip:
        return None

    fp = _sha(f"{owner_user_id}:{client_ip}")[:64]
    try:
        actor = AIRSActor.query.filter_by(owner_user_id=owner_user_id, fingerprint=fp).first()
        if not actor:
            actor = AIRSActor(owner_user_id=owner_user_id, fingerprint=fp, client_ip=client_ip)
            db.session.add(actor)
        actor.detections = (actor.detections or 0) + 1
        actor.max_risk = max(actor.max_risk or 0, risk_score)
        actor.last_seen = _now()
        db.session.commit()
        return {"fingerprint": fp, "detections": actor.detections,
                "max_risk": actor.max_risk, "blocked": actor.blocked}
    except Exception as e:
        logger.error(f"airs actor track error: {e}")
        db_rollback()
        return None

def _enrich_ip(ip):
    """Deep-path only: reuse the existing IP enrichment engine. Best-effort and
    guarded — never blocks or raises into the request path."""
    if not ip:
        return None
    try:
        from asn_intelligence import get_service
        svc = get_service()
        intel = svc.enrich(ip) if svc else None
        if intel is None:
            return None
        # IPIntelligence may be a dataclass — coerce to a small dict
        for attr in ('to_dict', '_asdict'):
            if hasattr(intel, attr):
                return getattr(intel, attr)()
        return {k: getattr(intel, k) for k in
                ('asn', 'asn_name', 'country', 'is_hosting', 'is_vpn', 'is_tor',
                 'abuse_score', 'risk_score', 'risk_level') if hasattr(intel, k)}
    except Exception as e:
        logger.error(f"airs enrich error: {e}")
        return None

# ────────────────────────────────────────────────────────────
# MODULE 12 — Alerting Pipeline
# ────────────────────────────────────────────────────────────
def _fire_alert(owner_email, endpoint, verdict, risk_score, threat_level,
                primary_technique, source_ip, client_ip):
    """Telegram + Discord on high/critical, deduped per owner+technique."""
    r = _redis()
    if r:
        try:
            dk = f"airs:alert:{owner_email}:{primary_technique or threat_level}"
            if not r.set(dk, "1", nx=True, ex=DEDUP_TTL):
                return  # collapsed within the window
        except Exception:
            pass
    msg = (f"🛡️ <b>AI firewall: {verdict.upper()}</b> ({threat_level})\n"
           f"Risk: <code>{risk_score}</code> · {endpoint}\n"
           f"Technique: <code>{primary_technique or 'n/a'}</code>\n"
           f"Owner: <code>{owner_email}</code>\n"
           f"Caller: <code>{source_ip}</code>" + (f" · client <code>{client_ip}</code>" if client_ip else ""))
    try:

        send_telegram_alert_bg(msg)
    except Exception as e:
        logger.error(f"airs telegram alert error: {e}")
    try:
        url = os.getenv('DISCORD_WEBHOOK_URL')
        if url:
            import requests
            txt = re.sub(r'<[^>]+>', '', msg)
            thread_utils.spawn_request_thread(lambda: _safe_post(url, {"content": txt, "allowed_mentions": {"parse": []}}))
    except Exception as e:
        logger.error(f"airs discord alert error: {e}")

def _safe_post(url, payload):
    try:
        import requests
        requests.post(url, json=payload, timeout=8)
    except Exception as e:
        logger.error(f"AIRS safe_post failed: {e}")

# ────────────────────────────────────────────────────────────
# MODULE 10 — Audit Logging
# ────────────────────────────────────────────────────────────
def _record_detection(ctx, endpoint, raw_input, result, source_ip, client_ip,
                      intel=None, store_preview=STORE_PREVIEW_DEFAULT):
    """Persist an AIRSDetection row + tamper-evident immutable log for high risk.
    By default we store only a SHA-256 of the input, never the raw prompt."""

    det_id = None
    try:
        row = AIRSDetection(
            owner_user_id=ctx['user_id'], api_key_id=ctx.get('api_key_id'),
            endpoint=endpoint, input_hash=_sha(raw_input),
            input_preview=(raw_input[:280] if store_preview and raw_input else None),
            verdict=result['verdict'], risk_score=result['risk_score'],
            threat_level=result['threat_level'], primary_technique=result.get('primary_technique'),
            techniques=json.dumps(result.get('techniques') or [])[:8000],
            detectors=json.dumps(result.get('detectors') or {})[:16000],
            source_ip=source_ip, client_ip=client_ip,
            intel=json.dumps(intel)[:4000] if intel else None,
        )
        db.session.add(row)
        db.session.commit()
        det_id = row.id
    except Exception as e:
        logger.error(f"airs record error: {e}")
        db_rollback()

    if result['threat_level'] in ('high', 'critical'):
        try:
            write_immutable_log({
                "event": "airs_detection",
                "endpoint": endpoint, "verdict": result['verdict'],
                "risk_score": result['risk_score'], "threat_level": result['threat_level'],
                "primary_technique": result.get('primary_technique'),
                "owner_user_id": ctx['user_id'], "input_hash": _sha(raw_input),
                "source_ip": source_ip, "ts": _now().isoformat(),
            })
        except Exception as e:
            logger.error(f"airs immutable log error: {e}")

        try:
            owner = User.query.get(ctx['user_id'])
            _fire_alert(owner.email if owner else str(ctx['user_id']), endpoint,
                        result['verdict'], result['risk_score'], result['threat_level'],
                        result.get('primary_technique'), source_ip, client_ip)
        except Exception as e:
            logger.error(f"airs alert dispatch error: {e}")
    return det_id

# ────────────────────────────────────────────────────────────
# MODULE 1 — Prompt Inspection Engine (orchestrator)
# ────────────────────────────────────────────────────────────
def _run_detectors(payload):
    """Run every detector over the supplied surfaces and return the combined
    result dict (without persistence)."""
    user_input = _as_text(payload.get('input'))
    context = payload.get('context')
    rag = payload.get('rag_chunks')
    tools = payload.get('tool_calls')

    detectors = {
        "injection":  _detect_injection(user_input),
        "jailbreak":  _detect_jailbreak(user_input),
        "indirect":   _detect_indirect(context),
        "rag":        _detect_rag(rag),
        "tool_abuse": _detect_tool_abuse(tools),
    }
    score, level = _score(detectors)
    primary = _primary_technique(detectors)
    # collect a flat technique list for convenience
    techs = []
    for det in detectors.values():
        for m in (det.get("techniques") or det.get("matches") or []):
            if m.get("atlas"):
                techs.append(m["atlas"])
    return {
        "detectors": detectors,
        "risk_score": score,
        "threat_level": level,
        "primary_technique": primary,
        "techniques": sorted(set(techs)),
    }

def _inspect_and_decide(ctx, endpoint, payload):
    """Full pipeline: detect → score → policy → audit → alert. Returns response dict."""
    raw_input = _as_text(payload.get('input'))
    source_ip = _client_ip()
    client_ip = (payload.get('client_ip') or '').strip()[:45] or None

    base = _run_detectors(payload)
    verdict, policy = _evaluate_policy(ctx['user_id'], base['risk_score'],
                                       base['threat_level'], base['primary_technique'])
    result = dict(base)
    result['verdict'] = verdict
    result['policy'] = policy

    actor = _track_actor(ctx['user_id'], client_ip, base['risk_score'])
    det_id = _record_detection(ctx, endpoint, raw_input, result, source_ip, client_ip)

    return {
        "ok": True,
        "verdict": verdict,
        "risk_score": base['risk_score'],
        "threat_level": base['threat_level'],
        "primary_technique": base['primary_technique'],
        "techniques": base['techniques'],
        "detectors": base['detectors'],
        "policy": policy,
        "actor": actor,
        "detection_id": det_id,
        "version": API_VERSION,
    }

# ════════════════════════════════════════════════════════════
# ROUTES — versioned /api/airs/v1
# ════════════════════════════════════════════════════════════
@ai_runtime_bp.route(f'/api/airs/{API_VERSION}/inspect', methods=['POST'])
def inspect():
    ctx, err = _auth_customer()
    if err:
        return err
    payload = request.get_json(silent=True) or {}
    if not any(payload.get(k) for k in ('input', 'context', 'rag_chunks', 'tool_calls')):
        return _err("Provide at least one of: input, context, rag_chunks, tool_calls", 400)
    try:
        return jsonify(_inspect_and_decide(ctx, 'inspect', payload))
    except Exception as e:
        logger.error(f"airs inspect error: {e}")
        return _err("Inspection failed", 500)

@ai_runtime_bp.route(f'/api/airs/{API_VERSION}/analyze', methods=['POST'])
def analyze():
    """Deep analysis: full inspection + (optional) IP enrichment of client_ip.
    The enrichment is best-effort and isolated to this slower endpoint."""
    ctx, err = _auth_customer()
    if err:
        return err
    payload = request.get_json(silent=True) or {}
    if not any(payload.get(k) for k in ('input', 'context', 'rag_chunks', 'tool_calls')):
        return _err("Provide at least one of: input, context, rag_chunks, tool_calls", 400)
    try:
        resp = _inspect_and_decide(ctx, 'analyze', payload)
        client_ip = (payload.get('client_ip') or '').strip()
        if client_ip:
            resp['intel'] = _enrich_ip(client_ip)
        return jsonify(resp)
    except Exception as e:
        logger.error(f"airs analyze error: {e}")
        return _err("Analysis failed", 500)

@ai_runtime_bp.route(f'/api/airs/{API_VERSION}/score', methods=['POST'])
def score():
    """Stateless scoring: run detectors + risk score, no policy/persistence."""
    ctx, err = _auth_customer()
    if err:
        return err
    payload = request.get_json(silent=True) or {}
    try:
        base = _run_detectors(payload)
        base.update({"ok": True, "version": API_VERSION})
        return jsonify(base)
    except Exception as e:
        logger.error(f"airs score error: {e}")
        return _err("Scoring failed", 500)

@ai_runtime_bp.route(f'/api/airs/{API_VERSION}/policy/evaluate', methods=['POST'])
def policy_evaluate():
    """Evaluate a (possibly pre-computed) risk against the owner's policy."""
    ctx, err = _auth_customer()
    if err:
        return err
    payload = request.get_json(silent=True) or {}
    try:
        if any(payload.get(k) for k in ('input', 'context', 'rag_chunks', 'tool_calls')):
            base = _run_detectors(payload)
            risk, level, primary = base['risk_score'], base['threat_level'], base['primary_technique']
        else:
            risk = int(payload.get('risk_score') or 0)
            level = payload.get('threat_level') or ('high' if risk >= 80 else 'medium' if risk >= 50 else 'low' if risk else 'none')
            primary = payload.get('primary_technique')
        verdict, policy = _evaluate_policy(ctx['user_id'], risk, level, primary)
        return jsonify({"ok": True, "verdict": verdict, "risk_score": risk,
                        "threat_level": level, "policy": policy, "version": API_VERSION})
    except Exception as e:
        logger.error(f"airs policy eval error: {e}")
        return _err("Policy evaluation failed", 500)

# ── Dashboard / management (session auth) ───────────────────────────────────
@ai_runtime_bp.route(f'/api/airs/{API_VERSION}/detections', methods=['GET'])
def detections():
    user, err = _auth_session()
    if err:
        return err

    try:
        q = AIRSDetection.query.filter_by(owner_user_id=user.id)
        verdict = request.args.get('verdict')
        if verdict in ('allow', 'flag', 'block'):
            q = q.filter_by(verdict=verdict)
        rows = q.order_by(AIRSDetection.created_at.desc()).limit(200).all()
        return jsonify({"ok": True, "detections": [{
            "id": r.id, "endpoint": r.endpoint, "verdict": r.verdict,
            "risk_score": r.risk_score, "threat_level": r.threat_level,
            "primary_technique": r.primary_technique,
            "techniques": json.loads(r.techniques) if r.techniques else [],
            "source_ip": r.source_ip, "client_ip": r.client_ip,
            "input_preview": r.input_preview,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        } for r in rows], "total": len(rows)})
    except Exception as e:
        logger.error(f"airs detections error: {e}")
        return _err("Could not load detections", 500)

@ai_runtime_bp.route(f'/api/airs/{API_VERSION}/dashboard/stats', methods=['GET'])
def dashboard_stats():
    user, err = _auth_session()
    if err:
        return err

    try:
        since = _now() - timedelta(days=7)
        base = AIRSDetection.query.filter_by(owner_user_id=user.id)
        total = base.count()
        recent = base.filter(AIRSDetection.created_at >= since).all()
        by_verdict = {"allow": 0, "flag": 0, "block": 0}
        by_level = {"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        tech_counts = {}
        for r in recent:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
            by_level[r.threat_level] = by_level.get(r.threat_level, 0) + 1
            if r.primary_technique:
                tech_counts[r.primary_technique] = tech_counts.get(r.primary_technique, 0) + 1
        top_tech = sorted(tech_counts.items(), key=lambda kv: kv[1], reverse=True)[:8]
        actors = AIRSActor.query.filter_by(owner_user_id=user.id).count()
        return jsonify({"ok": True, "total_detections": total,
                        "last_7d": len(recent), "by_verdict": by_verdict,
                        "by_threat_level": by_level,
                        "top_techniques": [{"technique": t, "count": c} for t, c in top_tech],
                        "tracked_actors": actors})
    except Exception as e:
        logger.error(f"airs stats error: {e}")
        return _err("Could not load stats", 500)

@ai_runtime_bp.route(f'/api/airs/{API_VERSION}/policy', methods=['GET', 'POST'])
def policy():
    user, err = _auth_session()
    if err:
        return err

    if request.method == 'GET':
        pol = _get_policy(user.id)
        return jsonify({"ok": True, "policy": {
            "mode": pol.mode if pol else 'enforce',
            "block_threshold": pol.block_threshold if pol else 80,
            "flag_threshold": pol.flag_threshold if pol else 50,
            "blocked_techniques": (json.loads(pol.blocked_techniques) if (pol and pol.blocked_techniques) else []),
            "enabled": pol.enabled if pol else True,
        }})
    data = request.get_json(silent=True) or {}
    try:
        pol = _get_policy(user.id)
        if not pol:
            pol = AIRSPolicy(owner_user_id=user.id)
            db.session.add(pol)
        if 'mode' in data and data['mode'] in ('enforce', 'monitor'):
            pol.mode = data['mode']
        if 'block_threshold' in data:
            pol.block_threshold = max(0, min(100, int(data['block_threshold'])))
        if 'flag_threshold' in data:
            pol.flag_threshold = max(0, min(100, int(data['flag_threshold'])))
        if 'enabled' in data:
            pol.enabled = bool(data['enabled'])
        if 'blocked_techniques' in data and isinstance(data['blocked_techniques'], list):
            pol.blocked_techniques = json.dumps([str(t)[:48] for t in data['blocked_techniques'][:50]])
        db.session.commit()
        return jsonify({"ok": True, "message": "Policy saved"})
    except Exception as e:
        logger.error(f"airs policy save error: {e}")
        db_rollback()
        return _err("Could not save policy", 400)

@ai_runtime_bp.route(f'/api/airs/{API_VERSION}/health', methods=['GET'])
def health():
    """Unauthenticated liveness check for the platform."""
    return jsonify({"ok": True, "service": "ai-runtime-security",
                    "version": API_VERSION, "detectors":
                    ["injection", "jailbreak", "indirect", "rag", "tool_abuse"]})

# ── Dashboard page (session-gated server-rendered shell) ─────────────────────
@ai_runtime_bp.route('/ai-security')
def dashboard_page():

    if not is_logged_in():
        from flask import redirect
        return redirect('/login?next=/ai-security')
    return render_template('airs-dashboard.html')

def register_airs_routes(app):
    """Optional functional registration (mirrors dml_engine pattern). main.py
    uses app.register_blueprint(ai_runtime_bp) directly; this is provided for
    parity / testing."""
    app.register_blueprint(ai_runtime_bp)
