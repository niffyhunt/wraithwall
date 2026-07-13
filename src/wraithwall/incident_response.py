import os
import time
import logging
from collections import defaultdict
from flask import Blueprint, request, jsonify, session
import requests as req

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

RESEND_API_KEY = os.environ.get("RESEND_API_KEY")  # kept for potential future use; not required
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@wraithwall.online")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "noreply@wraithwall.online")

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

RATE_LIMIT = 3
RATE_WINDOW = 3600  # seconds

incident_response_bp = Blueprint("incident_response", __name__)

class RedisRateLimiter:
    def __init__(self):
        import redis

        url = os.environ.get("REDIS_URL")
        if not url:
            raise RuntimeError("REDIS_URL not configured")
        self._client = redis.from_url(
            url,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        # verify connection
        self._client.ping()
        log.info("[IncidentResponse] Rate limiter: REDIS")

    def hit(self, user_email: str):
        key = "ir:" + user_email
        count = self._client.incr(key)
        if count == 1:
            self._client.expire(key, RATE_WINDOW)
        ttl = int(self._client.ttl(key) or RATE_WINDOW)
        return int(count), int(ttl)

    def decr(self, user_email: str):
        key = "ir:" + user_email
        current = int(self._client.get(key) or 0)
        if current > 0:
            try:
                self._client.decr(key)
            except Exception:
                # best-effort
                pass

class MemoryRateLimiter:
    def __init__(self):
        self._hits = defaultdict(list)
        log.warning("[IncidentResponse] Rate limiter: IN-MEMORY FALLBACK")

    def hit(self, user_email: str):
        now = time.time()
        valid = [t for t in self._hits[user_email] if now - t < RATE_WINDOW]
        valid.append(now)
        self._hits[user_email] = valid
        count = len(valid)
        if valid:
            ttl = int(RATE_WINDOW - (now - valid[0]))
            if ttl < 0:
                ttl = 0
        else:
            ttl = RATE_WINDOW
        return count, ttl

    def decr(self, user_email: str):
        if self._hits[user_email]:
            self._hits[user_email].pop()

def _build_limiter():
    try:
        return RedisRateLimiter()
    except Exception as e:
        log.warning("[IncidentResponse] Redis unavailable (%s), using fallback", e)
        return MemoryRateLimiter()

_limiter = _build_limiter()

@incident_response_bp.route("/api/initiate-response", methods=["POST"])
def initiate_response():
    user_email = session.get("user_email")
    if not user_email:
        return jsonify({"error": "Unauthorized"}), 401

    # Note: Telegram (primary) + Discord (fallback) are used for notifications.
    # RESEND is no longer required for this flow.

    try:
        count, ttl = _limiter.hit(user_email)
    except Exception as e:
        log.exception("[IncidentResponse] Rate limiter error: %s", e)
        return jsonify({"error": "Internal rate limiter error"}), 500

    if count > RATE_LIMIT:
        mins = ttl // 60
        secs = ttl % 60
        return (
            jsonify(
                {
                    "error": "Rate limit reached",
                    "message": f"Max {RATE_LIMIT} alerts per hour. Resets in {mins}m {secs}s.",
                }
            ),
            429,
        )

    remaining = max(RATE_LIMIT - count, 0)

    data = request.get_json(silent=True) or {}
    # Structured "what they are requesting" (preferred over free note)
    request_type = (data.get("request_type") or data.get("type") or "").strip()[:120]
    description = (data.get("description") or data.get("note") or "").strip()[:1500]
    urgency = (data.get("urgency") or "normal").lower()
    context = data.get("context") or {}
    ip_addr = request.headers.get("X-Forwarded-For", request.remote_addr) or request.remote_addr
    limiter_type = "Redis" if isinstance(_limiter, RedisRateLimiter) else "In-Memory (fallback)"
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())

    # Build a warm, friendly message for the admin (clicker only sees the generic success toast)
    # "Let them fill what they're requesting for" before we notify
    req_line = request_type or "General response / escalation"
    desc_line = description or "<i>(no additional details provided)</i>"
    urgency_badge = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH", "normal": "🟡 NORMAL", "low": "🟢 LOW"}.get(urgency, "🟡 NORMAL")

    context_bits = []
    if context.get("ip"): context_bits.append(f"IP: <code>{context['ip']}</code>")
    if context.get("session_id"): context_bits.append(f"Session: <code>{str(context['session_id'])[:24]}</code>")
    if context.get("campaign_id"): context_bits.append(f"Campaign: <code>{context['campaign_id']}</code>")
    if context.get("target"): context_bits.append(f"Target: {context['target']}")
    ctx_str = " | ".join(context_bits) if context_bits else "<i>none</i>"

    warm_msg = (
        "👋 <b>Hey there!</b>\n\n"
        "Someone just used <b>Initiate Response</b> in the WraithWall console and filled out a request.\n\n"
        f"<b>Request:</b> {req_line}\n"
        f"<b>Urgency:</b> {urgency_badge}\n"
        f"<b>Details:</b>\n{desc_line}\n\n"
        f"<b>Context:</b> {ctx_str}\n\n"
        f"<b>Analyst:</b> <code>{user_email}</code>\n"
        f"<b>When (UTC):</b> {timestamp}\n"
        f"<b>Client IP:</b> <code>{ip_addr}</code>\n"
        f"<b>Alert #:</b> {count}  <i>({remaining} remaining this hour)</i>\n\n"
        "If this needs your eyes on it, you know the drill. Otherwise, hope your day is going smoothly!\n\n"
        "Stay sharp out there. ❤️\n\n"
        "— WraithWall Console"
    )

    sent = False
    try:
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            tg_resp = req.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": warm_msg,
                    "parse_mode": "HTML"
                },
                timeout=10,
            )
            if tg_resp.status_code in (200, 201):
                sent = True
                log.info("[IncidentResponse] Telegram alert sent - user=%s count=%s", user_email, count)
            else:
                log.warning("[IncidentResponse] Telegram non-OK: %s %s", tg_resp.status_code, tg_resp.text[:200])
    except req.exceptions.Timeout:
        try:
            _limiter.decr(user_email)
        except Exception:
            pass
        return jsonify({"error": "Notification service timed out"}), 504
    except req.exceptions.RequestException as e:
        try:
            _limiter.decr(user_email)
        except Exception:
            pass
        return jsonify({"error": "Notification service unreachable: " + str(e)}), 502

    # Discord fallback / parallel (plain text version)
    try:
        discord_url = os.environ.get("DISCORD_WEBHOOK_URL", "")
        if discord_url and not sent:
            plain = (
                "👋 Hey there!\n\n"
                "Someone just used 'Initiate Response' and filled a request.\n\n"
                f"Request: {request_type or 'General response/escalation'}\n"
                f"Urgency: {urgency}\n"
                f"Details: {description or '(no details)'}\n"
                f"Context: {ctx_str.replace('<code>','').replace('</code>','').replace('<i>','').replace('</i>','')}\n\n"
                f"Analyst: {user_email}\nWhen (UTC): {timestamp}\nClient IP: {ip_addr}\n"
                f"Alert #: {count} ({remaining} remaining)\n\n"
                "If this needs your eyes on it, you know the drill.\n\n"
                "Stay sharp out there. ❤️\n\n"
                "— WraithWall Console"
            )
            d_resp = req.post(discord_url, json={"content": plain[:1900]}, timeout=10)
            if d_resp.status_code in (200, 204):
                sent = True
                log.info("[IncidentResponse] Discord alert sent - user=%s count=%s", user_email, count)
    except Exception as e:
        log.warning("[IncidentResponse] Discord send failed: %s", e)

    if sent:
        return (
            jsonify(
                {
                    "success": True,
                    "message": "Notification sent successfully.",
                    "remaining": remaining,
                    "alert_number": count,
                }
            ),
            200,
        )
    else:
        try:
            _limiter.decr(user_email)
        except Exception:
            pass
        return jsonify({"error": "Notification service not configured or failed"}), 502
