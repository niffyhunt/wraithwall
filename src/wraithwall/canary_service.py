"""
canary_service.py — WraithWall Canary Token Service (standalone product).

Multi-tenant: any signed-in user mints tracking tokens, wraps a secret-looking
artifact in a poisoned payload, and gets an instant email + Telegram alert the
moment the token is touched anywhere on the internet.

Public surface:
  GET  /canary                                  landing page (cream theme)
  GET  /canary/app                              dashboard (login required)
  GET  /c/<token>                               the trap (public, logs + alerts)
API (login required, owner-scoped, origin-gated POSTs under /api/...):
  POST /api/canary-service/create
  GET  /api/canary-service/tokens
  GET  /api/canary-service/tokens/<public_id>/hits
  POST /api/canary-service/tokens/<public_id>/deactivate

Security posture (see the audit in the launch task): owner-scoped IDOR checks,
no existence oracle on the trap, rate limits on creation + alerts, origin-gate
CSRF on POSTs, input validation incl. open-redirect/SSRF guard on redirect_to,
and we never store the user's real secret (credential/api_key payloads are fake).
"""
import os
import re
import json
import hmac
import base64
import hashlib
import secrets
import logging
import threading
import ipaddress
from datetime import datetime, timedelta
from wraithwall import thread_utils
from urllib.parse import urlparse

import requests
from flask import Blueprint, request, jsonify, session, render_template, redirect, Response, abort, current_app
from urllib.parse import quote
logger = logging.getLogger(__name__)

canary_service_bp = Blueprint('canary_service', __name__)

# 1x1 transparent GIF returned by the trap for beacon/unknown requests.
_PIXEL = base64.b64decode(
    'R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7'
)

VALID_TYPES = {'url', 'web_beacon', 'credential', 'text'}
TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{16,32}$')

PUBLIC_BASE = os.environ.get('CANARY_PUBLIC_BASE', 'https://wraithwall.online')

# Pricing / payment. All sensitive provider credentials come from env so
# nothing real is ever hardcoded in the repo; when no automated processor is
# configured, the UI shows a manual contact/address fallback instead of a fake
# checkout.
CANARY_PRICE        = os.environ.get('CANARY_PRICE', '$9')          # display only
CANARY_LN_ADDRESS   = os.environ.get('CANARY_LN_ADDRESS', '').strip()   # Lightning address, e.g. you@walletofsatoshi.com
CANARY_BTC_ADDRESS  = os.environ.get('CANARY_BTC_ADDRESS', '').strip()  # on-chain BTC, e.g. bc1q...
PAYMENT_CONTACT     = os.environ.get('CANARY_PAYMENT_CONTACT', 'contact@wraithwall.online').strip()

# Paystack — card/bank/mobile checkout + webhook/callback verification.
PAYSTACK_SECRET_KEY       = os.environ.get('PAYSTACK_SECRET_KEY', '').strip()
PAYSTACK_PUBLIC_KEY       = os.environ.get('PAYSTACK_PUBLIC_KEY', '').strip()
PAYSTACK_CURRENCY         = os.environ.get('PAYSTACK_CURRENCY', 'NGN').strip().upper()
PAYSTACK_AMOUNT_SUBUNITS  = os.environ.get('PAYSTACK_AMOUNT_SUBUNITS', '').strip()
PAYSTACK_CALLBACK_URL     = os.environ.get('PAYSTACK_CALLBACK_URL', '').strip()
PAYSTACK_API_BASE         = (os.environ.get('PAYSTACK_API_BASE') or 'https://api.paystack.co').rstrip('/')

# BTCPay Server (Greenfield API) — existing Bitcoin/Lightning invoice support.
BTCPAY_URL            = os.environ.get('BTCPAY_URL', '').rstrip('/')
BTCPAY_API_KEY        = os.environ.get('BTCPAY_API_KEY', '').strip()
BTCPAY_STORE_ID       = os.environ.get('BTCPAY_STORE_ID', '').strip()
BTCPAY_WEBHOOK_SECRET = os.environ.get('BTCPAY_WEBHOOK_SECRET', '').strip()
CANARY_PRICE_AMOUNT   = os.environ.get('CANARY_PRICE_AMOUNT', '9')          # numeric, for BTCPay invoices
CANARY_PRICE_CURRENCY = os.environ.get('CANARY_PRICE_CURRENCY', 'USD')
SUB_PERIOD_DAYS       = int(os.environ.get('CANARY_SUB_PERIOD_DAYS', '30'))
TRIAL_DAYS            = int(os.environ.get('CANARY_TRIAL_DAYS', '60'))
TRIAL_GRACE_DAYS      = int(os.environ.get('CANARY_TRIAL_GRACE_DAYS', '3'))
TRIAL_MAX_BILLING_ATTEMPTS = int(os.environ.get('CANARY_TRIAL_MAX_BILLING_ATTEMPTS', '3'))
CANARY_AUTH_AMOUNT_SUBUNITS = os.environ.get('CANARY_AUTH_AMOUNT_SUBUNITS', '').strip()

CREATE_LIMIT_PER_HOUR = 30
SUBSCRIBE_LIMIT_PER_HOUR = 10

def _btcpay_enabled():
    return all((BTCPAY_URL, BTCPAY_API_KEY, BTCPAY_STORE_ID, BTCPAY_WEBHOOK_SECRET))

def _paystack_enabled():
    return bool(PAYSTACK_SECRET_KEY)

def _billing_enabled():
    """True when an automated processor is configured. Paystack is preferred
    when present; otherwise the existing BTCPay flow remains available."""
    return _paystack_enabled() or _btcpay_enabled()

def _billing_processor():
    if _paystack_enabled():
        return 'paystack'
    if _btcpay_enabled():
        return 'btcpay'
    return 'manual'
ALERT_DEDUP_TTL = 300       # per-token alert collapse window
HIT_IP_THROTTLE_TTL = 60    # per-IP trap throttle window (seconds)
HIT_IP_THROTTLE_MAX = 20    # max trap requests per IP per window before we shed

# ────────────────────────────────────────────────────────────
# helpers
# ────────────────────────────────────────────────────────────
def _redis():
    try:

        return get_redis()
    except Exception:
        return None

def _client_ip():
    try:
        from gateway import _client_ip as gw_ip
        return gw_ip()
    except Exception:
        xff = request.headers.get('X-Forwarded-For', request.remote_addr or 'unknown')
        return xff.split(',')[0].strip()

def _current_user():
    """Return the logged-in User row, or None. Session-cookie based like the rest of the app."""
    uid = session.get('user_id')
    if not uid:
        return None
    try:

        return User.query.get(uid)
    except Exception:
        return None

def _json_error(msg, code):
    return jsonify({"ok": False, "error": msg}), code

def process_canary_payment(verified, data):
    def _extract_canary_metadata(payload: dict):
        meta = (payload.get("data", {}) or {}).get("metadata", {}) or {}
        return {
            "user_id": meta.get("user_id") or meta.get("userId"),
            "purpose": meta.get("purpose"),
        }

    uid = _resolve_user_id_for_paystack(verified) or _resolve_user_id_for_paystack(data)
    meta = _extract_canary_metadata(verified or data)

    if not uid:
        return

    if meta.get("purpose") != "canary_subscription":
        return

    sub = CanarySubscription.query.filter_by(
        owner_user_id=uid,
        status="pending"
    ).first()

    if not sub:
        return

    sub.status = "active"
    sub.activated_at = datetime.utcnow()
    db.session.commit()

def _safe_redirect_target(url):
    """Validate a user-supplied redirect URL. Returns cleaned URL or None.
    Blocks non-http(s) schemes (javascript:/data:) and internal/SSRF targets."""
    if not url or len(url) > 2048:
        return None
    try:
        p = urlparse(url.strip())
    except Exception:
        return None
    if p.scheme not in ('http', 'https') or not p.hostname:
        return None
    host = p.hostname.lower()
    if host in ('localhost',) or host.endswith('.localhost') or host.endswith('.internal'):
        return None
    # block raw-IP internal/loopback/link-local/private targets
    try:
        ip = ipaddress.ip_address(host)
        if (ip.is_private or ip.is_loopback or ip.is_link_local or
                ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return None
    except ValueError:
        pass  # hostname, not an IP — allowed
    return p.geturl()

def _clean_text(value, maxlen):
    if value is None:
        return None
    return str(value).strip()[:maxlen]

# ────────────────────────────────────────────────────────────
# access classification — distinguish "your token was SEEN by an automated
# link-preview / scanner" (it surfaced somewhere crawlable — shared in a chat,
# posted, mailed) from "someone OPENED it in a browser" (a human interaction).
# Messengers (WhatsApp/Telegram/Slack/Discord/iMessage…), social unfurlers, and
# email/EDR link-safety scanners all pre-fetch a URL, which trips the trap. That
# is signal, not noise — but a different kind of signal than a human click.
# ────────────────────────────────────────────────────────────
_PREVIEW_BOT_SIGNATURES = {
    'whatsapp': 'WhatsApp', 'telegrambot': 'Telegram', 'slackbot': 'Slack',
    'slack-imgproxy': 'Slack', 'discordbot': 'Discord',
    'facebookexternalhit': 'Facebook', 'facebot': 'Facebook',
    'twitterbot': 'Twitter/X', 'linkedinbot': 'LinkedIn', 'redditbot': 'Reddit',
    'pinterest': 'Pinterest', 'skypeuripreview': 'Skype', 'viber': 'Viber',
    'line/': 'LINE', 'applebot': 'Apple', 'googlebot': 'Google',
    'google-inspectiontool': 'Google', 'bingbot': 'Bing', 'yandexbot': 'Yandex',
    'duckduckbot': 'DuckDuckGo', 'embedly': 'Embedly', 'vkshare': 'VK',
    'whatsapp/2': 'WhatsApp', 'safelinks': 'Microsoft SafeLinks',
    'proofpoint': 'Proofpoint scanner', 'barracuda': 'Barracuda scanner',
    'mimecast': 'Mimecast scanner', 'bitdefender': 'Bitdefender scanner',
}
# Generic automation markers: HTTP libraries, headless tooling, generic crawlers.
_GENERIC_BOT_MARKERS = (
    'bot', 'crawl', 'spider', 'preview', 'scan', 'fetch', 'http-client',
    'httpclient', 'python-requests', 'curl/', 'wget', 'go-http-client', 'libwww',
    'okhttp', 'headless', 'axios', 'java/', 'apache-httpclient', 'guzzle',
)
_BROWSER_MARKERS = ('mozilla', 'applewebkit', 'gecko', 'chrome', 'safari', 'firefox', 'edg')

def _classify_access(ua):
    """Classify a canary hit by User-Agent into an access *kind*:
      - ``automated``  : a link-preview crawler / unfurler / link-safety scanner
                         fetched the URL — your token was *seen* somewhere crawlable,
                         not necessarily opened by a person.
      - ``interactive``: looks like a real browser — someone actually *opened* it.
      - ``unknown``    : couldn't tell (missing or unrecognized UA).
    Returns ``{'kind', 'bot', 'label'}``. Specific bots are checked before the
    generic markers, and both before browser markers (many bots carry 'Mozilla').
    """
    s = (ua or '').lower().strip()
    if not s:
        return {'kind': 'unknown', 'bot': None,
                'label': 'No user-agent — automated client or stripped header'}
    for sig, name in _PREVIEW_BOT_SIGNATURES.items():
        if sig in s:
            return {'kind': 'automated', 'bot': name,
                    'label': f'Seen by an automated link preview ({name}) — your token surfaced somewhere, not necessarily opened by a person'}
    if any(m in s for m in _GENERIC_BOT_MARKERS):
        return {'kind': 'automated', 'bot': None,
                'label': 'Seen by an automated client (bot / scanner / HTTP library) — not necessarily opened by a person'}
    if any(m in s for m in _BROWSER_MARKERS):
        return {'kind': 'interactive', 'bot': None,
                'label': 'Opened in a browser — likely a human interaction'}
    return {'kind': 'unknown', 'bot': None, 'label': 'Unrecognized client'}

def _access_verb(enrichment):
    """Past-tense verb for alert headings, derived from the access classification."""
    kind = ((enrichment or {}).get('access') or {}).get('kind')
    return {'automated': 'was seen by an automated fetch',
            'interactive': 'was opened',
            'unknown': 'was accessed'}.get(kind, 'was accessed')

# ────────────────────────────────────────────────────────────
# alerting (fire-and-forget so the trap stays fast)
# ────────────────────────────────────────────────────────────
def _email_enrichment_rows(enrichment):
    """Render the attacker dossier as table rows for the alert email."""
    if not enrichment:
        return ""
    rows = []
    acc = enrichment.get('access')
    if acc:
        rows.append(("Access type", acc.get('label')))
    asn = enrichment.get('asn')
    if asn:
        flags = [k.replace('is_', '').upper() for k in ('is_hosting', 'is_vpn', 'is_tor', 'is_proxy') if asn.get(k)]
        bits = [b for b in [asn.get('asn'), asn.get('org'), asn.get('country')] if b]
        profile = " · ".join(bits) or "—"
        if asn.get('abuse_score'):
            profile += f" · abuse {asn['abuse_score']}"
        if flags:
            profile += f" · {'/'.join(flags)}"
        rows.append(("Attacker profile", profile))
    hp = enrichment.get('honeypot')
    if hp and hp.get('seen_before'):
        rows.append(("Honeypot history",
                     f"Seen before — {hp.get('sessions')} session(s), max threat {hp.get('max_threat_score')}"))
    elif hp is not None:
        rows.append(("Honeypot history", "No prior contact"))
    camp = enrichment.get('campaign')
    if camp:
        rows.append(("Coordinated attack",
                     f"Part of campaign {camp.get('campaign_id')} "
                     f"({camp.get('threat_level')}, {camp.get('unique_ip_count')} IPs, "
                     f"{camp.get('sensor_count')} sensors)"))
    return "".join(
        f'<tr><td style="padding:6px 0;color:#6B6860;">{k}</td>'
        f'<td style="padding:6px 0;"><code>{v}</code></td></tr>'
        for k, v in rows
    )

def _send_owner_email(to_email, label, ip, ua, when, ttype, enrichment=None):
    if not os.getenv('RESEND_API_KEY') or not to_email:
        return
    try:
        import resend
        resend.api_key = os.getenv('RESEND_API_KEY')
        html = f"""
        <html><body style="font-family:Arial,sans-serif;color:#0F0F0E;background:#FAFAF8;padding:24px;">
          <div style="max-width:520px;margin:0 auto;background:#fff;padding:24px;border-radius:8px;border:1px solid rgba(15,15,14,.1);">
            <h2 style="margin-top:0;color:#C41A1A;">🐦 Canary triggered</h2>
            <p>Your canary token <strong>{label}</strong> ({ttype}) {_access_verb(enrichment)}.</p>
            <table style="width:100%;border-collapse:collapse;font-size:14px;">
              <tr><td style="padding:6px 0;color:#6B6860;">Source IP</td><td style="padding:6px 0;"><code>{ip}</code></td></tr>
              <tr><td style="padding:6px 0;color:#6B6860;">User agent</td><td style="padding:6px 0;"><code>{ua}</code></td></tr>
              <tr><td style="padding:6px 0;color:#6B6860;">Time (UTC)</td><td style="padding:6px 0;">{when}</td></tr>
              {_email_enrichment_rows(enrichment)}
            </table>
            <p style="margin-top:20px;"><a href="{PUBLIC_BASE}/canary/app"
              style="display:inline-block;padding:10px 20px;background:#C41A1A;color:#fff;text-decoration:none;border-radius:4px;">
              View in dashboard</a></p>
          </div></body></html>"""
        resend.Emails.send({
            "from": f"WraithWall Canary <{os.environ.get('FROM_EMAIL', 'noreply@wraithwall.online')}>",
            "to": [to_email],
            "subject": f"🐦 Canary triggered: {label}",
            "html": html,
        })
    except Exception as e:
        logger.error(f"canary email error: {e}")

def _enrich_attacker(ip):
    """Build an attacker dossier for a canary-trip source IP by cross-feeding the
    other engines. This is the differentiation from free token services: instead
    of just "your token was touched", the owner sees *who* touched it.

    Returns a dict with up to three sections (any may be absent on error/no-data):
      - ``asn``       : ASN / org / country / abuse profile (asn_intelligence)
      - ``honeypot``  : whether this IP has hit the SSH honeypot before (cowrie)
      - ``campaign``  : linkage to an active coordinated campaign (correlator)

    Runs off the request hot path (background thread) and never raises.
    """
    out = {}

    # 1. ASN / attacker profile via asn_intelligence
    try:
        from asn_intelligence import get_service
        intel = get_service().enrich_and_track(ip)
        if intel and not getattr(intel, 'private', False):
            risk = getattr(intel, 'risk_level', None)
            out['asn'] = {
                'asn': getattr(intel, 'asn', None),
                'org': getattr(intel, 'asn_name', None) or getattr(intel, 'org', None),
                'country': getattr(intel, 'country', None),
                'is_hosting': getattr(intel, 'is_hosting', False),
                'is_vpn': getattr(intel, 'is_vpn', False),
                'is_tor': getattr(intel, 'is_tor', False),
                'is_proxy': getattr(intel, 'is_proxy', False),
                'abuse_score': getattr(intel, 'abuse_score', 0),
                'rdns': getattr(intel, 'rdns', None),
                'risk_level': getattr(risk, 'value', None) if risk is not None else None,
            }
    except Exception as e:
        logger.debug(f"canary enrich (asn): {e}")

    # 2. Has this IP hit the SSH honeypot before? (bounded scan of recent sessions)
    try:
        out['honeypot'] = _check_cowrie_history(ip)
    except Exception as e:
        logger.debug(f"canary enrich (cowrie): {e}")

    # 3. Is this IP part of an active coordinated campaign?
    try:
        from campaign_correlator import get_correlator
        for c in (get_correlator().get_active_campaigns() or []):
            if ip in (c.get('unique_ips') or []):
                out['campaign'] = {
                    'campaign_id': c.get('campaign_id'),
                    'threat_level': c.get('threat_level'),
                    'session_count': c.get('session_count'),
                    'unique_ip_count': len(c.get('unique_ips', []) or []),
                    'sensor_count': len(c.get('sensors_hit', []) or []),
                }
                break
    except Exception as e:
        logger.debug(f"canary enrich (campaign): {e}")

    return out

def _check_cowrie_history(ip):
    """Check the recent Cowrie session buffer for prior contact from this IP."""
    r = _redis()
    if not r:
        return None
    seen, last_seen, max_score = 0, None, 0
    try:
        sids = r.lrange('cowrie_sessions:recent', 0, 199)
    except Exception:
        return None
    for sid in sids:
        raw = None
        try:
            raw = r.get(f"cowrie_completed:{sid}")
        except Exception:
            continue
        if not raw:
            continue
        try:
            s = json.loads(raw)
        except Exception:
            continue
        if s.get('src_ip') == ip:
            seen += 1
            last_seen = s.get('connected_at') or last_seen
            score = (s.get('intelligence') or {}).get('threat_score', 0) or 0
            max_score = max(max_score, score)
    if seen:
        return {'seen_before': True, 'sessions': seen,
                'last_seen': last_seen, 'max_threat_score': max_score}
    return {'seen_before': False}

def _enrichment_summary(enrichment):
    """One-line-per-signal HTML summary for alerts (empty string if nothing)."""
    if not enrichment:
        return ""
    lines = []
    acc = enrichment.get('access')
    if acc:
        icon = {'automated': '🔍', 'interactive': '🖱️', 'unknown': '❔'}.get(acc.get('kind'), '•')
        lines.append(f"{icon} <b>Access:</b> {acc.get('label')}")
    asn = enrichment.get('asn')
    if asn:
        flags = [k.replace('is_', '').upper() for k in ('is_hosting', 'is_vpn', 'is_tor', 'is_proxy') if asn.get(k)]
        bits = [b for b in [asn.get('asn'), asn.get('org'), asn.get('country')] if b]
        line = " · ".join(bits)
        if asn.get('abuse_score'):
            line += f" · abuse {asn['abuse_score']}"
        if flags:
            line += f" · {'/'.join(flags)}"
        if line:
            lines.append(f"<b>Profile:</b> {line}")
    hp = enrichment.get('honeypot')
    if hp and hp.get('seen_before'):
        lines.append(f"<b>Honeypot:</b> seen before — {hp.get('sessions')} session(s), "
                     f"max threat {hp.get('max_threat_score')}")
    elif hp is not None:
        lines.append("<b>Honeypot:</b> no prior contact")
    camp = enrichment.get('campaign')
    if camp:
        lines.append(f"<b>Campaign:</b> part of <code>{camp.get('campaign_id')}</code> "
                     f"({camp.get('threat_level')}, {camp.get('unique_ip_count')} IPs, "
                     f"{camp.get('sensor_count')} sensors)")
    return ("\n" + "\n".join(lines)) if lines else ""

def _fire_alerts(token_label, owner_email, ip, ua, ttype, enrichment=None):
    when = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    # Telegram → global operator channel (per-user TG needs user-supplied creds; roadmap)
    try:

        msg = (f"🐦 <b>Canary triggered</b>\n"
               f"Token: <code>{token_label}</code> ({ttype}) {_access_verb(enrichment)}\n"
               f"IP: <code>{ip}</code>\n"
               f"UA: <code>{(ua or '')[:120]}</code>\n"
               f"Owner: <code>{owner_email}</code>"
               f"{_enrichment_summary(enrichment)}")
        send_telegram_alert_bg(msg)
    except Exception as e:
        logger.error(f"canary telegram error: {e}")
    thread_utils.spawn_request_thread(_send_owner_email,
                     args=(owner_email, token_label, ip, ua, when, ttype, enrichment))

def _enrich_and_alert(hit_id, token_label, owner_email, ip, ua, ttype):
    """Off-hot-path: enrich the source IP, persist the dossier to the hit row
    (so the dashboard shows it), then fire the owner alerts. Never raises."""
    enrichment = {}
    try:
        enrichment = _enrich_attacker(ip)
    except Exception as e:
        logger.error(f"canary enrich error: {e}")

    # Always classify the access kind (automated preview/scanner vs human browser)
    # so every alert + dashboard row distinguishes "seen" from "opened". This also
    # guarantees enrichment is non-empty, so it's always persisted to the hit.
    try:
        enrichment['access'] = _classify_access(ua)
    except Exception as e:
        logger.debug(f"canary classify: {e}")

    if enrichment:
        try:

            with app.app_context():
                h = CanaryServiceHit.query.get(hit_id)
                if h:
                    existing = {}
                    if h.geo:
                        try:
                            existing = json.loads(h.geo)
                        except Exception:
                            existing = {}
                    existing['enrichment'] = enrichment
                    h.geo = json.dumps(existing)
                    db.session.commit()
        except Exception as e:
            logger.error(f"canary enrich persist error: {e}")

    _fire_alerts(token_label, owner_email, ip, ua, ttype, enrichment)

# ────────────────────────────────────────────────────────────
# payload builders
# ────────────────────────────────────────────────────────────
def _build_payload(token_type, public_id, redirect_to=None):
    beacon = f"{PUBLIC_BASE}/c/{public_id}"
    if token_type == 'url':
        return beacon
    if token_type == 'web_beacon':
        return f'<img src="{beacon}.gif" width="1" height="1" alt="" style="display:none">'
    if token_type == 'credential':
        # FAKE credential — we never store/echo the user's real secret
        fake_user = f"svc_{secrets.token_hex(4)}"
        fake_pass = secrets.token_urlsafe(18)
        return (f"# Decoy service credential — touching the endpoint trips the canary\n"
                f"WRAITHWALL_API_HOST={beacon}\n"
                f"WRAITHWALL_API_USER={fake_user}\n"
                f"WRAITHWALL_API_KEY={fake_pass}")
    # text
    return f"{beacon}"

# ────────────────────────────────────────────────────────────
# pages
# ────────────────────────────────────────────────────────────
@canary_service_bp.route('/canary')
def canary_landing():
    # Serve prerendered Vue SSG marketing page if built
    fp = os.path.join(current_app.root_path, 'static', 'marketing_dist', 'canary.html')
    if os.path.isfile(fp):
        return current_app.send_static_file('marketing_dist/canary.html')
    return render_template(
        'canary-landing.html',
        price=CANARY_PRICE,
        ln_address=CANARY_LN_ADDRESS,
        btc_address=CANARY_BTC_ADDRESS,
        payment_contact=PAYMENT_CONTACT,
        payment_configured=bool(CANARY_LN_ADDRESS or CANARY_BTC_ADDRESS),
        billing_enabled=_billing_enabled(),
        billing_processor=_billing_processor(),
        paystack_enabled=_paystack_enabled(),
        btcpay_enabled=_btcpay_enabled(),
    )

@canary_service_bp.route('/canary/app')
def canary_app():
    user = _current_user()
    if not user:
        next_path = request.args.get('next') or '/canary/app'
        if next_path not in ('/canary', '/canary/app'):
            next_path = '/canary/app'
        session['next'] = next_path
        return redirect(f'/login?next={quote(next_path, safe="/")}')
    return render_template('canary-app.html', user_email=user.email)

# ────────────────────────────────────────────────────────────
# API (login required, owner-scoped)
# ────────────────────────────────────────────────────────────
@canary_service_bp.route('/api/canary-service/create', methods=['POST'])
def create_token():
    try:
        user = _current_user()
        if not user:
            return _json_error("Authentication required", 401)

        # paywall: requires an active subscription or trial (admins exempt;
        # no-op when billing isn't configured). 402 lets the UI prompt to subscribe.
        if not _has_active_subscription(user):
            return _json_error("An active subscription is required to mint tokens.", 402)

        # rate limit creation
        r = _redis()
        if r:
            try:
                key = f"canary:rl:create:{user.id}"
                n = r.incr(key)
                if n == 1:
                    r.expire(key, 3600)
                if n > CREATE_LIMIT_PER_HOUR:
                    return _json_error("Rate limit exceeded — try again later.", 429)
            except Exception:
                pass

        data = request.get_json(silent=True) or {}
        ttype = data.get('type', 'url')
        if ttype not in VALID_TYPES:
            return _json_error("Invalid token type.", 400)

        label = _clean_text(data.get('label'), 120) or f"{ttype}-canary"
        memo = _clean_text(data.get('memo'), 500)

        redirect_to = None
        if ttype == 'url':
            redirect_to = _safe_redirect_target(data.get('redirect_to', ''))
            if data.get('redirect_to') and not redirect_to:
                return _json_error("redirect_to must be a public http(s) URL.", 400)

        public_id = secrets.token_urlsafe(16)[:22]
        tok = CanaryServiceToken(
            public_id=public_id, owner_user_id=user.id, token_type=ttype,
            label=label, redirect_to=redirect_to, memo=memo,
        )
        db.session.add(tok)
        db.session.commit()

        try:

            log_audit(user.email, 'canary_service_created', details=f"type={ttype}")
        except Exception:
            pass

        return jsonify({
            "ok": True,
            "token": {
                "public_id": public_id,
                "type": ttype,
                "label": label,
                "beacon_url": f"{PUBLIC_BASE}/c/{public_id}",
                "payload": _build_payload(ttype, public_id, redirect_to),
            }
        }), 201
    except Exception as e:
        logger.error(f"canary create error: {e}")
        return _json_error("Could not create token.", 500)

@canary_service_bp.route('/api/canary-service/tokens', methods=['GET'])
def list_tokens():
    try:
        user = _current_user()
        if not user:
            return _json_error("Authentication required", 401)

        toks = (CanaryServiceToken.query
                .filter_by(owner_user_id=user.id)
                .order_by(CanaryServiceToken.created_at.desc()).all())
        return jsonify({
            "ok": True,
            "tokens": [{
                "public_id": t.public_id,
                "type": t.token_type,
                "label": t.label,
                "beacon_url": f"{PUBLIC_BASE}/c/{t.public_id}",
                "payload": _build_payload(t.token_type, t.public_id, t.redirect_to),
                "is_active": t.is_active,
                "trigger_count": t.trigger_count,
                "last_triggered": t.last_triggered.isoformat() if t.last_triggered else None,
                "created_at": t.created_at.isoformat() if t.created_at else None,
            } for t in toks],
            "stats": {
                "total": len(toks),
                "active": sum(1 for t in toks if t.is_active),
                "triggered": sum(1 for t in toks if (t.trigger_count or 0) > 0),
            }
        })
    except Exception as e:
        logger.error(f"canary list error: {e}")
        return _json_error("Could not load tokens.", 500)

@canary_service_bp.route('/api/canary-service/tokens/<public_id>/hits', methods=['GET'])
def token_hits(public_id):
    try:
        user = _current_user()
        if not user:
            return _json_error("Authentication required", 401)

        tok = CanaryServiceToken.query.filter_by(public_id=public_id).first()
        # owner-scoped: mismatch returns identical 404 (no existence oracle)
        if not tok or tok.owner_user_id != user.id:
            return _json_error("Not found.", 404)
        hits = (CanaryServiceHit.query.filter_by(token_id=tok.id)
                .order_by(CanaryServiceHit.created_at.desc()).limit(100).all())
        return jsonify({
            "ok": True,
            "label": tok.label,
            "hits": [{
                "ip": h.source_ip,
                "user_agent": h.user_agent,
                "method": h.method,
                "referer": h.referer,
                "geo": json.loads(h.geo) if h.geo else None,
                "timestamp": h.created_at.isoformat() if h.created_at else None,
            } for h in hits],
            "total": len(hits),
        })
    except Exception as e:
        logger.error(f"canary hits error: {e}")
        return _json_error("Could not load hits.", 500)

@canary_service_bp.route('/api/canary-service/tokens/<public_id>/deactivate', methods=['POST'])
def deactivate_token(public_id):
    try:
        user = _current_user()
        if not user:
            return _json_error("Authentication required", 401)

        tok = CanaryServiceToken.query.filter_by(public_id=public_id).first()
        if not tok or tok.owner_user_id != user.id:
            return _json_error("Not found.", 404)
        tok.is_active = False
        db.session.commit()
        r = _redis()
        if r:
            try:
                r.delete(f"canary:token:{public_id}")
            except Exception:
                pass
        return jsonify({"ok": True, "message": "Token deactivated."})
    except Exception as e:
        logger.error(f"canary deactivate error: {e}")
        return _json_error("Could not deactivate token.", 500)

# ────────────────────────────────────────────────────────────
# billing — BTCPay invoice + auto-activation webhook
# ────────────────────────────────────────────────────────────
def _sub_payload(sub):
    now = datetime.utcnow()
    active = False
    trial_active = False
    days_remaining = None

    if sub:
        if sub.status == 'active' and sub.current_period_end and sub.current_period_end > now:
            active = True
        elif sub.status == 'trial' and sub.trial_end and sub.trial_end > now:
            trial_active = True
            days_remaining = (sub.trial_end - now).days
        elif sub.status == 'trial' and sub.trial_end and sub.trial_end <= now:
            if sub.grace_period_end and sub.grace_period_end > now:
                days_remaining = 0

    return {
        "status": sub.status if sub else "inactive",
        "current_period_end": sub.current_period_end.isoformat() if (sub and sub.current_period_end) else None,
        "active": active,
        "trial_active": trial_active,
        "trial_start": sub.trial_start.isoformat() if (sub and sub.trial_start) else None,
        "trial_end": sub.trial_end.isoformat() if (sub and sub.trial_end) else None,
        "days_remaining": days_remaining,
        "grace_period_end": sub.grace_period_end.isoformat() if (sub and sub.grace_period_end) else None,
        "cancelled": sub.cancelled if sub else False,
    }

def _has_active_subscription(user):
    """Boolean check: does this user have active access (paid or trial)? Used by the
    create_token paywall. Returns True when billing is off (dev mode) or for admins."""
    if not _billing_enabled():
        return True
    if user.role == 'admin':
        return True
    try:

        sub = CanarySubscription.query.filter_by(owner_user_id=user.id).first()
        if not sub:
            return False
        now = datetime.utcnow()
        if sub.status == 'active' and sub.current_period_end and sub.current_period_end > now:
            return True
        if sub.status == 'trial' and sub.trial_end and sub.trial_end > now:
            return True
        if sub.status == 'trial' and sub.trial_end and sub.trial_end <= now:
            if sub.grace_period_end and sub.grace_period_end > now:
                return True
    except Exception:
        pass
    return False

@canary_service_bp.route('/api/canary-service/subscription', methods=['GET'])
def subscription_route():
    user = _current_user()
    if not user:
        return _json_error("Authentication required", 401)
    sub = None
    if _billing_enabled():
        try:

            sub = CanarySubscription.query.filter_by(owner_user_id=user.id).first()
        except Exception:
            pass
    data = _sub_payload(sub)
    data["ok"] = True
    data["billing_enabled"] = _billing_enabled()
    data["billing_processor"] = _billing_processor()
    data["can_create"] = _has_active_subscription(user)
    data["price"] = CANARY_PRICE
    return jsonify(data)

def _paystack_amount_subunits():
    """Paystack requires the amount in the currency subunit (for example kobo
    for NGN). Prefer an explicit env var so currency/rounding stays operator
    controlled; otherwise derive from CANARY_PRICE_AMOUNT for simple setups."""
    if PAYSTACK_AMOUNT_SUBUNITS:
        return str(int(PAYSTACK_AMOUNT_SUBUNITS))
    return str(int(round(float(CANARY_PRICE_AMOUNT) * 100)))

def _paystack_callback_url():
    if PAYSTACK_CALLBACK_URL:
        return PAYSTACK_CALLBACK_URL
    return f"{PUBLIC_BASE}/canary/app?paid=1"

def _paystack_auth_amount_subunits():
    """Minimum reversible authorization amount (50 kobo = ~$0.0008 for NGN).
    This verifies the card is valid without charging meaningful money.
    Override via CANARY_AUTH_AMOUNT_SUBUNITS env var."""
    if CANARY_AUTH_AMOUNT_SUBUNITS:
        return str(int(CANARY_AUTH_AMOUNT_SUBUNITS))
    return "50"  # 50 kobo = ~$0.0008, the smallest Paystack subunit for NGN

def _refund_paystack_transaction(reference):
    """Full refund of a Paystack transaction. Returns True on success."""
    try:
        resp = requests.post(
            f"{PAYSTACK_API_BASE}/refund",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                     "Content-Type": "application/json"},
            json={"transaction": reference},
            timeout=15,
        )
        if resp.status_code == 200:
            body = resp.json()
            if body.get("status"):
                logger.info(f"paystack refund issued for {reference}")
                return True
        logger.warning(f"paystack refund failed for {reference}: {resp.status_code} {resp.text[:200]}")
    except Exception as e:
        logger.error(f"paystack refund error for {reference}: {e}")
    return False

def _activate_subscription(sub, processor, paid_reference):
    """Grant one subscription period idempotently for a paid provider reference."""

    if sub.active_invoice_id == paid_reference and sub.status == 'active':
        return False

    base = sub.current_period_end if (sub.current_period_end and
                                      sub.current_period_end > datetime.utcnow()) else datetime.utcnow()
    sub.current_period_end = base + timedelta(days=SUB_PERIOD_DAYS)
    sub.status = 'active'
    sub.processor = processor
    sub.active_invoice_id = paid_reference
    db.session.commit()
    return True

def _notify_subscription_activated(sub):
    try:

        owner = User.query.get(sub.owner_user_id)
        log_audit(owner.email if owner else None, 'canary_subscription_activated',
                  details=f"processor={sub.processor} reference={sub.active_invoice_id}")
        send_telegram_alert_bg(
            f"💸 <b>Canary subscription paid</b>\n"
            f"Processor: <code>{sub.processor}</code>\n"
            f"User: <code>{owner.email if owner else sub.owner_user_id}</code>\n"
            f"Through: <code>{sub.current_period_end:%Y-%m-%d}</code>")
    except Exception as e:
        logger.error(f"Subscription activation notify failed: {e}")

def _verify_paystack_reference(reference):
    resp = requests.get(
        f"{PAYSTACK_API_BASE}/transaction/verify/{reference}",
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}"},
        timeout=15,
    )
    if resp.status_code != 200:
        logger.error(f"paystack verify failed: {resp.status_code} {resp.text[:200]}")
        return None
    payload = resp.json()
    data = payload.get('data') or {}
    if not payload.get('status') or data.get('status') != 'success':
        return None
    return data

@canary_service_bp.route('/api/canary-service/subscribe', methods=['POST'])
def subscribe():
    """Create an automated checkout and return its hosted payment link."""
    try:
        user = _current_user()
        if not user:
            return _json_error("Authentication required", 401)
        if not _billing_enabled():
            return _json_error("Online payment isn't configured — see the manual payment details.", 503)

        # rate limit checkout creation
        r = _redis()
        if r:
            try:
                key = f"canary:rl:sub:{user.id}"
                n = r.incr(key)
                if n == 1:
                    r.expire(key, 3600)
                if n > SUBSCRIBE_LIMIT_PER_HOUR:
                    return _json_error("Too many attempts — try again later.", 429)
            except Exception:
                pass

        # Accept processor choice from frontend, or use whichever is configured
        data = request.get_json(silent=True) or {}
        chosen = (data.get('processor') or '').lower()
        if chosen == 'btcpay' and _btcpay_enabled():
            return _subscribe_btcpay(user)
        if chosen == 'paystack' and _paystack_enabled():
            return _subscribe_paystack(user)

        # No choice made — try paystack first, then btcpay
        if _paystack_enabled():
            return _subscribe_paystack(user)
        if _btcpay_enabled():
            return _subscribe_btcpay(user)
        return _json_error("No payment processor configured", 503)
    except requests.RequestException as e:
        logger.error(f"checkout provider request error: {e}")
        return _json_error("Could not reach the payment provider.", 502)
    except Exception as e:
        logger.error(f"canary subscribe error: {e}")
        return _json_error("Could not start checkout.", 500)

def _subscribe_paystack(user):
    reference = f"canary-{user.id}-{secrets.token_urlsafe(18).replace('_', '-')[:24]}"
    resp = requests.post(
        f"{PAYSTACK_API_BASE}/transaction/initialize",
        headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                 "Content-Type": "application/json"},
        json={
            "amount": _paystack_amount_subunits(),
            "email": user.email,
            "currency": PAYSTACK_CURRENCY,
            "reference": reference,
            "callback_url": _paystack_callback_url(),
            "metadata": {"user_id": user.id, "purpose": "canary-subscription"},
        },
        timeout=15,
    )
    if resp.status_code not in (200, 201):
        logger.error(f"paystack initialize failed: {resp.status_code} {resp.text[:200]}")
        return _json_error("Could not start payment checkout.", 502)
    payload = resp.json()
    data = payload.get('data') or {}
    checkout_url = data.get('authorization_url')
    reference = data.get('reference') or reference
    if not payload.get('status') or not checkout_url or not reference:
        return _json_error("Payment processor returned an unexpected response.", 502)

    sub = CanarySubscription.query.filter_by(owner_user_id=user.id).first()
    if not sub:
        sub = CanarySubscription(owner_user_id=user.id, processor='paystack')
        db.session.add(sub)
    sub.invoice_id = reference
    sub.processor = 'paystack'
    if sub.status != 'active':
        sub.status = 'pending'
    db.session.commit()

    return jsonify({"ok": True, "checkout_url": checkout_url, "invoice_id": reference,
                    "processor": "paystack"})

def _subscribe_btcpay(user):
    """Create a BTCPay invoice (BTC + Lightning) and return its checkout link."""
    try:
        price_amount = float(CANARY_PRICE_AMOUNT)
    except (TypeError, ValueError):
        price_amount = 9.0
    resp = requests.post(
        f"{BTCPAY_URL}/api/v1/stores/{BTCPAY_STORE_ID}/invoices",
        headers={"Authorization": f"token {BTCPAY_API_KEY}",
                 "Content-Type": "application/json"},
        json={
            "amount": price_amount,
            "currency": CANARY_PRICE_CURRENCY,
            "metadata": {"userId": str(user.id), "buyerEmail": user.email or "",
                         "purpose": "canary-subscription"},
            "checkout": {"redirectURL": f"{PUBLIC_BASE}/canary/app?paid=1",
                         "redirectAutomatically": True},
        },
        timeout=15,
    )
    if resp.status_code not in (200, 201):
        logger.error(f"btcpay invoice create failed: {resp.status_code} {resp.text[:500]}")
        return _json_error("Could not start checkout. Try again or use the manual address.", 502)
    inv = resp.json()
    invoice_id = inv.get("id")
    checkout_url = inv.get("checkoutLink")
    if not invoice_id or not checkout_url:
        return _json_error("Payment provider returned an unexpected response.", 502)

    sub = CanarySubscription.query.filter_by(owner_user_id=user.id).first()
    if not sub:
        sub = CanarySubscription(owner_user_id=user.id, processor='btcpay')
        db.session.add(sub)
    sub.invoice_id = invoice_id
    sub.processor = 'btcpay'
    if sub.status != 'active':
        sub.status = 'pending'
    db.session.commit()

    return jsonify({"ok": True, "checkout_url": checkout_url, "invoice_id": invoice_id,
                    "processor": "btcpay"})

@canary_service_bp.route('/api/canary-service/verify/paystack/<reference>', methods=['POST'])
def paystack_callback_verify(reference):
    """Browser-return fallback: verify a Paystack reference after checkout in
    case the webhook is delayed. Owner-scoped by the pending subscription row."""
    user = _current_user()
    if not user:
        return _json_error("Authentication required", 401)
    if not _paystack_enabled():
        return _json_error("Payment processor is not configured.", 503)
    if not re.match(r'^[A-Za-z0-9_.=-]{4,160}$', reference or ''):
        return _json_error("Invalid reference.", 400)

    try:

        sub = CanarySubscription.query.filter_by(owner_user_id=user.id, invoice_id=reference).first()
        if not sub:
            return _json_error("Payment reference not found.", 404)
        data = _verify_paystack_reference(reference)
        if not data:
            return jsonify({"ok": True, "verified": False, "active": _sub_payload(sub)["active"]})
        paid_reference = data.get('reference') or reference
        changed = _activate_subscription(sub, 'paystack', paid_reference)
        if changed:
            _notify_subscription_activated(sub)
        db.session.commit()
        out = _sub_payload(sub)
        out.update({"ok": True, "verified": True})
        return jsonify(out)
    except Exception as e:
        logger.error(f"paystack callback verify error: {e}")
        return _json_error("Could not verify payment.", 500)

# ────────────────────────────────────────────────────────────
# trial flow — 60-day card-backed free trial
# ────────────────────────────────────────────────────────────

@canary_service_bp.route('/api/canary-service/trial/start', methods=['POST'])
def trial_start():
    """Start a 60-day trial with card authorization via Paystack."""
    try:
        user = _current_user()
        if not user:
            return _json_error("Authentication required", 401)
        if not _paystack_enabled():
            return _json_error("Card authorization requires Paystack configuration.", 503)

        # One trial per account — check for existing trial or active sub
        sub = CanarySubscription.query.filter_by(owner_user_id=user.id).first()
        if sub:
            if sub.status in ('active', 'trial'):
                return _json_error("You already have an active subscription or trial.", 400)
            if sub.trial_start and sub.status != 'expired':
                return _json_error("You have already used your free trial.", 400)

        # Rate limit trial starts
        r = _redis()
        if r:
            try:
                key = f"canary:rl:trial:{user.id}"
                n = r.incr(key)
                if n == 1:
                    r.expire(key, 3600)
                if n > SUBSCRIBE_LIMIT_PER_HOUR:
                    return _json_error("Too many attempts — try again later.", 429)
            except Exception:
                pass

        reference = f"trial-{user.id}-{secrets.token_urlsafe(18).replace('_', '-')[:24]}"
        amount = _paystack_auth_amount_subunits()

        resp = requests.post(
            f"{PAYSTACK_API_BASE}/transaction/initialize",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                     "Content-Type": "application/json"},
            json={
                "amount": amount,
                "email": user.email,
                "currency": PAYSTACK_CURRENCY,
                "reference": reference,
                "callback_url": _paystack_callback_url(),
                "metadata": {"user_id": user.id, "purpose": "canary-trial-auth"},
            },
            timeout=15,
        )
        if resp.status_code not in (200, 201):
            logger.error(f"paystack trial init failed: {resp.status_code} {resp.text[:200]}")
            return _json_error("Could not start card authorization.", 502)

        payload = resp.json()
        data = payload.get('data') or {}
        checkout_url = data.get('authorization_url')
        ref = data.get('reference') or reference
        if not payload.get('status') or not checkout_url or not ref:
            return _json_error("Payment processor returned an unexpected response.", 502)

        if not sub:
            sub = CanarySubscription(owner_user_id=user.id, processor='paystack')
            db.session.add(sub)
        sub.invoice_id = ref
        sub.processor = 'paystack'
        sub.status = 'pending'
        db.session.commit()

        return jsonify({"ok": True, "checkout_url": checkout_url, "reference": ref, "processor": "paystack"})
    except requests.RequestException as e:
        logger.error(f"trial start provider error: {e}")
        return _json_error("Could not reach the payment provider.", 502)
    except Exception as e:
        logger.error(f"trial start error: {e}")
        return _json_error("Could not start trial.", 500)

@canary_service_bp.route('/api/canary-service/trial/verify/<reference>', methods=['POST'])
def trial_verify(reference):
    """Verify trial card authorization, refund, and activate the trial period."""
    user = _current_user()
    if not user:
        return _json_error("Authentication required", 401)
    if not _paystack_enabled():
        return _json_error("Payment processor is not configured.", 503)
    if not re.match(r'^[A-Za-z0-9_.=-]{4,160}$', reference or ''):
        return _json_error("Invalid reference.", 400)

    try:

        sub = CanarySubscription.query.filter_by(owner_user_id=user.id, invoice_id=reference).first()
        if not sub:
            return _json_error("Trial reference not found.", 404)

        # Verify with Paystack
        data = _verify_paystack_reference(reference)
        if not data:
            return jsonify({"ok": True, "verified": False, "trial_active": False})

        # Extract card authorization
        auth = data.get('authorization') or {}
        auth_code = auth.get('authorization_code')
        if not auth_code:
            logger.warning(f"trial verify: no authorization_code in response for {reference}")
            return jsonify({"ok": True, "verified": False, "error": "Card authorization failed"})

        # Refund the authorization amount
        _refund_paystack_transaction(reference)

        # Activate trial
        now = datetime.utcnow()
        sub.status = 'trial'
        sub.trial_start = now
        sub.trial_end = now + timedelta(days=TRIAL_DAYS)
        sub.authorization_code = auth_code
        sub.authorization_email = data.get('customer', {}).get('email', user.email)
        sub.active_invoice_id = reference
        sub.billing_attempts = 0
        sub.last_billing_attempt = None
        sub.grace_period_end = None
        sub.cancelled = False
        db.session.commit()

        # Notify trial started
        _notify_trial_started(sub, user)

        out = {"ok": True, "verified": True, "trial_active": True,
               "trial_end": sub.trial_end.isoformat(), "days": TRIAL_DAYS}
        return jsonify(out)
    except Exception as e:
        logger.error(f"trial verify error: {e}")
        return _json_error("Could not verify trial.", 500)

@canary_service_bp.route('/api/canary-service/subscription/cancel', methods=['POST'])
def cancel_subscription():
    """Cancel subscription/trial. Prevents future billing but keeps current access."""
    try:
        user = _current_user()
        if not user:
            return _json_error("Authentication required", 401)

        sub = CanarySubscription.query.filter_by(owner_user_id=user.id).first()
        if not sub:
            return _json_error("No subscription to cancel.", 404)
        if sub.cancelled:
            return jsonify({"ok": True, "message": "Already cancelled."})

        sub.cancelled = True
        db.session.commit()

        try:

            log_audit(user.email, 'canary_subscription_cancelled',
                      details=f"status={sub.status}")
            send_telegram_alert_bg(
                f"🚫 <b>Canary cancelled</b>\nUser: <code>{user.email}</code>\n"
                f"Status: <code>{sub.status}</code>")
        except Exception as e:
            logger.error(f"Canary cancel notify failed: {e}")

        return jsonify({"ok": True, "message": "Subscription cancelled. Access continues until the period ends."})
    except Exception as e:
        logger.error(f"cancel error: {e}")
        return _json_error("Could not cancel subscription.", 500)

# ────────────────────────────────────────────────────────────
# trial notifications
# ────────────────────────────────────────────────────────────

def _notify_trial_started(sub, user):
    try:

        log_audit(user.email, 'canary_trial_started',
                  details=f"trial_end={sub.trial_end:%Y-%m-%d} days={TRIAL_DAYS}")
        send_telegram_alert_bg(
            f"🎉 <b>Canary trial started</b>\n"
            f"User: <code>{user.email}</code>\n"
            f"Expires: <code>{sub.trial_end:%Y-%m-%d}</code> ({TRIAL_DAYS} days)")
    except Exception as e:
        logger.error(f"Trial start notify failed: {e}")

def _notify_trial_ending(user_email, days_left):
    try:

        send_telegram_alert_bg(
            f"⏰ <b>Canary trial ending in {days_left} day{'s' if days_left != 1 else ''}</b>\n"
            f"User: <code>{user_email}</code>\n"
            f"Billing will start automatically. Update payment method or cancel in the dashboard.")
    except Exception as e:
        logger.error(f"Trial ending Telegram notify failed: {e}")

    # Email notification
    if os.getenv('RESEND_API_KEY') and user_email:
        try:
            import resend
            resend.api_key = os.getenv('RESEND_API_KEY')
            resend.Emails.send({
                "from": f"WraithWall Canary <{os.getenv('FROM_EMAIL', 'noreply@wraithwall.online')}>",
                "to": [user_email],
                "subject": f"Canary trial ending in {days_left} day{'s' if days_left != 1 else ''}",
                "html": f"""
                <html><body style="font-family:Arial,sans-serif;color:#0F0F0E;background:#FAFAF8;padding:24px;">
                <div style="max-width:520px;margin:0 auto;background:#fff;padding:24px;border-radius:8px;">
                <h2 style="margin-top:0;color:#C41A1A;">⏰ Trial ending soon</h2>
                <p>Your WraithWall Canary trial ends in <strong>{days_left} day{'s' if days_left != 1 else ''}</strong>.</p>
                <p>After the trial, billing will begin automatically. No action needed if you wish to continue.</p>
                <p><a href="{PUBLIC_BASE}/canary/app" style="display:inline-block;padding:10px 20px;background:#C41A1A;color:#fff;text-decoration:none;border-radius:4px;">Manage subscription</a></p>
                </div></body></html>""",
            })
        except Exception as e:
            logger.error(f"Trial ending Resend notify failed: {e}")

def _notify_charge_success(user_email, amount):
    try:

        send_telegram_alert_bg(
            f"💸 <b>Canary billing successful</b>\n"
            f"User: <code>{user_email}</code>\n"
            f"Amount: <code>{amount}</code>")
    except Exception as e:
        logger.error(f"Charge success Telegram notify failed: {e}")

    if os.getenv('RESEND_API_KEY') and user_email:
        try:
            import resend
            resend.api_key = os.getenv('RESEND_API_KEY')
            resend.Emails.send({
                "from": f"WraithWall Canary <{os.getenv('FROM_EMAIL', 'noreply@wraithwall.online')}>",
                "to": [user_email],
                "subject": "Canary subscription charged successfully",
                "html": f"""
                <html><body style="font-family:Arial,sans-serif;color:#0F0F0E;background:#FAFAF8;padding:24px;">
                <div style="max-width:520px;margin:0 auto;background:#fff;padding:24px;border-radius:8px;">
                <h2 style="margin-top:0;color:#2D7A3E;">✅ Payment successful</h2>
                <p>Your Canary subscription payment of <strong>{amount}</strong> was successful.</p>
                <p><a href="{PUBLIC_BASE}/canary/app">View dashboard</a></p>
                </div></body></html>""",
            })
        except Exception as e:
            logger.error(f"Charge success Resend notify failed: {e}")

def _notify_charge_failed(user_email):
    try:

        send_telegram_alert_bg(
            f"❌ <b>Canary billing failed</b>\n"
            f"User: <code>{user_email}</code>\n"
            f"Grace period started — update payment method.")
    except Exception as e:
        logger.error(f"Charge failed Telegram notify failed: {e}")

    if os.getenv('RESEND_API_KEY') and user_email:
        try:
            import resend
            resend.api_key = os.getenv('RESEND_API_KEY')
            resend.Emails.send({
                "from": f"WraithWall Canary <{os.getenv('FROM_EMAIL', 'noreply@wraithwall.online')}>",
                "to": [user_email],
                "subject": "Canary payment failed — action required",
                "html": f"""
                <html><body style="font-family:Arial,sans-serif;color:#0F0F0E;background:#FAFAF8;padding:24px;">
                <div style="max-width:520px;margin:0 auto;background:#fff;padding:24px;border-radius:8px;">
                <h2 style="margin-top:0;color:#C41A1A;">❌ Payment failed</h2>
                <p>We tried to charge your card for Canary but the payment failed.</p>
                <p>You have a <strong>{TRIAL_GRACE_DAYS}-day grace period</strong> to update your payment method before access is revoked.</p>
                <p><a href="{PUBLIC_BASE}/canary/app" style="display:inline-block;padding:10px 20px;background:#C41A1A;color:#fff;text-decoration:none;border-radius:4px;">Update payment method</a></p>
                </div></body></html>""",
            })
        except Exception as e:
            logger.error(f"Charge failed Resend notify failed: {e}")

def _notify_trial_expired(user_email):
    try:

        send_telegram_alert_bg(
            f"⛔ <b>Canary trial expired</b>\n"
            f"User: <code>{user_email}</code>\n"
            f"Access revoked.")
    except Exception as e:
        logger.error(f"Trial expired notify failed: {e}")

# ────────────────────────────────────────────────────────────
# trial billing — called by APScheduler cron
# ────────────────────────────────────────────────────────────

def run_trial_billing():
    """Hourly job: charge expired trials, handle grace periods, send reminders."""
    try:

        with app.app_context():
            now = datetime.utcnow()

            # 1. Charge expired trials that have a valid authorization_code
            expired = CanarySubscription.query.filter(
                CanarySubscription.status == 'trial',
                CanarySubscription.trial_end <= now,
                CanarySubscription.authorization_code.isnot(None),
                CanarySubscription.cancelled == False,
            ).all()

            for sub in expired:
                _attempt_trial_charge(sub, now)

            # 2. Handle grace period expirations
            grace_expired = CanarySubscription.query.filter(
                CanarySubscription.status == 'trial',
                CanarySubscription.grace_period_end.isnot(None),
                CanarySubscription.grace_period_end <= now,
            ).all()

            for sub in grace_expired:
                sub.status = 'expired'
                sub.grace_period_end = None
                db.session.commit()
                user = User.query.get(sub.owner_user_id)
                if user:
                    _notify_trial_expired(user.email)
                    try:

                        log_audit(user.email, 'canary_trial_expired',
                                  details='grace period ended')
                    except Exception:
                        pass

            # 3. Send trial-ending reminders (daily granularity check)
            reminder_intervals = [30, 14, 7, 3, 1]
            for days in reminder_intervals:
                target = now + timedelta(days=days)
                day_start = target.replace(hour=0, minute=0, second=0, microsecond=0)
                day_end = day_start.replace(hour=23, minute=59, second=59)
                due = CanarySubscription.query.filter(
                    CanarySubscription.status == 'trial',
                    CanarySubscription.trial_end.between(day_start, day_end),
                    CanarySubscription.cancelled == False,
                    CanarySubscription.authorization_code.isnot(None),
                ).all()
                for sub in due:
                    user = User.query.get(sub.owner_user_id)
                    if user:
                        _notify_trial_ending(user.email, days)

            logger.info(f"trial billing: checked {len(expired)} expired, "
                        f"{len(grace_expired)} grace-expired, "
                        f"{sum(1 for d in reminder_intervals for _ in [1])} reminders")
    except Exception as e:
        logger.error(f"trial billing error: {e}", exc_info=True)

def _attempt_trial_charge(sub, now):
    """Charge an expired trial's authorization code. Returns True on success."""
    try:

        if not sub.authorization_code:
            return False

        amount = int(_paystack_amount_subunits())
        resp = requests.post(
            f"{PAYSTACK_API_BASE}/transaction/charge_authorization",
            headers={"Authorization": f"Bearer {PAYSTACK_SECRET_KEY}",
                     "Content-Type": "application/json"},
            json={
                "authorization_code": sub.authorization_code,
                "email": sub.authorization_email,
                "amount": amount,
            },
            timeout=30,
        )
        if resp.status_code != 200:
            logger.warning(f"trial charge failed (HTTP {resp.status_code}) for sub {sub.id}")
            _handle_trial_charge_failure(sub, now)
            return False

        body = resp.json()
        if not body.get('status'):
            logger.warning(f"trial charge declined for sub {sub.id}: {resp.text[:200]}")
            _handle_trial_charge_failure(sub, now)
            return False

        data = body.get('data') or {}
        tx_status = data.get('status')
        if tx_status != 'success':
            logger.warning(f"trial charge tx {tx_status} for sub {sub.id}")
            _handle_trial_charge_failure(sub, now)
            return False

        # Success — convert to active subscription
        sub.status = 'active'
        sub.current_period_end = now + timedelta(days=SUB_PERIOD_DAYS)
        sub.billing_attempts = 0
        sub.last_billing_attempt = now
        sub.grace_period_end = None
        db.session.commit()

        user = User.query.get(sub.owner_user_id)
        if user:
            _notify_charge_success(user.email, amount)
            try:

                log_audit(user.email, 'canary_trial_billed',
                          details=f"amount={amount} sub={sub.id}")
            except Exception:
                pass
        return True
    except Exception as e:
        logger.error(f"_attempt_trial_charge error for sub {sub.id}: {e}")
        _handle_trial_charge_failure(sub, now)
        return False

def _handle_trial_charge_failure(sub, now):
    """Increment billing attempts and start grace period if max exceeded."""
    try:

        sub.billing_attempts = (sub.billing_attempts or 0) + 1
        sub.last_billing_attempt = now
        if sub.billing_attempts >= TRIAL_MAX_BILLING_ATTEMPTS:
            sub.grace_period_end = now + timedelta(days=TRIAL_GRACE_DAYS)
        db.session.commit()

        if sub.billing_attempts == 1:

            user = User.query.get(sub.owner_user_id)
            if user:
                _notify_charge_failed(user.email)
    except Exception as e:
        logger.error(f"_handle_trial_charge_failure: {e}")

def _verify_btcpay_sig(raw_body, header_sig):
    """Constant-time check of the BTCPay-Sig header (format: 'sha256=<hex>')."""
    if not header_sig or not BTCPAY_WEBHOOK_SECRET:
        return False
    expected = 'sha256=' + hmac.new(
        BTCPAY_WEBHOOK_SECRET.encode(), raw_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header_sig)

def _resolve_user_id_for_invoice(invoice_id, payload):
    """Map a paid invoice back to a user: prefer webhook metadata, then a
    Greenfield lookup, so a stale local invoice_id can't drop a real payment."""
    uid = (payload.get('metadata') or {}).get('userId')
    if uid:
        return uid
    try:
        resp = requests.get(
            f"{BTCPAY_URL}/api/v1/stores/{BTCPAY_STORE_ID}/invoices/{invoice_id}",
            headers={"Authorization": f"token {BTCPAY_API_KEY}"}, timeout=15,
        )
        if resp.status_code == 200:
            return (resp.json().get('metadata') or {}).get('userId')
    except Exception as e:
        logger.error(f"btcpay invoice lookup error: {e}")
    return None

def _verify_paystack_sig(raw_body, header_sig):
    """Paystack signs the raw JSON body with HMAC-SHA512 using the secret key."""
    if not header_sig or not PAYSTACK_SECRET_KEY:
        return False
    expected = hmac.new(PAYSTACK_SECRET_KEY.encode(), raw_body, hashlib.sha512).hexdigest()
    return hmac.compare_digest(expected, header_sig)

def _resolve_user_id_for_paystack(data):
    metadata = data.get('metadata') or {}
    return metadata.get('user_id') or metadata.get('userId')

@canary_service_bp.route('/api/canary-service/webhook/paystack', methods=['POST'])
def paystack_webhook():
    """Paystack calls this on transaction events. HMAC-verified; grants/extends
    the subscription for successful charges. Returns 200 for valid but ignored
    events so Paystack does not retry non-payment events."""
    raw = request.get_data()
    if not _verify_paystack_sig(raw, request.headers.get('x-paystack-signature', '')):
        logger.warning("paystack webhook: bad signature")
        return _json_error("invalid signature", 400)

    try:
        payload = json.loads(raw.decode() or '{}')
    except Exception:
        return _json_error("bad payload", 400)

    event = payload.get('event')
    data = payload.get('data') or {}
    reference = data.get('reference')
    if event != 'charge.success' or not reference:
        return jsonify({"ok": True, "ignored": event})

    # Defense in depth: webhooks are signed, but still verify the transaction with
    # Paystack before granting access.
    verified = _verify_paystack_reference(reference)
    if not verified:
        return jsonify({"ok": True, "verified": False})

    try:

        sub = CanarySubscription.query.filter_by(invoice_id=reference).first()
        if not sub:
            uid = _resolve_user_id_for_paystack(verified) or _resolve_user_id_for_paystack(data)
            if uid:
                sub = CanarySubscription.query.filter_by(owner_user_id=uid).first()
                if not sub:
                    sub = CanarySubscription(owner_user_id=uid, processor='paystack',
                                             invoice_id=reference)
                    db.session.add(sub)
        if not sub:
            logger.warning(f"paystack webhook: no subscription for reference {reference}")
            return jsonify({"ok": True, "unmatched": True})

        changed = _activate_subscription(sub, 'paystack', reference)
        if changed:
            _notify_subscription_activated(sub)
        return jsonify({"ok": True, "activated": changed})
    except Exception as e:
        logger.error(f"paystack webhook processing error: {e}")
        return _json_error("processing error", 500)

# settled events that should grant/extend access
_BTCPAY_PAID_EVENTS = {'InvoiceSettled', 'InvoicePaymentSettled'}

@canary_service_bp.route('/api/canary-service/webhook/btcpay', methods=['POST'])
def btcpay_webhook():
    """BTCPay calls this on invoice events. HMAC-verified; grants/extends the
    subscription on a settled invoice. Always 200 on accepted-but-ignored events
    so BTCPay doesn't retry; 400 only on a bad signature."""
    raw = request.get_data()
    if not _verify_btcpay_sig(raw, request.headers.get('BTCPay-Sig', '')):
        logger.warning("btcpay webhook: bad signature")
        return _json_error("invalid signature", 400)

    try:
        payload = json.loads(raw.decode() or '{}')
    except Exception:
        return _json_error("bad payload", 400)

    event = payload.get('type')
    invoice_id = payload.get('invoiceId')
    if event not in _BTCPAY_PAID_EVENTS or not invoice_id:
        return jsonify({"ok": True, "ignored": event})   # ack non-payment events

    try:

        sub = CanarySubscription.query.filter_by(invoice_id=invoice_id).first()
        if not sub:
            uid = _resolve_user_id_for_invoice(invoice_id, payload)
            if uid:
                sub = CanarySubscription.query.filter_by(owner_user_id=uid).first()
                if not sub:
                    sub = CanarySubscription(owner_user_id=uid, processor='btcpay',
                                             invoice_id=invoice_id)
                    db.session.add(sub)
        if not sub:
            logger.warning(f"btcpay webhook: no subscription for invoice {invoice_id}")
            return jsonify({"ok": True, "unmatched": True})

        changed = _activate_subscription(sub, 'btcpay', invoice_id)
        if changed:
            _notify_subscription_activated(sub)

        return jsonify({"ok": True, "activated": changed})
    except Exception as e:
        logger.error(f"btcpay webhook processing error: {e}")
        return _json_error("processing error", 500)

# ────────────────────────────────────────────────────────────
# the trap — public, no auth, no existence oracle
# ────────────────────────────────────────────────────────────
@canary_service_bp.route('/c/<token>', methods=['GET'])
def canary_trap(token):
    # strip beacon image extension if present
    for ext in ('.gif', '.png', '.jpg', '.jpeg'):
        if token.endswith(ext):
            token = token[:-len(ext)]
            break

    # validate format before any lookup; invalid → benign pixel
    if not TOKEN_RE.match(token or ''):
        return Response(_PIXEL, mimetype='image/gif')

    ip = _client_ip()

    # per-IP throttle to blunt scanners hammering the trap: once an IP exceeds
    # HIT_IP_THROTTLE_MAX requests in the window we shed the load — record nothing,
    # fire no alerts, and return the benign pixel (a single real access never trips this).
    r = _redis()
    if r:
        try:
            tkey = f"canary:rl:hitip:{ip}"
            tn = r.incr(tkey)
            if tn == 1:
                r.expire(tkey, HIT_IP_THROTTLE_TTL)
            if tn > HIT_IP_THROTTLE_MAX:
                return Response(_PIXEL, mimetype='image/gif')
        except Exception:
            pass

    redirect_to = None
    ttype = 'text'
    try:

        tok = CanaryServiceToken.query.filter_by(public_id=token).first()
        if tok and tok.is_active:
            ttype = tok.token_type
            redirect_to = tok.redirect_to
            ua = (request.headers.get('User-Agent') or '')[:255]
            ref = (request.headers.get('Referer') or '')[:255] or None

            hit = CanaryServiceHit(
                token_id=tok.id, source_ip=ip, user_agent=ua,
                method=request.method, referer=ref,
            )
            tok.trigger_count = (tok.trigger_count or 0) + 1
            tok.last_triggered = datetime.utcnow()
            db.session.add(hit)
            db.session.commit()

            try:
                from deception_event_bus import publish_deception_event
                publish_deception_event(
                    'canary_service', f'CS-{tok.public_id[:8]}', 'beacon',
                    'http_request', ip,
                    context={'token_label': tok.label, 'token_type': ttype},
                    bait_layer=4,
                )
            except Exception:
                pass

            # alert, deduped per token to cut alert-fatigue
            should = True
            if r:
                try:
                    should = r.set(f"canary:rl:hit:{token}", "1", nx=True, ex=ALERT_DEDUP_TTL)
                    should = bool(should)
                except Exception:
                    should = True
            if should:
                owner = User.query.get(tok.owner_user_id)
                hit.alert_sent = True
                try:
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                # Enrich + alert off the hot path so the trap stays fast and the
                # response shape is unchanged whether or not enrichment succeeds.
                thread_utils.spawn_request_thread(_enrich_and_alert,
                    args=(hit.id, tok.label, owner.email if owner else None, ip, ua, ttype))
    except Exception as e:
        logger.error(f"canary trap error: {e}")
        # fall through to benign response — never leak internals

    # benign response, identical shape whether or not the token was real
    if ttype == 'url' and redirect_to:
        return redirect(redirect_to, code=302)
    return Response(_PIXEL, mimetype='image/gif')
