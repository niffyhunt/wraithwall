import os
import re
import json
import time
import asyncio
import hashlib
import logging
import threading
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Set, Tuple

import requests
import redis as redis_lib
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────

CLOUDFLARE_API_TOKEN = os.environ.get('CLOUDFLARE_API_TOKEN', '')
YOUR_ASN = os.environ.get('YOUR_ASN', '')
YOUR_PREFIXES_RAW = os.environ.get('YOUR_PREFIXES', '')
REDIS_URL = os.environ.get('REDIS_URL', '')
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')

MONITORED_PREFIXES = [p.strip() for p in YOUR_PREFIXES_RAW.split(',') if p.strip()] or [
    "104.21.0.0/16",
    "172.67.0.0/16",
]

AUTHORIZED_ASNS = set(filter(None, [
    YOUR_ASN,
    "AS13335",
    "AS209242",
]))

BGP_STATE_KEY = "bgp_monitor:route_state"
BGP_ALERTS_KEY = "bgp_monitor:alerts"
CF_RADAR_BASE = "https://api.cloudflare.com/client/v4/radar"
RIPE_RIS_WS = "wss://ris-live.ripe.net/v1/ws/"

# ────────────────────────────────────────────────────────────
# ROUTE STATE TRACKER
# ────────────────────────────────────────────────────────────

class BGPRouteState:
    """Tracks‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ known-good BGP route state and detects anomalies."""

    def __init__(self):
        self._state: Dict[str, Dict] = {}
        self._lock = threading.RLock()
        self._load_from_redis()

    def _get_redis(self):
        if not REDIS_URL:
            return None
        try:
            return redis_lib.from_url(REDIS_URL, socket_connect_timeout=3,
                                      decode_responses=True, max_connections=5)
        except Exception:
            return None

    def _load_from_redis(self):
        r = self._get_redis()
        if not r:
            return
        try:
            data = r.get(BGP_STATE_KEY)
            if data:
                with self._lock:
                    self._state = json.loads(data)
                logger.info(f"BGP: Loaded {len(self._state)} known routes from Redis")
        except Exception as e:
            logger.error(f"BGP: Redis load error: {e}")

    def _save_to_redis(self):
        r = self._get_redis()
        if not r:
            return
        try:
            with self._lock:
                r.set(BGP_STATE_KEY, json.dumps(self._state))
        except Exception as e:
            logger.error(f"BGP: Redis save error: {e}")

    def learn(self, prefix: str, origin_asn: str, as_path: List[str]):
        with self._lock:
            self._state[prefix] = {
                "origin_asn": origin_asn,
                "as_path": as_path,
                "learned_at": datetime.utcnow().isoformat(),
                "last_seen": datetime.utcnow().isoformat(),
            }
        self._save_to_redis()

    def check(self, prefix: str, origin_asn: str, as_path: List[str]) -> Optional[Dict]:
        with self._lock:
            known = self._state.get(prefix)

            if not known:
                self.learn(prefix, origin_asn, as_path)
                if origin_asn and origin_asn not in AUTHORIZED_ASNS:
                    return {
                        "type": "new_unauthorized_announcement",
                        "prefix": prefix,
                        "origin_asn": origin_asn,
                        "as_path": as_path,
                        "severity": "high",
                        "description": f"Prefix {prefix} announced by unauthorized AS {origin_asn} — first sighting"
                    }
                return None

            if known["origin_asn"] and origin_asn and known["origin_asn"] != origin_asn:
                severity = "critical" if origin_asn not in AUTHORIZED_ASNS else "medium"
                return {
                    "type": "origin_asn_change",
                    "prefix": prefix,
                    "origin_asn": origin_asn,
                    "prev_asn": known["origin_asn"],
                    "as_path": as_path,
                    "severity": severity,
                    "description": f"Prefix {prefix} origin changed: {known['origin_asn']} → {origin_asn}"
                }

            known_set = set(known.get("as_path", []))
            new_set = set(as_path)
            new_ases = new_set - known_set - AUTHORIZED_ASNS

            if new_ases:
                return {
                    "type": "new_as_in_path",
                    "prefix": prefix,
                    "new_ases": list(new_ases),
                    "as_path": as_path,
                    "severity": "medium",
                    "description": f"New AS(es) in path for {prefix}: {new_ases}"
                }

            self._state[prefix]["last_seen"] = datetime.utcnow().isoformat()
        self._save_to_redis()
        return None

    def get_state(self) -> Dict:
        with self._lock:
            return dict(self._state)

route_state = BGPRouteState()

# ────────────────────────────────────────────────────────────
# CLOUDFLARE RADAR API
# ────────────────────────────────────────────────────────────

def _cf_headers() -> Dict:
    return {
        "Authorization": f"Bearer {CLOUDFLARE_API_TOKEN}",
        "Content-Type": "application/json"
    }

def check_bgp_routes_cloudflare() -> List[Dict]:
    if not CLOUDFLARE_API_TOKEN:
        return []

    anomalies = []
    for prefix in MONITORED_PREFIXES:
        try:
            resp = requests.get(
                f"{CF_RADAR_BASE}/bgp/routes/pfx2as",
                params={"prefix": prefix, "format": "json"},
                headers=_cf_headers(),
                timeout=15
            )
            if not resp.ok:
                continue

            data = resp.json()
            routes = data.get("result", {}).get("routes", [])

            for route in routes:
                origin_asn = f"AS{route.get('origin', '')}"
                as_path = route.get("asnPath", "").split() or [origin_asn]
                anomaly = route_state.check(prefix, origin_asn, as_path)
                if anomaly:
                    anomalies.append(anomaly)
        except requests.exceptions.Timeout:
            logger.warning(f"BGP: CF Radar timeout for {prefix}")
        except Exception as e:
            logger.error(f"BGP: CF Radar error for {prefix}: {e}")

    return anomalies

def check_bgp_hijacks_cloudflare() -> List[Dict]:
    if not CLOUDFLARE_API_TOKEN:
        return []

    anomalies = []
    try:
        resp = requests.get(
            f"{CF_RADAR_BASE}/bgp/hijacks/events",
            params={"dateRange": "1d", "format": "json", "maxConfidence": 90},
            headers=_cf_headers(),
            timeout=15
        )
        if not resp.ok:
            return []

        data = resp.json()
        events = data.get("result", {}).get("asns_events", [])

        for event in events:
            hijack_prefix = event.get("prefix", "")
            hijacker_asn = f"AS{event.get('hijacker_asn', '')}"
            victim_asn = f"AS{event.get('victim_asn', '')}"

            is_ours = (
                _prefix_overlaps_any(hijack_prefix, MONITORED_PREFIXES) or
                victim_asn == YOUR_ASN
            )

            if is_ours:
                anomalies.append({
                    "type": "bgp_hijack_detected",
                    "prefix": hijack_prefix,
                    "hijacker_asn": hijacker_asn,
                    "victim_asn": victim_asn,
                    "confidence": event.get("confidence"),
                    "severity": "critical",
                    "source": "cloudflare_radar",
                    "description": (
                        f"BGP HIJACK: {hijack_prefix} potentially hijacked by "
                        f"{hijacker_asn} (victim: {victim_asn})"
                    ),
                    "event_data": event
                })
    except Exception as e:
        logger.error(f"BGP: CF hijack check error: {e}")

    return anomalies

def _prefix_overlaps_any(prefix_str: str, monitored: List[str]) -> bool:
    try:
        check = ipaddress.ip_network(prefix_str, strict=False)
        for mon in monitored:
            if check.overlaps(ipaddress.ip_network(mon, strict=False)):
                return True
    except ValueError:
        pass
    return False

# ────────────────────────────────────────────────────────────
# RIPE RIS LIVE MONITORING
# ────────────────────────────────────────────────────────────

async def monitor_ripe_ris_continuous():
    """Continuously‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ monitor RIPE RIS Live with auto-reconnect."""
    try:
        import websockets
    except ImportError:
        logger.error("BGP: pip install websockets required for RIPE RIS Live")
        return

    subscribe_msg = json.dumps({
        "type": "ris_subscribe",
        "data": {
            "type": "UPDATE",
            "moreSpecific": True,
            "lessSpecific": False
        }
    })

    while True:
        try:
            logger.info("BGP: Connecting to RIPE RIS Live...")
            async with websockets.connect(
                RIPE_RIS_WS,
                ping_interval=60,
                ping_timeout=30,
                close_timeout=10
            ) as ws:
                await ws.send(subscribe_msg)
                logger.info("BGP: Connected to RIPE RIS Live")
                setattr(monitor_ripe_ris_continuous, '_backoff', 0)  # reset on success
                _set_feed_status('connected', 0)

                if MONITORED_PREFIXES:
                    update_msg = json.dumps({
                        "type": "ris_subscribe",
                        "data": {
                            "type": "UPDATE",
                            "prefix": MONITORED_PREFIXES[0],
                            "moreSpecific": True
                        }
                    })
                    await ws.send(update_msg)

                while True:
                    try:
                        msg = await asyncio.wait_for(ws.recv(), timeout=60)
                        data = json.loads(msg)

                        if data.get("type") != "ris_message":
                            continue

                        body = data.get("data", {})
                        if body.get("type") != "UPDATE":
                            continue

                        prefix = body.get("prefix", "")
                        origin_asn = f"AS{body.get('origin', '')}"
                        as_path = body.get("path", [])

                        if not _prefix_overlaps_any(prefix, MONITORED_PREFIXES):
                            continue

                        anomaly = route_state.check(prefix, origin_asn, as_path)
                        if anomaly:
                            anomaly["source"] = "ripe_ris_live"
                            _handle_anomaly(anomaly)

                    except asyncio.TimeoutError:
                        await ws.ping()
                        _set_feed_status('degraded', 3000)
                        continue
                    except Exception as e:
                        logger.error(f"BGP: RIS message error: {e}")
                        _set_feed_status('disconnected')
                        break

        except Exception as e:
            logger.warning(f"BGP: RIPE RIS connection lost: {e}. Reconnecting with backoff...")
            _set_feed_status('disconnected')
            # Exponential backoff for reconnect (suggestion from public OSS analysis)
            reconnect_delay = min(300, 30 * (2 ** getattr(monitor_ripe_ris_continuous, '_backoff', 0)))
            setattr(monitor_ripe_ris_continuous, '_backoff', getattr(monitor_ripe_ris_continuous, '_backoff', 0) + 1)
            await asyncio.sleep(reconnect_delay)
            # reset backoff on next success (handled in connect block)

def _run_ripe_ris_thread():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(monitor_ripe_ris_continuous())
    finally:
        loop.close()

# ────────────────────────────────────────────────────────────
# ANOMALY HANDLER & CROSS-MODULE INTEGRATION
# ────────────────────────────────────────────────────────────

def _handle_anomaly(anomaly: Dict):
    """Process‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ a detected BGP anomaly — store, alert, cross-feed modules."""
    anomaly_hash = hashlib.sha256(
        f"{anomaly['type']}:{anomaly['prefix']}:{anomaly.get('origin_asn', '')}".encode()
    ).hexdigest()[:16]

    r = _get_bgp_redis()
    if r:
        dedup_key = f"bgp_alert_sent:{anomaly_hash}"
        if r.exists(dedup_key):
            return
        r.setex(dedup_key, 3600, "1")

        ts = datetime.utcnow().isoformat()
        alert_payload = {
            **anomaly,
            "timestamp": ts,
            "hash": anomaly_hash
        }
        r.lpush(BGP_ALERTS_KEY, json.dumps(alert_payload))
        r.ltrim(BGP_ALERTS_KEY, 0, 499)

        # Route change log (24h TTL sorted set for time-based filtering)
        r.zadd('bgp_monitor:route_changes', {json.dumps(alert_payload): time.time()})
        r.zremrangebyscore('bgp_monitor:route_changes', 0, time.time() - 86400)

        # Active hijack tracking
        if anomaly.get('severity') in ('critical', 'high'):
            hijack_key = f"bgp_monitor:hijacks:active:{anomaly_hash}"
            r.setex(hijack_key, 86400, json.dumps({
                "attacker_asn": anomaly.get('origin_asn') or anomaly.get('hijacker_asn', 'unknown'),
                "victim_prefix": anomaly['prefix'],
                "confidence_score": 95 if anomaly.get('severity') == 'critical' else 80,
                "first_seen": ts,
                "type": anomaly['type'],
                "description": anomaly['description']
            }))

        # Cross-feed ASN intelligence
        origin_asn = anomaly.get('origin_asn', '')
        hijacker_asn = anomaly.get('hijacker_asn', '')
        for asn in set(filter(None, [origin_asn, hijacker_asn])):
            r.setex(f"asn:bgp_hijack:{asn}", 86400 * 30, json.dumps({
                "asn": asn,
                "hijack_type": anomaly.get('type'),
                "prefix": anomaly.get('prefix'),
                "detected_at": datetime.utcnow().isoformat(),
                "severity": anomaly.get('severity')
            }))
            r.zadd('asn:high_risk', {asn: 100})
            r.zincrby('asn:leaderboard:total', 50, asn)

    # Log to immutable log
    try:

        write_immutable_log({
            "event": "bgp_anomaly_detected",
            "anomaly_type": anomaly["type"],
            "prefix": anomaly["prefix"],
            "severity": anomaly["severity"],
            "description": anomaly["description"],
            "timestamp": datetime.utcnow().isoformat()
        })
    except ImportError:
        pass

    # Alert
    severity_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(anomaly["severity"], "🟢")
    msg = (
        f"{severity_emoji} <b>BGP ANOMALY DETECTED</b>\n"
        f"<b>Type:</b> {anomaly['type']}\n"
        f"<b>Prefix:</b> <code>{anomaly['prefix']}</code>\n"
        f"<b>Severity:</b> {anomaly['severity'].upper()}\n"
        f"<b>Detail:</b> {anomaly['description']}\n"
        f"<b>Source:</b> {anomaly.get('source', 'unknown')}\n"
        f"<b>Time:</b> {datetime.utcnow().strftime('%H:%M:%S UTC')}"
    )

    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"},
                timeout=5
            )
        except Exception as e:
            logger.error(f"BGP Telegram alert failed: {e}")

    if DISCORD_WEBHOOK_URL:
        try:
            plain = re.sub(r'<[^>]+>', '', msg)
            requests.post(DISCORD_WEBHOOK_URL, json={"content": plain, "allowed_mentions": {"parse": []}}, timeout=3)
        except Exception as e:
            logger.error(f"BGP Discord alert failed: {e}")

    logger.warning(f"BGP ALERT: {anomaly['description']}")

def _get_bgp_redis():
    if not REDIS_URL:
        return None
    try:
        return redis_lib.from_url(REDIS_URL, socket_connect_timeout=3,
                                  decode_responses=True, max_connections=5)
    except Exception:
        return None

def is_ip_from_hijacked_prefix(ip_address: str) -> Optional[Dict]:
    """Called by cowrie_intelligence and asn_intelligence to check if IP is from hijacked prefix."""
    r = _get_bgp_redis()
    if not r:
        return None

    try:
        addr = ipaddress.ip_address(ip_address)
        alert_data = r.lrange(BGP_ALERTS_KEY, 0, 99)

        for alert_json in alert_data:
            alert = json.loads(alert_json)
            hijack_prefix = alert.get('prefix', '')
            if not hijack_prefix:
                continue
            try:
                network = ipaddress.ip_network(hijack_prefix, strict=False)
                if addr in network:
                    return {
                        "ip": ip_address,
                        "hijack_prefix": hijack_prefix,
                        "hijacker_asn": alert.get('origin_asn') or alert.get('hijacker_asn'),
                        "alert_type": alert.get('type'),
                        "severity": alert.get('severity'),
                        "detected_at": alert.get('timestamp'),
                        "warning": "IP from hijacked prefix — traffic may be intercepted"
                    }
            except ValueError:
                continue
    except (ValueError, ipaddress.AddressValueError):
        pass

    return None

# ────────────────────────────────────────────────────────────
# MAIN MONITOR JOB
# ────────────────────────────────────────────────────────────

def run_bgp_monitor() -> List[Dict]:
    """Main BGP monitoring job. Call from APScheduler."""
    anomalies = []
    try:
        anomalies.extend(check_bgp_routes_cloudflare())
        anomalies.extend(check_bgp_hijacks_cloudflare())
        for anomaly in anomalies:
            _handle_anomaly(anomaly)
        if anomalies:
            logger.warning(f"BGP: {len(anomalies)} anomalies detected")
        else:
            logger.debug(f"BGP: Clean — {len(MONITORED_PREFIXES)} prefixes nominal")
    except Exception as e:
        logger.error(f"BGP monitor error: {e}")
    return anomalies

def start_bgp_monitor():
    """Start BGP monitoring."""
    if CLOUDFLARE_API_TOKEN:
        logger.info(f"BGP Monitor started — watching {MONITORED_PREFIXES}")
    if REDIS_URL and RIPE_RIS_WS:
        t = threading.Thread(target=_run_ripe_ris_thread, daemon=True, name="ripe-ris")
        t.start()
        logger.info("BGP: RIPE RIS Live monitoring started")

# ── Feed status tracking ─────────────────────────────────────

_feed_status = {'state': 'disconnected', 'latency_ms': 0, 'last_update': None}
_feed_lock = threading.Lock()

def _set_feed_status(state, latency_ms=0):
    with _feed_lock:
        _feed_status['state'] = state
        _feed_status['latency_ms'] = latency_ms
        _feed_status['last_update'] = datetime.utcnow().isoformat()

def get_feed_status():
    """Return RIPE RIS feed connection status."""
    with _feed_lock:
        return dict(_feed_status)

# ────────────────────────────────────────────────────────────
# FLASK BLUEPRINT
# ────────────────────────────────────────────────────────────

bgp_bp = Blueprint('bgp_monitor', __name__)

def _require_admin():
    try:

        if not is_logged_in() or not is_admin():
            return jsonify({"error": "Admin required"}), 403
    except ImportError:
        pass
    return None

@bgp_bp.route('/api/bgp/status', methods=['GET'])
def bgp_status():
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    state = route_state.get_state()
    return jsonify({
        "ok": True,
        "monitored_prefixes": MONITORED_PREFIXES,
        "authorized_asns": list(AUTHORIZED_ASNS),
        "known_routes": len(state),
        "routes": [
            {
                "prefix": p,
                "origin_asn": d.get("origin_asn"),
                "as_path": d.get("as_path"),
                "learned_at": d.get("learned_at"),
                "last_seen": d.get("last_seen")
            }
            for p, d in state.items()
        ]
    })

@bgp_bp.route('/api/bgp/alerts', methods=['GET'])
def bgp_alerts():
    # Allow logged-in for dashboard
    try:

        if not is_logged_in():
            auth_err = _require_admin()
            if auth_err:
                return auth_err
    except:
        auth_err = _require_admin()
        if auth_err:
            return auth_err

    r = _get_bgp_redis()
    if not r:
        return jsonify({"ok": True, "alerts": [], "note": "Redis unavailable"})

    alert_data = r.lrange(BGP_ALERTS_KEY, 0, 49)
    alerts = []
    for a in alert_data:
        try:
            alerts.append(json.loads(a))
        except Exception:
            continue

    return jsonify({"ok": True, "count": len(alerts), "alerts": alerts})

@bgp_bp.route('/api/bgp/check-ip/<ip_address>', methods=['GET'])
def check_ip(ip_address):
    try:

        if not is_logged_in():
            return jsonify({"error": "Login required"}), 403
    except ImportError:
        return jsonify({"error": "Authentication unavailable"}), 503

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    hijack = is_ip_from_hijacked_prefix(ip_address)
    return jsonify({
        "ok": True,
        "ip": ip_address,
        "hijacked": hijack is not None,
        "hijack_info": hijack
    })

@bgp_bp.route('/api/bgp/route-changes', methods=['GET'])
def bgp_route_changes():
    """Route state change log — last 24 hours."""
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    r = _get_bgp_redis()
    if not r:
        return jsonify({"ok": True, "changes": [], "note": "Redis unavailable"})

    cutoff = time.time() - 86400
    raw = r.zrangebyscore('bgp_monitor:route_changes', cutoff, '+inf')
    changes = []
    for item in reversed(raw):
        try:
            changes.append(json.loads(item))
        except Exception:
            continue

    return jsonify({"ok": True, "count": len(changes), "changes": changes})

@bgp_bp.route('/api/bgp/hijacks/active', methods=['GET'])
def bgp_hijacks_active():
    """Active hijack detections currently in progress."""
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    r = _get_bgp_redis()
    if not r:
        return jsonify({"ok": True, "hijacks": [], "note": "Redis unavailable"})

    keys = []
    try:
        keys = r.keys('bgp_monitor:hijacks:active:*')
    except Exception:
        pass

    hijacks = []
    for k in (keys or []):
        try:
            hijacks.append(json.loads(r.get(k)))
        except Exception:
            continue
    hijacks.sort(key=lambda x: x.get('first_seen', ''), reverse=True)

    return jsonify({"ok": True, "count": len(hijacks), "hijacks": hijacks})

@bgp_bp.route('/api/bgp/feed-status', methods=['GET'])
def bgp_feed_status():
    """RIPE RIS Live feed connection status."""
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    status = get_feed_status()
    return jsonify({
        "ok": True,
        "feed": "RIPE RIS Live",
        "state": status['state'].upper(),
        "latency_ms": status['latency_ms'],
        "last_update": status['last_update']
    })
