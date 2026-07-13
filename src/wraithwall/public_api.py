import os
import json
import logging
from datetime import datetime
from flask import Blueprint, jsonify, request
import redis as redis_lib

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get('REDIS_URL', '')
public_bp = Blueprint('public_api', __name__)

ACTIVITY_FEED_KEY = "public:activity"
ACTIVITY_FEED_MAX = 50

def _get_redis():
    if not REDIS_URL:
        return None
    try:
        return redis_lib.from_url(REDIS_URL, socket_connect_timeout=3, socket_timeout=5,
                                  decode_responses=True)
    except Exception:
        return None

def record_public_activity(activity_type: str, target: str, details: dict = None):
    """Push a public activity entry to the Redis feed for the landing page."""
    r = _get_redis()
    if not r:
        return
    try:
        entry = {
            "type": activity_type,
            "target": target[:200],
            "timestamp": datetime.utcnow().isoformat(),
            "details": details or {},
        }
        r.lpush(ACTIVITY_FEED_KEY, json.dumps(entry))
        r.ltrim(ACTIVITY_FEED_KEY, 0, ACTIVITY_FEED_MAX - 1)
    except Exception as e:
        logger.debug(f"record_public_activity failed: {e}")

def _scan_keys(r, pattern, limit=None):
    keys = []
    for key in r.scan_iter(match=pattern, count=500):
        keys.append(key)
        if limit is not None and len(keys) >= limit:
            break
    return keys

def _stage_severity(stage):
    high_risk = {'credential_access', 'impact', 'exfiltration', 'command_and_control'}
    med_risk = {'privilege_escalation', 'lateral_movement', 'defense_evasion', 'persistence'}
    if stage in high_risk:
        return 'critical'
    elif stage in med_risk:
        return 'high'
    elif stage == 'reconnaissance':
        return 'medium'
    return 'low'

@public_bp.route('/api/public/activity', methods=['GET'])
def public_activity():
    """Return recent public activity feed for the landing page live strip."""
    r = _get_redis()
    if not r:
        return jsonify({"activities": [], "error": "Redis unavailable"}), 503

    limit = request.args.get('limit', 20, type=int)
    if limit < 1:
        limit = 1
    if limit > 100:
        limit = 100

    try:
        raw = r.lrange(ACTIVITY_FEED_KEY, 0, limit - 1)
        activities = [json.loads(line) for line in raw if line]
        return jsonify({"activities": activities, "count": len(activities)})
    except Exception as e:
        logger.error(f"public_activity error: {e}")
        return jsonify({"activities": [], "error": str(e)}), 500

@public_bp.route('/api/public/stats', methods=['GET'])
def public_stats():
    r = _get_redis()
    if not r:
        return jsonify({"error": "Redis unavailable"}), 503

    try:
        # 'cowrie_sessions:recent' is a capped rolling buffer (LTRIM 0,999), so its
        # length pins at 1000. Prefer the cumulative 'cowrie_sessions:total' counter
        # and fall back to the buffer length when the counter is not yet populated.
        recent_count = r.llen('cowrie_sessions:recent') or 0
        try:
            lifetime_count = int(r.get('cowrie_sessions:total') or 0)
        except (TypeError, ValueError):
            lifetime_count = 0
        total_sessions = max(recent_count, lifetime_count)
        stage_counts = {}
        session_ids = r.lrange('cowrie_sessions:recent', 0, 499)
        for sid in session_ids:
            data = r.get(f"cowrie_completed:{sid}")
            if data:
                try:
                    sess = json.loads(data)
                    stage = sess.get('intelligence', {}).get('attack_stage', 'unknown')
                    stage_counts[stage] = stage_counts.get(stage, 0) + 1
                except:
                    pass

        recent_attacks = [
            {"stage": k, "count": v, "severity": _stage_severity(k)}
            for k, v in sorted(stage_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        ]

        try:
            active_lures = r.zcard('lures:active') or 0
        except:
            active_lures = 0
        try:
            active_sc_canaries = r.zcard('canaries:active') or 0
        except:
            active_sc_canaries = 0
        active_canaries = active_lures + active_sc_canaries

        try:
            countries = r.zrevrange('asn:countries', 0, 4, withscores=True)
        except:
            countries = []
        attack_origins = {}
        for c, s in countries:
            c = c.decode() if isinstance(c, bytes) else c
            attack_origins[c] = int(s)

        tool_keys = _scan_keys(r, 'corpus:tool:*', limit=20)
        tool_popularity = {}
        for key in tool_keys:
            tool_name = key.split('corpus:tool:')[1]
            count = r.scard(key)
            if count:
                tool_popularity[tool_name] = count
        top_tools = sorted(tool_popularity, key=tool_popularity.get, reverse=True)[:5]

        try:
            llm_attempts = len(_scan_keys(r, 'llm_honeypot:*', limit=500))
        except:
            llm_attempts = 0

        try:
            bgp_alerts = r.llen('bgp_monitor:alerts') or 0
        except:
            bgp_alerts = 0

        sensor_nodes = len([s for s in os.environ.get('HONEYPOT_SENSORS', '').split(',') if s.strip()])
        bgp_prefix_count = len([s for s in os.environ.get('YOUR_PREFIXES', '').split(',') if s.strip()])

        try:
            campaign_count = r.zcard('active_campaigns') if r.exists('active_campaigns') else 0
        except:
            campaign_count = 0
        total_threats = total_sessions + campaign_count + active_lures + llm_attempts

        try:
            canary_triggers = int(r.get('canary_triggers:total') or r.get('canary:triggers:total') or 0)
        except (TypeError, ValueError):
            canary_triggers = 0
        if not canary_triggers:
            try:
                canary_triggers = len(_scan_keys(r, 'canary_trigger:*', limit=10000))
            except Exception:
                canary_triggers = 0

        return jsonify({
            "total_threats": total_threats,
            "total_sessions": total_sessions,
            "honeypot_sessions": total_sessions,
            "active_canaries": active_canaries,
            "canary_triggers": canary_triggers,
            "recent_attacks": recent_attacks,
            "attack_origins": [{"country_code": k, "count": v} for k, v in attack_origins.items()] if isinstance(attack_origins, dict) else attack_origins,
            "top_tools": top_tools,
            "llm_injection_attempts": llm_attempts,
            "bgp_alerts": bgp_alerts,
            "bgp_prefix_count": bgp_prefix_count,
            "sensor_nodes": sensor_nodes,
            "last_updated": datetime.utcnow().isoformat()
        })

    except Exception as e:
        logger.error(f"public_stats error: {e}")
        return jsonify({"error": "Stats temporarily unavailable"}), 500
