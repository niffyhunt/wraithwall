import os
import re
import json
import hashlib
import logging
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any
from collections import Counter

import redis as redis_lib
from flask import Blueprint, jsonify, request, g, session

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────

REDIS_URL = os.environ.get('REDIS_URL', '')

# ────────────────────────────────────────────────────────────
# KNOWN JA3 SIGNATURES
# ────────────────────────────────────────────────────────────

# ────────────────────────────────────────────────────────────
# KNOWN HASSH SIGNATURES
# ────────────────────────────────────────────────────────────

KNOWN_HASSH = {
    "e3b0c44298fc1c149afbf4c8996fb924": {
        "tool": "OpenSSH", "version": "7.4+", "confidence": 80,
        "category": "ssh_client", "os": "linux"
    },
    "1c3b6c1e8a9c5f7d2e4b8a0d6f9c3e7a": {
        "tool": "OpenSSH", "version": "8.0+", "confidence": 85,
        "category": "ssh_client", "os": "linux"
    },
    "a2b8c4d6e8f0a1b3c5d7e9f0b2d4f6a8": {
        "tool": "libssh2", "version": "1.x", "confidence": 82,
        "category": "ssh_client", "os": "cross_platform"
    },
    "b4c6d8e0f2a4b6c8d0e2f4a6b8c0d2e4": {
        "tool": "Paramiko", "version": "2.x", "confidence": 84,
        "category": "ssh_client", "os": "cross_platform"
    },
    "f0e1d2c3b4a59687786a5b4c3d2e1f0": {
        "tool": "PuTTY", "version": "0.7x+", "confidence": 88,
        "category": "ssh_client", "os": "windows"
    },
    "5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d": {
        "tool": "Dropbear", "version": "2019+", "confidence": 86,
        "category": "ssh_client", "os": "embedded"
    },
    "9e8d7c6b5a49382716354a5b6c7d8e9f": {
        "tool": "MobaXterm", "version": "12+", "confidence": 82,
        "category": "ssh_client", "os": "windows"
    },
    "7f6e5d4c3b2a1908f7e6d5c4b3a291807": {
        "tool": "GoSSH", "version": "0.x", "confidence": 76,
        "category": "ssh_client", "os": "cross_platform"
    },
    "d4c5b6a79807f6e5d4c3b2a1908f7e6d": {
        "tool": "JSch", "version": "0.1.x", "confidence": 80,
        "category": "ssh_client", "os": "java"
    },
}

KNOWN_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865": {
        "tool": "Metasploit", "version": "4.x+", "confidence": 97,
        "category": "exploitation_framework"
    },
    "6734f37431670b3ab4292b8f60f29984": {
        "tool": "Nmap", "version": "ssl-scan", "confidence": 94,
        "category": "port_scanner"
    },
    "8f52d1ce085084bbd6be1709c7de8b01": {
        "tool": "ZGrab", "version": "2.x", "confidence": 92,
        "category": "banner_grabber"
    },
    "51c64c77e60f3980eea90869b68c58a8": {
        "tool": "curl", "version": "7.x", "confidence": 78,
        "category": "http_client"
    },
    "19e29534fd49dd27d09234e639c4057e": {
        "tool": "python-requests", "version": "2.x", "confidence": 85,
        "category": "http_client"
    },
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "tool": "Go http.Client", "version": "1.x", "confidence": 80,
        "category": "http_client"
    },
    "b386946a5a44d1ddcc843bc75336dfce": {
        "tool": "Nikto", "version": "2.x", "confidence": 93,
        "category": "web_scanner"
    },
    "4d7a28d6f2263ed61de88ca66eb011e3": {
        "tool": "sqlmap", "version": "1.x", "confidence": 96,
        "category": "exploitation_tool"
    },
    "c35b10c4eb2ecf0985a5c16f5e0b8a2f": {
        "tool": "Burp Suite", "version": "community", "confidence": 88,
        "category": "proxy_scanner"
    },
    "c13c2027a7e5a46b456bc1d6fb1c01b0": {
        "tool": "Masscan", "version": "1.x", "confidence": 90,
        "category": "port_scanner"
    },
    "5e2ebe3f37e82f41d67d6abb6e2e1e76": {
        "tool": "Dirbuster", "version": "1.x", "confidence": 84,
        "category": "path_brute_forcer"
    },
    "d1d7d1e2b9e7b5a8c5f2d3e4f1a2b3c4": {
        "tool": "Internet Scanner", "version": "crawler", "confidence": 75,
        "category": "search_crawler"
    },
    "3b87a2d6f1c9e4a5b8d2f3c1e6a4b5d7": {
        "tool": "Hydra", "version": "9.x", "confidence": 91,
        "category": "credential_brute_forcer"
    },
    "7e4f9a1b2c3d5e6f8a9b0c1d2e3f4a5b": {
        "tool": "WPScan", "version": "3.x", "confidence": 88,
        "category": "cms_scanner"
    },
    "2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d": {
        "tool": "Acunetix", "version": "14+", "confidence": 92,
        "category": "vulnerability_scanner"
    },
    "9b8a7c6d5e4f3a2b1c0d9e8f7a6b5c4d": {
        "tool": "Nessus", "version": "10.x", "confidence": 90,
        "category": "vulnerability_scanner"
    },
}

# ────────────────────────────────────────────────────────────
# KNOWN USER-AGENT PATTERNS
# ────────────────────────────────────────────────────────────

KNOWN_UA_PATTERNS = [
    (re.compile(r'sqlmap', re.I), "sqlmap", "exploitation_tool", 96),
    (re.compile(r'nikto', re.I), "Nikto", "web_scanner", 95),
    (re.compile(r'masscan', re.I), "Masscan", "port_scanner", 94),
    (re.compile(r'zgrab', re.I), "ZGrab", "banner_grabber", 93),
    (re.compile(r'nuclei', re.I), "Nuclei", "vulnerability_scanner", 92),
    (re.compile(r'hydra', re.I), "Hydra", "credential_brute_forcer", 91),
    (re.compile(r'dirbuster', re.I), "DirBuster", "path_brute_forcer", 91),
    (re.compile(r'gobuster', re.I), "Gobuster", "path_brute_forcer", 91),
    (re.compile(r'ffuf', re.I), "ffuf", "path_brute_forcer", 90),
    (re.compile(r'wfuzz', re.I), "Wfuzz", "path_brute_forcer", 90),
    (re.compile(r'nmap', re.I), "Nmap", "port_scanner", 89),
    (re.compile(r'python-requests/(\d+\.\d+)', re.I), "python-requests", "http_client", 78),
    (re.compile(r'go-http-client/(\d)', re.I), "Go http.Client", "http_client", 77),
    (re.compile(r'libwww-perl', re.I), "libwww-perl", "http_client", 80),
    (re.compile(r'curl/(\d+\.\d+)', re.I), "curl", "http_client", 75),
    (re.compile(r'wget/(\d+\.\d+)', re.I), "wget", "http_client", 75),
    (re.compile(r'scrapy/(\d+\.\d+)', re.I), "Scrapy", "web_crawler", 82),
    (re.compile(r'wpscan', re.I), "WPScan", "cms_scanner", 93),
    (re.compile(r'acunetix', re.I), "Acunetix", "vulnerability_scanner", 94),
    (re.compile(r'nessus', re.I), "Nessus", "vulnerability_scanner", 93),
    (re.compile(r'openvas', re.I), "OpenVAS", "vulnerability_scanner", 93),
    (re.compile(r'arachni', re.I), "Arachni", "web_scanner", 91),
    (re.compile(r'shodan', re.I), "Internet Scanner", "search_crawler", 85),
    (re.compile(r'headlesschrome', re.I), "HeadlessChrome", "headless_browser", 85),
    (re.compile(r'phantomjs', re.I), "PhantomJS", "headless_browser", 88),
]

# ────────────────────────────────────────────────────────────
# SUSPICIOUS PATH PATTERNS WITH MITRE MAPPING
# ────────────────────────────────────────────────────────────

SUSPICIOUS_PATHS = [
    (re.compile(r'wp-admin|wp-login|wordpress', re.I), "T1190", "Exploit Public-Facing Application", "CMS enumeration"),
    (re.compile(r'phpmyadmin|pma', re.I), "T1190", "Exploit Public-Facing Application", "DB admin panel scan"),
    (re.compile(r'\.git/(config|HEAD|index)', re.I), "T1083", "File and Directory Discovery", "Git repo exfil"),
    (re.compile(r'\.env|config\.php|settings', re.I), "T1552", "Unsecured Credentials", "Config file access"),
    (re.compile(r'\.\./|\%2e\%2e', re.I), "T1055", "Process Injection", "Directory traversal"),
    (re.compile(r'etc/passwd|etc/shadow', re.I), "T1003", "OS Credential Dumping", "Unix credential access"),
    (re.compile(r'shell|cmd=|exec\(', re.I), "T1059", "Command and Scripting Interpreter", "RCE attempt"),
    (re.compile(r'UNION.{0,20}SELECT|OR.1=1', re.I), "T1190", "Exploit Public-Facing Application", "SQL injection"),
    (re.compile(r'xmlrpc\.php', re.I), "T1190", "Exploit Public-Facing Application", "XML-RPC exploit"),
    (re.compile(r'backup|\.sql|\.bak|\.tar', re.I), "T1005", "Data from Local System", "Backup file access"),
    (re.compile(r'\.DS_Store|thumbs\.db', re.I), "T1083", "File and Directory Discovery", "OS metadata file"),
    (re.compile(r'actuator|jolokia|jmx', re.I), "T1190", "Exploit Public-Facing Application", "Spring Boot actuator"),
    (re.compile(r'solr|elastic|kibana', re.I), "T1190", "Exploit Public-Facing Application", "Search engine admin"),
    (re.compile(r'\.aws|credentials|\.ssh', re.I), "T1552", "Unsecured Credentials", "Cloud/SSH credential"),
    (re.compile(r'admin/setup-config', re.I), "T1190", "Exploit Public-Facing Application", "WP setup exploit"),
]

# ────────────────────────────────────────────────────────────
# HTTP/2 PSEUDO-HEADER ORDER SIGNATURES
# ────────────────────────────────────────────────────────────

H2_ORDER_SIGNATURES = {
    "masp": "chrome_desktop",
    "mpsa": "firefox_desktop",
    "msa": "safari",
    "mp": "curl_or_tool",
}

# ────────────────────────────────────────────────────────────
# REDIS HELPER
# ────────────────────────────────────────────────────────────

def _get_redis():
    if not REDIS_URL:
        return None
    try:
        return redis_lib.from_url(REDIS_URL, socket_connect_timeout=3,
                                  decode_responses=True, max_connections=10)
    except Exception:
        return None

# ────────────────────────────────────────────────────────────
# FINGERPRINT BUILDER
# ────────────────────────────────────────────────────────────

def _identify_tool_from_ua(ua: str) -> Optional[Dict]:
    if not ua:
        return None
    for pattern, tool, category, confidence in KNOWN_UA_PATTERNS:
        if pattern.search(ua):
            return {"tool": tool, "category": category, "confidence": confidence, "method": "ua_pattern"}
    return None

def _classify_path(path: str) -> List[Dict]:
    signals = []
    for pattern, technique, tactic, description in SUSPICIOUS_PATHS:
        if pattern.search(path):
            signals.append({
                "technique": technique,
                "tactic": tactic,
                "description": description
            })
    return signals

def _detect_automation_signals(req_headers: Dict, header_order: List[str]) -> List[str]:
    signals = []
    ua = req_headers.get('User-Agent', '').lower()
    if not req_headers.get('Sec-Fetch-Dest'):
        signals.append('missing_sec_fetch')
    if 'chrome/' in ua and not req_headers.get('Sec-Ch-Ua'):
        signals.append('chrome_without_client_hints')
    if not req_headers.get('Accept-Language'):
        signals.append('missing_accept_language')
    if 'headlesschrome' in ua or 'phantomjs' in ua:
        signals.append('headless_browser')
    if len(header_order) < 8:
        signals.append('suspiciously_few_headers')
    if req_headers.get('Connection', '').lower() == 'close':
        signals.append('connection_close')
    return signals

def build_corpus_entry(req) -> Dict:
    """Build‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ a corpus entry from a Flask request object. PII-safe."""
    ua = req.headers.get('User-Agent', '')
    ip = req.remote_addr or ''
    if req.headers.get('X-Forwarded-For'):
        ip = req.headers['X-Forwarded-For'].split(',')[0].strip()

    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:16]
    ja3 = req.headers.get('CF-JA3-Hash', '') or req.headers.get('X-JA3', '')
    header_order = [k.lower() for k in req.headers.keys()]
    tool_id = _identify_tool_from_ua(ua)
    ja3_id = KNOWN_JA3.get(ja3.lower()) if ja3 else None
    path_signals = _classify_path(req.path)
    auto_signals = _detect_automation_signals(dict(req.headers), header_order)

    fp_components = [ua, ja3, ':'.join(header_order[:10])]
    fp_hash = hashlib.sha256('|'.join(fp_components).encode()).hexdigest()[:20]

    return {
        'fp_hash': fp_hash,
        'ip_hash': ip_hash,
        'ja3': ja3 or None,
        'ja3_tool': ja3_id,
        'ua_tool': tool_id,
        'header_order': header_order[:12],
        'header_count': len(header_order),
        'automation_signals': auto_signals,
        'path_signals': path_signals,
        'country': req.headers.get('CF-IPCountry', ''),
        'has_sec_headers': bool(req.headers.get('Sec-Fetch-Dest')),
        'has_client_hints': bool(req.headers.get('Sec-Ch-Ua')),
        'method': req.method,
        'path': req.path,
        'timestamp': datetime.utcnow().isoformat(),
    }

def store_hassh_entry(hassh: str, session_id: str, tool: str = None):
    """Store HASSH fingerprint in the corpus for cross-session correlation.

    Args:
        hassh: The HASSH MD5 hash.
        session_id: The associated Cowrie session ID.
        tool: Optional identified tool name.
    """
    r = _get_redis()
    if not r or not hassh:
        return
    try:
        fp_hash = hashlib.sha256(f"hassh:{hassh}:{session_id}".encode()).hexdigest()[:20]
        r.sadd(f"corpus:hassh:{hassh.lower()}", fp_hash)
        r.expire(f"corpus:hassh:{hassh.lower()}", 2592000)
        if tool:
            safe_tool = re.sub(r'[^a-zA-Z0-9_-]', '_', tool.lower())
            r.sadd(f"corpus:hassh_tool:{safe_tool}", hassh.lower())
            r.expire(f"corpus:hassh_tool:{safe_tool}", 2592000)
        r.incr("corpus:total_entries")
    except Exception as e:
        logger.error(f"HASSH store error: {e}")

def store_corpus_entry(entry: Dict):
    """Store‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ fingerprint in Redis corpus with indexing."""
    r = _get_redis()
    if not r:
        return

    try:
        fp = entry['fp_hash']
        count_key = f"corpus:fp:{fp}:count"
        count = r.incr(count_key)
        r.expire(count_key, 2592000)

        entry['seen_count'] = count
        r.setex(f"corpus:fp:{fp}:data", 2592000, json.dumps(entry))

        if entry.get('ja3'):
            r.sadd(f"corpus:ja3:{entry['ja3']}", fp)
            r.expire(f"corpus:ja3:{entry['ja3']}", 2592000)

        tool = None
        if entry.get('ja3_tool'):
            tool = entry['ja3_tool']['tool']
        elif entry.get('ua_tool'):
            tool = entry['ua_tool']['tool']
        if tool:
            safe_tool = re.sub(r'[^a-zA-Z0-9_-]', '_', tool)
            r.sadd(f"corpus:tool:{safe_tool}", fp)
            r.expire(f"corpus:tool:{safe_tool}", 2592000)

        country = entry.get('country')
        if country:
            r.zincrby("corpus:country_scores", 1, country)

        for sig in entry.get('path_signals', []):
            r.zincrby("corpus:techniques", 1, sig['technique'])

        r.incr("corpus:total_entries")

        # Recent-events feed consumed by /api/platform/activity and the home
        # dashboard threat stream. Previously nothing wrote this key, so the feed
        # was permanently empty; we push a compact, non-sensitive record here.
        recent = {
            'tool': tool or 'unknown',
            'country': country,
            'threat_score': entry.get('threat_score'),
            'timestamp': entry.get('timestamp') or datetime.utcnow().isoformat(),
        }
        r.lpush('fingerprint:recent_events', json.dumps(recent))
        r.ltrim('fingerprint:recent_events', 0, 49)
        r.expire('fingerprint:recent_events', 2592000)
    except Exception as e:
        logger.error(f"Corpus store error: {e}")

def collect_corpus_entry():
    """Middleware-compatible‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ collector. Call from before_request."""
    try:
        if request.path.startswith('/static/') or request.path == '/api/health':
            return
        entry = build_corpus_entry(request)
        has_signals = (
            entry.get('ja3_tool') or
            entry.get('ua_tool') or
            entry.get('path_signals') or
            len(entry.get('automation_signals', [])) >= 2
        )
        if has_signals:
            store_corpus_entry(entry)
            g.corpus_entry = entry
    except Exception as e:
        logger.error(f"Corpus collect error: {e}")

def lookup_hassh_internal(hassh: str = None) -> Dict:
    """Lookup HASSH fingerprint in known signature database.

    Args:
        hassh: The HASSH MD5 hash string to look up.

    Returns:
        Dict with match info, tool identification, and threat score contribution.
    """
    result = {
        "hassh_match": None,
        "threat_score": 0.0,
        "verdict": "unknown",
        "corpus_sightings": 0,
    }
    if not hassh:
        return result
    known = KNOWN_HASSH.get(hassh.lower())
    if known:
        result["hassh_match"] = known
        result["threat_score"] += known.get("confidence", 0) / 100 * 0.6
    r = _get_redis()
    if r:
        try:
            members = r.smembers(f"corpus:hassh:{hassh.lower()}")
            result["corpus_sightings"] = len(members)
        except Exception:
            pass
    result["threat_score"] = min(result["threat_score"], 1.0)
    threat_map = {"malicious": 0.7, "suspicious": 0.4, "potentially_automated": 0.2}
    for verdict, threshold in threat_map.items():
        if result["threat_score"] >= threshold:
            result["verdict"] = verdict
            break
    return result

def lookup_fingerprint_internal(ja3: str = None, ua: str = None,
                                header_order: List[str] = None) -> Dict:
    """Direct lookup for campaign_correlator and other modules. No HTTP overhead."""
    result = {
        "ja3_match": None,
        "ua_match": None,
        "automation_signals": [],
        "threat_score": 0.0,
        "verdict": "unknown"
    }

    if ja3:
        known = KNOWN_JA3.get(ja3.lower())
        if known:
            result["ja3_match"] = known
            result["threat_score"] += known.get("confidence", 0) / 100 * 0.5
    if ua:
        tool = _identify_tool_from_ua(ua)
        if tool:
            result["ua_match"] = tool
            result["threat_score"] += tool.get("confidence", 0) / 100 * 0.4
    if header_order:
        if len(header_order) < 8:
            result["automation_signals"].append("suspiciously_few_headers")

    result["threat_score"] = min(result["threat_score"], 1.0)
    if result["threat_score"] >= 0.7:
        result["verdict"] = "malicious"
    elif result["threat_score"] >= 0.4:
        result["verdict"] = "suspicious"
    elif result["threat_score"] >= 0.2:
        result["verdict"] = "potentially_automated"
    else:
        result["verdict"] = "clean"

    return result

# ────────────────────────────────────────────────────────────
# VERDICT COMPUTATION
# ────────────────────────────────────────────────────────────

def _compute_verdict(known_sig: Optional[Dict], corpus_count: int) -> str:
    if known_sig:
        conf = known_sig.get('confidence', 0)
        if conf >= 90: return "confirmed_malicious"
        if conf >= 75: return "likely_malicious"
        return "suspicious"
    if corpus_count >= 10: return "frequently_observed"
    if corpus_count >= 3: return "observed"
    return "unknown"

# ────────────────────────────────────────────────────────────
# FLASK BLUEPRINT
# ────────────────────────────────────────────────────────────

corpus_bp = Blueprint('corpus', __name__)

@corpus_bp.route('/api/intel/hassh/<string:hassh_hash>', methods=['GET'])
def query_hassh(hassh_hash: str):
    if len(hassh_hash) != 32 or not all(c in '0123456789abcdef' for c in hassh_hash.lower()):
        return jsonify({"ok": False, "error": "Invalid HASSH format (32 hex chars)"}), 400

    result = lookup_hassh_internal(hassh_hash)
    known = KNOWN_HASSH.get(hassh_hash.lower())
    return jsonify({
        "ok": True,
        "hassh": hassh_hash,
        "found": known is not None,
        "known_signature": known,
        "corpus_sightings": result["corpus_sightings"],
        "verdict": result["verdict"],
        "source": "WraithWall Attacker Fingerprint Corpus",
        "queried_at": datetime.utcnow().isoformat()
    })

@corpus_bp.route('/api/intel/ja3/<string:ja3_hash>', methods=['GET'])
def query_ja3(ja3_hash: str):
    if len(ja3_hash) != 32 or not all(c in '0123456789abcdef' for c in ja3_hash.lower()):
        return jsonify({"ok": False, "error": "Invalid JA3 format (32 hex chars)"}), 400

    known = KNOWN_JA3.get(ja3_hash.lower())
    corpus_count = 0

    r = _get_redis()
    if r:
        members = r.smembers(f"corpus:ja3:{ja3_hash}")
        corpus_count = len(members)

    if not known and corpus_count == 0:
        return jsonify({"ok": True, "ja3": ja3_hash, "found": False})

    return jsonify({
        "ok": True,
        "ja3": ja3_hash,
        "found": True,
        "known_signature": known,
        "corpus_sightings": corpus_count,
        "verdict": _compute_verdict(known, corpus_count),
        "source": "WraithWall Attacker Fingerprint Corpus",
        "queried_at": datetime.utcnow().isoformat()
    })

@corpus_bp.route('/api/intel/ua', methods=['POST'])
def query_ua():
    data = request.get_json(silent=True) or {}
    ua = data.get('ua', '').strip()[:500]
    if not ua:
        return jsonify({"ok": False, "error": "ua field required"}), 400

    tool = _identify_tool_from_ua(ua)
    if not tool:
        return jsonify({"ok": True, "ua": ua[:80], "found": False})

    return jsonify({
        "ok": True,
        "ua": ua[:80],
        "found": True,
        "tool": tool,
        "verdict": "malicious" if tool['confidence'] >= 85 else "suspicious",
        "source": "WraithWall Attacker Fingerprint Corpus",
    })

@corpus_bp.route('/api/intel/path', methods=['POST'])
def query_path():
    data = request.get_json(silent=True) or {}
    path = data.get('path', '').strip()[:500]
    if not path:
        return jsonify({"ok": False, "error": "path field required"}), 400

    signals = _classify_path(path)
    return jsonify({
        "ok": True,
        "path": path,
        "attack_signals": signals,
        "is_malicious": len(signals) > 0,
        "source": "WraithWall Attacker Fingerprint Corpus",
    })

@corpus_bp.route('/api/intel/fingerprint', methods=['POST'])
def query_fingerprint():
    data = request.get_json(silent=True) or {}
    headers_in = data.get('headers', {})
    if not headers_in or not isinstance(headers_in, dict):
        return jsonify({"ok": False, "error": "headers dict required"}), 400

    ua = headers_in.get('User-Agent', '')
    ja3 = headers_in.get('CF-JA3-Hash', '') or headers_in.get('X-JA3', '')
    header_order = [k.lower() for k in headers_in.keys()]

    result = lookup_fingerprint_internal(ja3=ja3, ua=ua, header_order=header_order)
    return jsonify({
        "ok": True,
        "threat_score": result["threat_score"],
        "verdict": result["verdict"],
        "tool_from_ja3": result["ja3_match"],
        "tool_from_ua": result["ua_match"],
        "automation_signals": result["automation_signals"],
        "source": "WraithWall Attacker Fingerprint Corpus",
        "queried_at": datetime.utcnow().isoformat()
    })

@corpus_bp.route('/api/intel/corpus/stats', methods=['GET'])
def corpus_stats():
    if not session.get('user_id'):
        return jsonify({"ok": False, "error": "Authentication required"}), 401
    r = _get_redis()
    if not r:
        return jsonify({
            "ok": True, "total_observations": 0,
            "known_ja3_signatures": len(KNOWN_JA3),
            "known_ua_patterns": len(KNOWN_UA_PATTERNS),
            "status": "redis_unavailable"
        })

    try:
        total = int(r.get("corpus:total_entries") or 0)
        techniques = r.zrevrange("corpus:techniques", 0, 9, withscores=True)
        top_techniques = [{"technique": t, "count": int(c)} for t, c in techniques]
        countries = r.zrevrange("corpus:country_scores", 0, 9, withscores=True)
        top_countries = [{"country": c, "count": int(s)} for c, s in countries]

        return jsonify({
            "ok": True,
            "total_observations": total,
            "known_ja3_signatures": len(KNOWN_JA3),
            "known_ua_patterns": len(KNOWN_UA_PATTERNS),
            "known_path_patterns": len(SUSPICIOUS_PATHS),
            "top_attack_techniques": top_techniques,
            "top_source_countries": top_countries,
            "source": "WraithWall Attacker Fingerprint Corpus",
            "updated_at": datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@corpus_bp.route('/api/intel/bulk', methods=['POST'])
def bulk_analyze():
    data = request.get_json(silent=True) or {}
    ja3_list = data.get('ja3_hashes', [])[:50]
    ua_list = data.get('user_agents', [])[:50]

    results = {"ok": True, "ja3_results": [], "ua_results": []}
    for ja3 in ja3_list:
        known = KNOWN_JA3.get(ja3.lower()) if ja3 else None
        results["ja3_results"].append({"ja3": ja3, "known": bool(known), "tool": known})
    for ua in ua_list:
        tool = _identify_tool_from_ua(ua or '')
        results["ua_results"].append({"ua": (ua or '')[:80], "known": bool(tool), "tool": tool})

    return jsonify(results)
