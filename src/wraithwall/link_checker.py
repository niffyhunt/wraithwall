import os
import re
import json
import time
import hashlib
import logging
import ipaddress
from datetime import datetime, timedelta
from urllib.parse import urlparse, quote
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from flask import Blueprint, request, jsonify, g, Response, stream_with_context
 
logger = logging.getLogger(__name__)
 
# ─────────────────────────────────────────────────
# CONFIG — pulled from env, no fallback secrets
# ─────────────────────────────────────────────────
 
VT_API_KEY     = os.getenv('VIRUSTOTAL_API_KEY', '')
URLSCAN_KEY    = os.getenv('URLSCAN_API_KEY', '')
IPQS_KEY       = os.getenv('IPQS_API_KEY', '')
REDIS_URL      = os.getenv('REDIS_URL', '')
 
# Cache TTLs
VT_CACHE_TTL      = 3600        # 1 hour — VT results don't change fast
URLSCAN_CACHE_TTL = 1800        # 30 min
SCAN_RATE_WINDOW  = 60          # seconds
SCAN_RATE_LIMIT   = 10          # max scans per IP per window
DAILY_SCAN_LIMIT  = 100         # max scans per IP per day
 
# ─────────────────────────────────────────────────
# BLUEPRINT
# ─────────────────────────────────────────────────
 
link_checker_bp = Blueprint('link_checker', __name__)
 
# ─────────────────────────────────────────────────
# REDIS HELPER — singleton per request, graceful fallback
# ─────────────────────────────────────────────────
 
_redis_client = None
 
def get_redis():
    global _redis_client
    if not REDIS_URL:
        return None
    try:
        if _redis_client is None:
            import redis
            _redis_client = redis.from_url(REDIS_URL, socket_connect_timeout=2)
        _redis_client.ping()
        return _redis_client
    except Exception:
        _redis_client = None
        return None
 
 
# ─────────────────────────────────────────────────
# INPUT VALIDATION
# ─────────────────────────────────────────────────
 
_URL_RE = re.compile(
    r'^(https?://)?'
    r'(([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,})'
    r'(/[^\s]*)?$'
)
 
_HASH_RE = re.compile(r'^[a-fA-F0-9]{32,64}$')  # MD5, SHA1, SHA256
 
_IP_RE = re.compile(
    r'^(\d{1,3}\.){3}\d{1,3}$'
)
 
def validate_and_normalise(raw: str) -> tuple[str, str]:
    """
    Returns (normalised_value, input_type) or raises ValueError.
    input_type: 'url' | 'hash' | 'ip' | 'domain'
    """
    raw = raw.strip()[:2000]
 
    if not raw:
        raise ValueError("Empty input")
 
    # Hash?
    if _HASH_RE.match(raw):
        return raw.lower(), 'hash'
 
    # IP address?
    if _IP_RE.match(raw):
        try:
            addr = ipaddress.ip_address(raw)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                raise ValueError("Private/loopback IPs are not scannable")
            return raw, 'ip'
        except ValueError as e:
            raise ValueError(str(e))
 
    # URL or domain
    value = raw
    if not value.startswith(('http://', 'https://')):
        value = 'https://' + value
 
    parsed = urlparse(value)
    if not parsed.netloc:
        raise ValueError("Could not parse hostname from input")
 
    hostname = parsed.netloc.lower().split(':')[0]
 
    # Block localhost / private use
    private_hosts = {'localhost', '127.0.0.1', '0.0.0.0', '::1'}
    if hostname in private_hosts:
        raise ValueError("Local addresses cannot be scanned")
 
    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback:
            raise ValueError("Private IP addresses cannot be scanned")
    except ValueError:
        pass  # Not an IP — fine
 
    # Minimum domain structure
    if '.' not in hostname or len(hostname) < 4:
        raise ValueError("Invalid domain")
 
    input_type = 'url' if parsed.path and parsed.path != '/' else 'domain'
    return value, input_type
 
 
# ─────────────────────────────────────────────────
# RATE LIMITING
# ─────────────────────────────────────────────────
 
def _get_real_ip() -> str:
    """Get real IP, respecting Cloudflare/Nginx forwarding."""
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()
    xff = request.headers.get('X-Forwarded-For', '')
    if xff:
        return xff.split(',')[0].strip()
    return request.remote_addr or '0.0.0.0'
 
 
def _check_scan_rate(ip: str) -> tuple[bool, str]:
    """Returns (allowed, reason). Enforces burst + daily limits."""
    r = get_redis()
    if not r:
        return True, ""
 
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:20]
 
    # Burst: 10 scans per 60 seconds
    burst_key = f"lc_burst:{ip_hash}"
    try:
        burst = r.incr(burst_key)
        if burst == 1:
            r.expire(burst_key, SCAN_RATE_WINDOW)
        if burst > SCAN_RATE_LIMIT:
            ttl = r.ttl(burst_key)
            return False, f"Too many requests. Try again in {ttl}s."
    except Exception:
        pass
 
    # Daily: 100 scans per 24h
    daily_key = f"lc_daily:{ip_hash}"
    try:
        daily = r.incr(daily_key)
        if daily == 1:
            r.expire(daily_key, 86400)
        if daily > DAILY_SCAN_LIMIT:
            return False, "Daily scan limit reached. Resets in 24 hours."
    except Exception:
        pass
 
    return True, ""
 
 
def _get_daily_remaining(ip: str) -> int:
    r = get_redis()
    if not r:
        return DAILY_SCAN_LIMIT
    ip_hash = hashlib.sha256(ip.encode()).hexdigest()[:20]
    try:
        used = int(r.get(f"lc_daily:{ip_hash}") or 0)
        return max(0, DAILY_SCAN_LIMIT - used)
    except Exception:
        return DAILY_SCAN_LIMIT
 
 
# ─────────────────────────────────────────────────
# CACHE HELPERS
# ─────────────────────────────────────────────────
 
def _cache_key(prefix: str, value: str) -> str:
    h = hashlib.sha256(value.encode()).hexdigest()[:24]
    return f"lc_cache:{prefix}:{h}"
 
 
def _cache_get(key: str) -> Optional[dict]:
    r = get_redis()
    if not r:
        return None
    try:
        raw = r.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        return None
 
 
def _cache_set(key: str, data: dict, ttl: int):
    r = get_redis()
    if not r:
        return
    try:
        r.setex(key, ttl, json.dumps(data))
    except Exception:
        pass
 
 
# ─────────────────────────────────────────────────
# VIRUSTOTAL — URL, domain, hash, IP
# ─────────────────────────────────────────────────
 
VT_BASE = "https://www.virustotal.com/api/v3"
 
def _vt_headers() -> dict:
    return {"x-apikey": VT_API_KEY, "Accept": "application/json"}
 
 
def scan_virustotal(value: str, input_type: str) -> dict:
    """Query VT for URL, domain, hash, or IP. Returns normalised result dict."""
    if not VT_API_KEY:
        return {"ok": False, "error": "Threat intelligence service not configured", "source": "virustotal"}
 
    cache_key = _cache_key("vt", value)
    cached = _cache_get(cache_key)
    if cached:
        cached["cached"] = True
        return cached
 
    try:
        if input_type in ('url', 'domain'):
            # Step 1: Submit URL for scanning
            url_id = _vt_url_id(value)
            submit_resp = requests.post(
                f"{VT_BASE}/urls",
                headers={**_vt_headers(), "Content-Type": "application/x-www-form-urlencoded"},
                data=f"url={quote(value, safe='')}",
                timeout=15
            )
            if not submit_resp.ok:
                return {"ok": False, "error": f"VT submit error {submit_resp.status_code}", "source": "virustotal"}
 
            analysis_id = submit_resp.json().get("data", {}).get("id", "")
            if not analysis_id:
                # Try GET by URL ID instead
                get_resp = requests.get(
                    f"{VT_BASE}/urls/{url_id}",
                    headers=_vt_headers(), timeout=15
                )
                if not get_resp.ok:
                    return {"ok": False, "error": "VT lookup failed", "source": "virustotal"}
                raw = get_resp.json()
            else:
                # Step 2: Poll analysis result (up to 3 attempts)
                raw = None
                for attempt in range(3):
                    time.sleep(1.5 * (attempt + 1))
                    ar = requests.get(
                        f"{VT_BASE}/analyses/{analysis_id}",
                        headers=_vt_headers(), timeout=15
                    )
                    if ar.ok:
                        ar_data = ar.json()
                        status = ar_data.get("data", {}).get("attributes", {}).get("status")
                        if status == "completed":
                            # Now get the full URL report
                            gr = requests.get(
                                f"{VT_BASE}/urls/{url_id}",
                                headers=_vt_headers(), timeout=15
                            )
                            if gr.ok:
                                raw = gr.json()
                            break
                if not raw:
                    # Use analysis data as fallback
                    raw = ar.json() if ar.ok else {}
 
        elif input_type == 'hash':
            resp = requests.get(
                f"{VT_BASE}/files/{value}",
                headers=_vt_headers(), timeout=15
            )
            if not resp.ok:
                return {"ok": False, "error": f"Hash not found in VT database", "source": "virustotal"}
            raw = resp.json()
 
        elif input_type == 'ip':
            resp = requests.get(
                f"{VT_BASE}/ip_addresses/{value}",
                headers=_vt_headers(), timeout=15
            )
            if not resp.ok:
                return {"ok": False, "error": f"IP lookup failed", "source": "virustotal"}
            raw = resp.json()
 
        else:
            return {"ok": False, "error": "Unsupported input type", "source": "virustotal"}
 
        result = _vt_parse(raw, input_type, value)
        _cache_set(cache_key, result, VT_CACHE_TTL)
        return result
 
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "Threat intelligence service timed out", "source": "virustotal"}
    except Exception as e:
        logger.error(f"VT error: {e}")
        return {"ok": False, "error": str(e), "source": "virustotal"}
 
 
def _vt_url_id(url: str) -> str:
    """VT URL ID is base64url-encoded URL (no padding)."""
    import base64
    return base64.urlsafe_b64encode(url.encode()).rstrip(b'=').decode()
 
 
def _vt_parse(raw: dict, input_type: str, original: str) -> dict:
    """Normalise VT API response into our standard schema."""
    attrs = raw.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    results = attrs.get("last_analysis_results", {})
 
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    undetected = stats.get("undetected", 0)
    harmless   = stats.get("harmless", 0)
    total      = malicious + suspicious + undetected + harmless
 
    rated = malicious + suspicious + (undetected if undetected else harmless)
    score = round(((malicious + suspicious) / rated * 100)) if rated > 0 else 0
 
    verdict = "CLEAN"
    if malicious > 0:
        verdict = "MALICIOUS"
    elif suspicious > 0:
        verdict = "SUSPICIOUS"
 
    # Vendor breakdown
    vendors = []
    for engine, res in results.items():
        cat = (res.get("category") or res.get("result") or "undetected").lower()
        v_verdict = "clean"
        if cat in ("malicious", "phishing", "malware"):
            v_verdict = "malicious"
        elif cat in ("suspicious",):
            v_verdict = "suspicious"
        vendors.append({"name": engine, "verdict": v_verdict, "detail": res.get("result", "")})
 
    vendors.sort(key=lambda x: {"malicious": 0, "suspicious": 1, "clean": 2}.get(x["verdict"], 3))
 
    # Extra metadata by type
    meta = {}
    if input_type in ('url', 'domain'):
        meta["categories"] = attrs.get("categories", {})
        meta["reputation"]  = attrs.get("reputation", 0)
        meta["country"]     = attrs.get("country", "")
        meta["registrar"]   = attrs.get("registrar", "")
        meta["creation_date"] = attrs.get("creation_date", "")
        meta["tags"]        = attrs.get("tags", [])
    elif input_type == 'hash':
        meta["file_type"] = attrs.get("type_description", "")
        meta["file_name"] = (attrs.get("names") or ["unknown"])[0]
        meta["file_size"] = attrs.get("size", 0)
        meta["magic"]     = attrs.get("magic", "")
        meta["tags"]      = attrs.get("tags", [])
    elif input_type == 'ip':
        meta["country"]    = attrs.get("country", "")
        meta["asn"]        = attrs.get("asn", "")
        meta["as_owner"]   = attrs.get("as_owner", "")
        meta["reputation"] = attrs.get("reputation", 0)
        meta["network"]    = attrs.get("network", "")
 
    return {
        "ok":          True,
        "source":      "virustotal",
        "cached":      False,
        "input":       original,
        "input_type":  input_type,
        "verdict":     verdict,
        "score":       score,
        "stats": {
            "malicious":  malicious,
            "suspicious": suspicious,
            "clean":      undetected + harmless,
            "total":      total
        },
        "vendors": vendors,
        "meta":    meta,
        "scanned_at": datetime.utcnow().isoformat()
    }
 
 
# ─────────────────────────────────────────────────
# URLSCAN.IO
# ─────────────────────────────────────────────────
 
URLSCAN_BASE = "https://urlscan.io/api/v1"
 
def scan_urlscan(url: str) -> dict:
    """Submit URL to urlscan.io. Returns result URL and screenshot link."""
    if not URLSCAN_KEY:
        return {"ok": False, "error": "URLScan not configured", "source": "urlscan"}
 
    cache_key = _cache_key("us", url)
    cached = _cache_get(cache_key)
    if cached:
        cached["cached"] = True
        return cached
 
    try:
        # Submit
        sub = requests.post(
            f"{URLSCAN_BASE}/scan/",
            headers={
                "API-Key": URLSCAN_KEY,
                "Content-Type": "application/json"
            },
            json={"url": url, "visibility": "unlisted"},
            timeout=15
        )
 
        if sub.status_code == 429:
            return {"ok": False, "error": "URLScan rate limit reached", "source": "urlscan"}
 
        if not sub.ok:
            return {"ok": False, "error": f"URLScan submit error {sub.status_code}", "source": "urlscan"}
 
        sub_data = sub.json()
        scan_uuid = sub_data.get("uuid")
        result_url = sub_data.get("result")
        api_result_url = sub_data.get("api")
 
        if not scan_uuid:
            return {"ok": False, "error": "URLScan returned no scan ID", "source": "urlscan"}
 
        # Poll for result — up to 20s
        result_data = None
        for attempt in range(8):
            time.sleep(2.5)
            try:
                r = requests.get(
                    f"{URLSCAN_BASE}/result/{scan_uuid}/",
                    headers={"API-Key": URLSCAN_KEY},
                    timeout=10
                )
                if r.status_code == 200:
                    result_data = r.json()
                    break
                elif r.status_code == 404:
                    continue  # Still processing
            except Exception:
                continue
 
        if not result_data:
            # Scan submitted but result not ready — return partial
            result = {
                "ok":          True,
                "source":      "urlscan",
                "cached":      False,
                "status":      "pending",
                "result_url":  result_url,
                "scan_uuid":   scan_uuid,
                "screenshot":  None,
                "verdict":     "PENDING",
                "malicious":   None,
                "tags":        [],
                "scanned_at":  datetime.utcnow().isoformat()
            }
            _cache_set(cache_key, result, 300)  # Short cache for pending
            return result
 
        page   = result_data.get("page", {})
        lists  = result_data.get("lists", {})
        verdicts = result_data.get("verdicts", {}).get("overall", {})
        screenshot = result_data.get("task", {}).get("screenshotURL", "")
 
        malicious_score = verdicts.get("score", 0)
        is_malicious    = verdicts.get("malicious", False)
        tags            = verdicts.get("tags", [])
 
        verdict = "MALICIOUS" if is_malicious else ("SUSPICIOUS" if malicious_score > 50 else "CLEAN")
 
        result = {
            "ok":           True,
            "source":       "urlscan",
            "cached":       False,
            "status":       "complete",
            "result_url":   result_url,
            "scan_uuid":    scan_uuid,
            "screenshot":   screenshot,
            "verdict":      verdict,
            "malicious":    is_malicious,
            "score":        malicious_score,
            "tags":         tags,
            "page": {
                "url":    page.get("url", url),
                "domain": page.get("domain", ""),
                "ip":     page.get("ip", ""),
                "city":   page.get("city", ""),
                "country": page.get("country", ""),
                "server": page.get("server", ""),
                "mime":   page.get("mimeType", ""),
                "title":  page.get("title", ""),
                "tls_valid": page.get("tlsValidDays", 0),
                "tls_issuer": page.get("tlsIssuer", ""),
            },
            "stats": {
                "ips":        len(lists.get("ips", [])),
                "domains":    len(lists.get("domains", [])),
                "urls":       len(lists.get("urls", [])),
                "js_scripts": len(lists.get("scripts", [])),
            },
            "scanned_at": datetime.utcnow().isoformat()
        }
 
        _cache_set(cache_key, result, URLSCAN_CACHE_TTL)
        return result
 
    except requests.exceptions.Timeout:
        return {"ok": False, "error": "URLScan timed out", "source": "urlscan"}
    except Exception as e:
        logger.error(f"URLScan error: {e}")
        return {"ok": False, "error": str(e), "source": "urlscan"}
 
 
# ─────────────────────────────────────────────────
# IPQS — optional fraud/proxy scoring
# ─────────────────────────────────────────────────
 
def scan_ipqs_url(url: str) -> Optional[dict]:
    """IPQS URL fraud scoring. Optional — only if IPQS_API_KEY set."""
    if not IPQS_KEY:
        return None
 
    cache_key = _cache_key("ipqs", url)
    cached = _cache_get(cache_key)
    if cached:
        return cached
 
    try:
        encoded = quote(url, safe='')
        resp = requests.get(
            f"https://www.ipqualityscore.com/api/json/url/{IPQS_KEY}/{encoded}",
            timeout=10
        )
        if not resp.ok:
            return None
 
        data = resp.json()
        result = {
            "ok":            True,
            "source":        "ipqs",
            "phishing":      data.get("phishing", False),
            "malware":       data.get("malware", False),
            "suspicious":    data.get("suspicious", False),
            "risk_score":    data.get("risk_score", 0),
            "spamming":      data.get("spamming", False),
            "adult":         data.get("adult", False),
            "domain_rank":   data.get("domain_rank", 0),
            "dns_valid":     data.get("dns_valid", True),
            "parking":       data.get("parking", False),
            "category":      data.get("category", ""),
        }
        _cache_set(cache_key, result, 3600)
        return result
    except Exception:
        return None
 
 
# ─────────────────────────────────────────────────
# ADDITIONAL INTELLIGENCE SOURCES
# (aggregated into the unified verdict; vendor names are
#  withheld from the client — results are white-labeled)
# ─────────────────────────────────────────────────

ABUSEIPDB_KEY = os.getenv('ABUSEIPDB_API_KEY', '')
WHOIS_KEY     = os.getenv('WHOISXML_API_KEY', '') or os.getenv('WHOIS_API_KEY', '')
URLHAUS_KEY   = os.getenv('URLHAUS_API_KEY', '')

_SUSPICIOUS_TLDS = {
    'zip', 'mov', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'work', 'click',
    'link', 'country', 'kim', 'science', 'party', 'gdn', 'review', 'stream',
    'download', 'loan', 'rest', 'fit', 'cam', 'quest', 'sbs'
}
_PHISH_KEYWORDS = ('login', 'verify', 'secure', 'account', 'update', 'bank',
                   'wallet', 'confirm', 'signin', 'password', 'webscr')

def _resolve_ip(host: str) -> str:
    """Best-effort DNS resolution. Returns '' on failure."""
    if not host:
        return ''
    try:
        import socket
        return socket.gethostbyname(host)
    except Exception:
        return ''

def scan_abuseipdb(ip: str) -> Optional[dict]:
    """IP abuse confidence (AbuseIPDB). Needs a resolved public IP."""
    if not ABUSEIPDB_KEY or not ip:
        return None
    cache_key = _cache_key("abuse", ip)
    cached = _cache_get(cache_key)
    if cached:
        cached["cached"] = True
        return cached
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=6
        )
        if not resp.ok:
            return None
        d = resp.json().get("data", {}) or {}
        score = int(d.get("abuseConfidenceScore", 0) or 0)
        result = {
            "ok": True, "source": "abuseipdb", "cached": False,
            "abuse_score": score,
            "total_reports": d.get("totalReports", 0),
            "is_tor": d.get("isTor", False),
            "usage_type": d.get("usageType", ""),
            "verdict": "MALICIOUS" if score >= 50 else ("SUSPICIOUS" if score >= 20 else "CLEAN"),
            "score": score,
        }
        _cache_set(cache_key, result, 3600)
        return result
    except Exception:
        return None

def scan_urlhaus(host: str) -> Optional[dict]:
    """abuse.ch URLhaus host lookup — known malware-distribution hosts."""
    if not host:
        return None
    try:
        headers = {}
        if URLHAUS_KEY:
            headers["Auth-Key"] = URLHAUS_KEY
        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": host}, headers=headers, timeout=6
        )
        if not resp.ok:
            return None
        d = resp.json()
        status = d.get("query_status")
        if status == "no_results":
            return {"ok": True, "source": "urlhaus", "listed": False,
                    "verdict": "CLEAN", "score": 0, "count": 0, "online": 0}
        if status != "ok":
            return None
        urls = d.get("urls", []) or []
        online = sum(1 for u in urls if u.get("url_status") == "online")
        listed = len(urls) > 0
        return {
            "ok": True, "source": "urlhaus", "listed": listed,
            "count": len(urls), "online": online,
            "verdict": "MALICIOUS" if online > 0 else ("SUSPICIOUS" if listed else "CLEAN"),
            "score": 90 if online > 0 else (60 if listed else 0),
        }
    except Exception:
        return None

def scan_domain_age(host: str) -> Optional[dict]:
    """Newly-registered-domain heuristic via WHOIS. Recent registration = risk."""
    if not WHOIS_KEY or not host:
        return None
    # Skip raw IPs
    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass
    cache_key = _cache_key("age", host)
    cached = _cache_get(cache_key)
    if cached:
        cached["cached"] = True
        return cached
    try:
        resp = requests.get(
            "https://www.whoisxmlapi.com/whoisserver/WhoisService",
            params={"apiKey": WHOIS_KEY, "domainName": host, "outputFormat": "JSON"},
            timeout=8
        )
        if not resp.ok:
            return None
        rec = (resp.json() or {}).get("WhoisRecord", {}) or {}
        reg = rec.get("registryData", {}) or {}
        age_days = rec.get("estimatedDomainAge")
        created = rec.get("createdDate") or reg.get("createdDate")
        if age_days is None and not created:
            return None
        try:
            age_days = int(age_days) if age_days is not None else None
        except Exception:
            age_days = None
        verdict, score = "CLEAN", 0
        if age_days is not None:
            if age_days < 30:
                verdict, score = "SUSPICIOUS", 55
            elif age_days < 90:
                verdict, score = "SUSPICIOUS", 30
        result = {
            "ok": True, "source": "domain_age", "cached": False,
            "age_days": age_days, "created": created,
            "verdict": verdict, "score": score,
        }
        _cache_set(cache_key, result, 86400)
        return result
    except Exception:
        return None

def scan_heuristics(value: str, input_type: str) -> dict:
    """Always-on local URL/domain structure heuristics — no external API."""
    host, path = "", ""
    try:
        p = urlparse(value if '://' in value else 'https://' + value)
        host = (p.netloc or '').lower().split(':')[0]
        path = p.path or ''
    except Exception:
        host = value.lower()

    reasons, score = [], 0
    try:
        ipaddress.ip_address(host)
        reasons.append("Raw IP address used as hostname")
        score += 25
    except ValueError:
        pass
    if 'xn--' in host:
        reasons.append("Internationalized (punycode) domain")
        score += 20
    if host.count('.') >= 4:
        reasons.append("Unusually deep subdomain nesting")
        score += 15
    tld = host.rsplit('.', 1)[-1] if '.' in host else ''
    if tld in _SUSPICIOUS_TLDS:
        reasons.append("High-abuse top-level domain")
        score += 20
    if '@' in value:
        reasons.append("Embedded credentials (@) in URL")
        score += 20
    if len(value) > 100:
        reasons.append("Abnormally long URL")
        score += 10
    low_path = path.lower()
    if any(kw in low_path for kw in _PHISH_KEYWORDS):
        reasons.append("Phishing-associated keyword in URL path")
        score += 10
    score = min(score, 100)
    return {
        "ok": True, "source": "heuristics", "score": score,
        "verdict": "SUSPICIOUS" if score >= 30 else "CLEAN",
        "reasons": reasons,
    }

# ─────────────────────────────────────────────────
# UNIFIED SCAN — combines all sources
# ─────────────────────────────────────────────────

def analyze(raw_input: str) -> dict:
    """Public API: validate and scan a URL, domain, IP address, or file hash."""
    return run_full_scan(raw_input)


def run_full_scan(raw_input: str) -> dict:
    """
    Full scan pipeline: validate → VT → URLScan (if URL) → IPQS (if URL).
    Returns unified result object ready for the frontend.
    """
    try:
        value, input_type = validate_and_normalise(raw_input)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
 
    result = {
        "ok":          True,
        "input":       value,
        "input_type":  input_type,
        "virustotal":  None,
        "urlscan":     None,
        "ipqs":        None,
        "abuseipdb":   None,
        "urlhaus":     None,
        "domain_age":  None,
        "heuristics":  None,
        "summary":     {},
        "scanned_at":  datetime.utcnow().isoformat()
    }

    # Derive hostname + best-effort IP for the host-based sources
    host = ''
    try:
        p = urlparse(value if '://' in value else 'https://' + value)
        host = (p.netloc or '').lower().split(':')[0]
    except Exception:
        host = ''
    ip_for_abuse = value if input_type == 'ip' else (_resolve_ip(host) if host else '')

    is_web = input_type in ('url', 'domain')

    # Always-on local heuristics (no network)
    if is_web:
        result["heuristics"] = scan_heuristics(value, input_type)

    # Fan out every external source concurrently — the single worker would
    # otherwise serialise these and block the whole app for ~minute.
    with ThreadPoolExecutor(max_workers=6) as ex:
        futs = {'vt': ex.submit(scan_virustotal, value, input_type)}
        if is_web:
            futs['us']      = ex.submit(scan_urlscan, value)
            futs['ipqs']    = ex.submit(scan_ipqs_url, value)
            futs['urlhaus'] = ex.submit(scan_urlhaus, host)
            futs['age']     = ex.submit(scan_domain_age, host)
        if ip_for_abuse:
            futs['abuse'] = ex.submit(scan_abuseipdb, ip_for_abuse)
        done = {}
        for key, fut in futs.items():
            try:
                done[key] = fut.result()
            except Exception:
                done[key] = None

    result["virustotal"] = done.get('vt')
    result["urlscan"]    = done.get('us')
    result["ipqs"]       = done.get('ipqs')
    result["urlhaus"]    = done.get('urlhaus')
    result["domain_age"] = done.get('age')
    result["abuseipdb"]  = done.get('abuse')

    # Build summary verdict from all sources
    result["summary"] = _build_summary(result)

    return result
 
 
def _build_summary(result: dict) -> dict:
    """Combine signals from every source into one white-labeled threat summary.

    Vendor names are deliberately NOT exposed to the client — only an
    aggregate verdict, blended score, source count and generic flags.
    """
    verdicts, scores, flags = [], [], []
    source_count = 0

    vt    = result.get("virustotal") or {}
    us    = result.get("urlscan")    or {}
    ipqs  = result.get("ipqs")       or {}
    abuse = result.get("abuseipdb")  or {}
    uh    = result.get("urlhaus")    or {}
    age   = result.get("domain_age") or {}
    heur  = result.get("heuristics") or {}

    if vt.get("ok"):
        source_count += 1
        verdicts.append(vt.get("verdict", "UNKNOWN"))
        scores.append(vt.get("score", 0))
        m = vt.get("stats", {}).get("malicious", 0)
        if m > 0:
            flags.append(f"Flagged malicious by {m} reputation engine{'s' if m != 1 else ''}")

    if us.get("ok") and us.get("status") == "complete":
        source_count += 1
        verdicts.append(us.get("verdict", "UNKNOWN"))
        scores.append(us.get("score", 0))
        if us.get("malicious"):
            flags.append("Live sandbox detonation flagged the page as malicious")

    if ipqs.get("ok"):
        source_count += 1
        scores.append(ipqs.get("risk_score", 0))
        if ipqs.get("phishing") or ipqs.get("malware"):
            verdicts.append("MALICIOUS")
            flags.append("Fraud scoring detected phishing or malware")
        elif ipqs.get("suspicious"):
            verdicts.append("SUSPICIOUS")

    if abuse.get("ok"):
        source_count += 1
        verdicts.append(abuse.get("verdict", "CLEAN"))
        scores.append(abuse.get("score", 0))
        if abuse.get("abuse_score", 0) >= 20:
            flags.append(f"Hosting IP has elevated abuse history ({abuse['abuse_score']}%)")
        if abuse.get("is_tor"):
            flags.append("Hosted behind a Tor exit node")

    if uh.get("ok"):
        source_count += 1
        verdicts.append(uh.get("verdict", "CLEAN"))
        scores.append(uh.get("score", 0))
        if uh.get("online"):
            flags.append("Host serves live malware payloads (threat feed)")
        elif uh.get("listed"):
            flags.append("Host appears on a malware-distribution feed")

    if age.get("ok"):
        source_count += 1
        verdicts.append(age.get("verdict", "CLEAN"))
        scores.append(age.get("score", 0))
        ad = age.get("age_days")
        if ad is not None and ad < 90:
            flags.append(f"Domain registered recently ({ad} days ago)")

    if heur.get("ok"):
        source_count += 1
        verdicts.append(heur.get("verdict", "CLEAN"))
        scores.append(heur.get("score", 0))
        for reason in heur.get("reasons", [])[:3]:
            flags.append(reason)

    # Worst-case verdict wins
    final_verdict = "CLEAN"
    if "MALICIOUS" in verdicts:
        final_verdict = "MALICIOUS"
    elif "SUSPICIOUS" in verdicts:
        final_verdict = "SUSPICIOUS"
    elif not verdicts:
        final_verdict = "UNKNOWN"

    avg_score = round(sum(scores) / len(scores)) if scores else 0
    peak_score = max(scores) if scores else 0
    # Surface the peak when something is wrong so a clean majority can't mask it
    display_score = peak_score if final_verdict in ("MALICIOUS", "SUSPICIOUS") else avg_score

    # De-duplicate flags while preserving order
    seen = set()
    deduped = [f for f in flags if not (f in seen or seen.add(f))]

    return {
        "verdict":      final_verdict,
        "score":        display_score,
        "source_count": source_count,
        "sources_used": [],   # intentionally empty — vendor identities withheld
        "flags":        deduped[:8],
        "cached":       any([
            vt.get("cached", False),
            us.get("cached", False) if us else False,
            abuse.get("cached", False),
            age.get("cached", False),
        ])
    }
 
 
# ─────────────────────────────────────────────────
# FLASK ROUTES
# ─────────────────────────────────────────────────
 
def _rate_check_response(ip: str):
    """Returns a 429 JSONified response if rate limited, else None."""
    allowed, reason = _check_scan_rate(ip)
    if not allowed:
        return jsonify({
            "ok": False,
            "error": reason,
            "remaining": 0
        }), 429
    return None
 
 
@link_checker_bp.route('/api/link/scan', methods=['POST'])
def api_link_scan():
    """
    Unified scan endpoint. Accepts URL, domain, hash, or IP.
    Body: {"url": "..."} or {"input": "..."}
    Returns full combined result.
    """
    ip = _get_real_ip()
    rate_err = _rate_check_response(ip)
    if rate_err:
        return rate_err
 
    data = request.get_json(silent=True) or {}
    raw = (data.get("url") or data.get("input") or "").strip()
 
    if not raw:
        return jsonify({"ok": False, "error": "url or input field required"}), 400
 
    if len(raw) > 2000:
        return jsonify({"ok": False, "error": "Input too long"}), 400
 
    result = run_full_scan(raw)
    result["remaining"] = _get_daily_remaining(ip)

    # Log to immutable log — hashed only, no raw URLs
    _log_scan(ip, raw, result.get("summary", {}).get("verdict", "UNKNOWN"))

    # Record public activity for the landing page feed
    try:
        from public_api import record_public_activity
        summary = result.get("summary", {})
        record_public_activity("scan", raw, {
            "verdict": summary.get("verdict", "unknown"),
            "score": summary.get("score", 0),
            "engines": summary.get("source_count", 0),
        })
    except Exception:
        pass

    status = 200 if result.get("ok") else 400
    return jsonify(result), status

def _source_brief(key: str, data: Optional[dict]) -> dict:
    """Compact, white-labeled status for one source — drives the live grid.

    Vendor identities are never derived here; only an aggregate verdict + score
    per generic source category, plus the source's own payload for the rich
    evidence panels (which the frontend renders without naming providers).
    """
    d = data or {}
    ok = bool(d.get("ok"))
    verdict = d.get("verdict")
    score = d.get("score")

    if key == "ipqs" and ok:
        verdict = "MALICIOUS" if (d.get("phishing") or d.get("malware")) \
            else ("SUSPICIOUS" if d.get("suspicious") else "CLEAN")
        score = d.get("risk_score", 0)
    elif key == "urlscan":
        # urlscan can return ok=True with status 'pending' (not yet rendered)
        if ok and d.get("status") != "complete":
            return {"ok": False, "pending": True, "verdict": "PENDING",
                    "score": 0, "data": d}

    return {
        "ok": ok,
        "pending": False,
        "verdict": verdict or ("CLEAN" if ok else "UNKNOWN"),
        "score": score if score is not None else 0,
        "data": d,
    }

@link_checker_bp.route('/api/link/scan/stream', methods=['GET'])
def api_link_scan_stream():
    """Server-Sent Events scan: emits each source result the moment it resolves
    so the operator console renders live progress instead of one blocking dump.

    Same validation, rate limits and logging as /api/link/scan. EventSource only
    issues GET, so input arrives via ?url= / ?input= query params. GET is exempt
    from the JSON-origin gate, so no extra header is needed.
    """
    ip = _get_real_ip()
    raw = (request.args.get("url") or request.args.get("input") or "").strip()

    def sse(event: str, payload: dict) -> str:
        return f"event: {event}\ndata: {json.dumps(payload)}\n\n"

    @stream_with_context
    def generate():
        allowed, reason = _check_scan_rate(ip)
        if not allowed:
            yield sse("error", {"ok": False, "error": reason, "remaining": 0})
            return
        if not raw:
            yield sse("error", {"ok": False, "error": "url or input field required"})
            return
        if len(raw) > 2000:
            yield sse("error", {"ok": False, "error": "Input too long"})
            return
        try:
            value, input_type = validate_and_normalise(raw)
        except ValueError as e:
            yield sse("error", {"ok": False, "error": str(e)})
            return

        is_web = input_type in ('url', 'domain')
        host = ''
        try:
            p = urlparse(value if '://' in value else 'https://' + value)
            host = (p.netloc or '').lower().split(':')[0]
        except Exception:
            host = ''
        ip_for_abuse = value if input_type == 'ip' else (_resolve_ip(host) if host else '')

        result = {
            "ok": True, "input": value, "input_type": input_type,
            "virustotal": None, "urlscan": None, "ipqs": None,
            "abuseipdb": None, "urlhaus": None, "domain_age": None,
            "heuristics": None, "summary": {},
            "scanned_at": datetime.utcnow().isoformat(),
        }

        planned = ['heuristics', 'virustotal'] if is_web else ['virustotal']
        if is_web:
            planned += ['urlscan', 'ipqs', 'urlhaus', 'domain_age']
        if ip_for_abuse:
            planned.append('abuseipdb')

        yield sse("start", {"input": value, "input_type": input_type,
                            "sources": planned, "ip": ip_for_abuse or None})

        # Local heuristics resolve instantly — emit before the network fan-out
        if is_web:
            result["heuristics"] = scan_heuristics(value, input_type)
            yield sse("source", {"key": "heuristics", **_source_brief("heuristics", result["heuristics"])})

        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(scan_virustotal, value, input_type): 'virustotal'}
            if is_web:
                futs[ex.submit(scan_urlscan, value)]   = 'urlscan'
                futs[ex.submit(scan_ipqs_url, value)]  = 'ipqs'
                futs[ex.submit(scan_urlhaus, host)]    = 'urlhaus'
                futs[ex.submit(scan_domain_age, host)] = 'domain_age'
            if ip_for_abuse:
                futs[ex.submit(scan_abuseipdb, ip_for_abuse)] = 'abuseipdb'

            for fut in as_completed(futs):
                key = futs[fut]
                try:
                    data = fut.result()
                except Exception:
                    data = None
                result[key] = data
                yield sse("source", {"key": key, **_source_brief(key, data)})

        result["summary"] = _build_summary(result)
        remaining = _get_daily_remaining(ip)
        result["remaining"] = remaining
        try:
            _log_scan(ip, raw, result["summary"].get("verdict", "UNKNOWN"))
        except Exception:
            pass

        try:
            from public_api import record_public_activity
            summary = result.get("summary", {})
            record_public_activity("scan", raw, {
                "verdict": summary.get("verdict", "unknown"),
                "score": summary.get("score", 0),
                "engines": summary.get("source_count", 0),
            })
        except Exception:
            pass

        yield sse("summary", {"summary": result["summary"], "remaining": remaining, "result": result})
        yield sse("done", {"ok": True})

    return Response(generate(), mimetype='text/event-stream', headers={
        'Cache-Control': 'no-cache',
        'X-Accel-Buffering': 'no',   # disable nginx buffering so events flush live
        'Connection': 'keep-alive',
    })

@link_checker_bp.route('/api/virustotal', methods=['POST'])
def api_virustotal_compat():
    """
    Backwards-compatible VirusTotal endpoint.
    Neon Sentinel calls this — keep it working.
    Body: {"url": "..."}
    """
    ip = _get_real_ip()
    rate_err = _rate_check_response(ip)
    if rate_err:
        return rate_err
 
    data = request.get_json(silent=True) or {}
    raw = (data.get("url") or data.get("input") or "").strip()
 
    if not raw:
        return jsonify({"ok": False, "error": "url required"}), 400
 
    try:
        value, input_type = validate_and_normalise(raw)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
 
    vt_result = scan_virustotal(value, input_type)
 
    # Return in the flat format Neon Sentinel expects
    if not vt_result.get("ok"):
        return jsonify({"error": vt_result.get("error")}), 502
 
    flat = {
        "last_analysis_stats":   {
            "malicious":  vt_result["stats"]["malicious"],
            "suspicious": vt_result["stats"]["suspicious"],
            "undetected": vt_result["stats"]["clean"],
            "harmless":   0
        },
        "last_analysis_results": {
            v["name"]: {"category": v["verdict"], "result": v.get("detail", "")}
            for v in vt_result.get("vendors", [])
        },
        "reputation":  vt_result.get("meta", {}).get("reputation", 0),
        "tags":        vt_result.get("meta", {}).get("tags", []),
        "verdict":     vt_result["verdict"],
        "score":       vt_result["score"],
        "cached":      vt_result.get("cached", False),
        "remaining":   _get_daily_remaining(ip)
    }
    _log_scan(ip, raw, vt_result["verdict"])
    return jsonify(flat)
 
 
@link_checker_bp.route('/api/urlscan', methods=['POST'])
def api_urlscan_compat():
    """
    Backwards-compatible URLScan endpoint.
    Neon Sentinel calls this — keep it working.
    Body: {"url": "..."}
    """
    ip = _get_real_ip()
    rate_err = _rate_check_response(ip)
    if rate_err:
        return rate_err
 
    data = request.get_json(silent=True) or {}
    raw = (data.get("url") or "").strip()
 
    if not raw:
        return jsonify({"ok": False, "error": "url required"}), 400
 
    try:
        value, input_type = validate_and_normalise(raw)
    except ValueError as e:
        return jsonify({"ok": False, "error": str(e)}), 400
 
    if input_type not in ('url', 'domain'):
        return jsonify({"ok": False, "error": "URLScan only supports URLs and domains"}), 400
 
    us_result = scan_urlscan(value)
 
    if not us_result.get("ok"):
        return jsonify({"error": us_result.get("error")}), 502
 
    # Neon Sentinel only uses result_url from this endpoint
    return jsonify({
        "result_url":  us_result.get("result_url"),
        "api_response": {"result": us_result.get("result_url")},
        "screenshot":  us_result.get("screenshot"),
        "verdict":     us_result.get("verdict"),
        "status":      us_result.get("status"),
        "cached":      us_result.get("cached", False)
    })
 
 
@link_checker_bp.route('/api/link/status', methods=['GET'])
def api_link_status():
    """Health + rate limit status for the current IP."""
    ip = _get_real_ip()
    remaining = _get_daily_remaining(ip)
    return jsonify({
        "ok":            True,
        "vt_configured": bool(VT_API_KEY),
        "us_configured": bool(URLSCAN_KEY),
        "iq_configured": bool(IPQS_KEY),
        "remaining":     remaining,
        "daily_limit":   DAILY_SCAN_LIMIT
    })
 
 
# ─────────────────────────────────────────────────
# INTERNAL LOGGING
# ─────────────────────────────────────────────────
 
def _log_scan(ip: str, raw_input: str, verdict: str):
    """Log to immutable log — hashed values only."""
    try:

        write_immutable_log({
            "event":        "link_scan",
            "ip_hash":      hashlib.sha256(ip.encode()).hexdigest()[:16],
            "input_hash":   hashlib.sha256(raw_input.encode()).hexdigest()[:16],
            "verdict":      verdict,
            "timestamp":    datetime.utcnow().isoformat()
        })
    except Exception:
        pass
 
    # Store verdict stats in Redis for admin dashboard
    r = get_redis()
    if r:
        try:
            date_key = datetime.utcnow().strftime("%Y%m%d")
            r.hincrby(f"lc_stats:{date_key}", verdict, 1)
            r.hincrby(f"lc_stats:{date_key}", "total", 1)
            r.expire(f"lc_stats:{date_key}", 86400 * 7)
        except Exception:
            pass
