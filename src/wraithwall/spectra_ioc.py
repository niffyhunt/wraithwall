import hashlib
import json
import os
import re
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse

import redis as redis_lib

try:
    from publicsuffixlist import PublicSuffixList
    _PSL = PublicSuffixList()
    _HAS_PSL = True
except ImportError:
    _HAS_PSL = False
    _PSL = None

REDIS_URL = os.environ.get("REDIS_URL", "")
IOC_TTL = int(os.environ.get("SPECTRA_IOC_TTL", "2592000"))
MAX_CONTEXT_LENGTH = int(os.environ.get("SPECTRA_MAX_CONTEXT", "200"))
MAX_SESSION_IDS_PER_IOC = int(os.environ.get("SPECTRA_MAX_SESSIONS", "1000"))

IPV4_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")

IPV6_RE = re.compile(
    r"(?<![\w:])(?:"
    r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}"
    r"|[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}"
    r"|:(?::[0-9a-fA-F]{1,4}){1,7}|::"
    r")(?![\w:])"
)

DOMAIN_RE = re.compile(
    r"(?:(?:https?://|ftp://)?)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,}|xn--[a-zA-Z0-9]{2,})"
    r"(?::\d{1,5})?(?:/[^\s\"'<>]*)?",
    re.IGNORECASE,
)

URL_RE = re.compile(
    r"https?://(?:[^\s\"'<>(){}|\\^`\[\]]+)(?:\.[^\s\"'<>(){}|\\^`\[\]]+)+",
    re.IGNORECASE,
)

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z]{2,})+"
)

FILEPATH_RE = re.compile(
    r"(?<!/)(?:/(?!/)(?:[^\s\"'<>|/]+/)*[^\s\"'<>|/]+)"
    r"|(?:\.\.?/[^\s\"'<>|/]*)"
    r"|(?:~/[^\s\"'<>|/]*)"
)

BTC_ADDRESS_RE = re.compile(
    r"(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}"
)

ETH_ADDRESS_RE = re.compile(
    r"0x[a-fA-F0-9]{40}"
)

MONERO_ADDRESS_RE = re.compile(
    r"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}"
)

BASE64_CANDIDATE_RE = re.compile(
    r"[A-Za-z0-9+/]{40,}(?:={1,2})?"
)

DOMAIN_MIN_LENGTH = int(os.environ.get("SPECTRA_DOMAIN_MIN_LENGTH", "6"))
DOMAIN_MIN_DOTS = int(os.environ.get("SPECTRA_DOMAIN_MIN_DOTS", "2"))

SCRIPT_EXTENSIONS = frozenset({
    ".sh", ".pl", ".py", ".rb", ".js", ".php", ".asp", ".jsp",
    ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".exe", ".dll", ".so",
    ".bin", ".elf", ".ko", ".o",
})

LOCALHOST_PREFIXES = (
    "127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
    "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
    "172.30.", "172.31.", "192.168.", "169.254.", "0.",
)
PRIVATE_IP_PREFIXES = LOCALHOST_PREFIXES

def _get_redis() -> Optional[redis_lib.Redis]:
    if not REDIS_URL:
        return None
    try:
        return redis_lib.from_url(REDIS_URL, decode_responses=True, socket_connect_timeout=5, socket_timeout=5)
    except Exception:
        return None

def _validate_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            n = int(p)
            if n < 0 or n > 255:
                return False
        except ValueError:
            return False
    return True

def _is_private_ip(ip: str) -> bool:
    return ip.startswith(LOCALHOST_PREFIXES)

def _normalize_domain(raw: str) -> Optional[str]:
    parsed = urlparse(raw)
    domain = (parsed.netloc or raw.split("/")[0]).split(":")[0].lower()
    ext = os.path.splitext(domain)[1].lower()
    if ext in SCRIPT_EXTENSIONS and not raw.startswith(("http://", "https://", "ftp://")):
        return None
    if len(domain) < DOMAIN_MIN_LENGTH:
        return None
    if _HAS_PSL:
        suffix = _PSL.publicsuffix(domain)
        if not suffix or domain.count(".") <= suffix.count("."):
            return None
    else:
        if domain.count(".") < DOMAIN_MIN_DOTS:
            return None
    return domain

def _decode_base64_nested(text: str) -> List[str]:
    results: List[str] = []
    for match in BASE64_CANDIDATE_RE.finditer(text):
        candidate = match.group()
        try:
            import base64
            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            if any(c.isalpha() for c in decoded):
                results.extend(extract_iocs_from_text(decoded))
        except Exception:
            pass
    return results

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    iocs: Dict[str, List[str]] = {
        "ipv4": [],
        "ipv6": [],
        "domain": [],
        "url": [],
        "filepath": [],
        "email": [],
        "btc_address": [],
        "eth_address": [],
        "monero_address": [],
    }

    seen: Dict[str, Set[str]] = {k: set() for k in iocs}

    for match in IPV4_RE.finditer(text):
        ip = match.group()
        if _validate_ipv4(ip) and not _is_private_ip(ip):
            if ip not in seen["ipv4"]:
                seen["ipv4"].add(ip)
                iocs["ipv4"].append(ip)

    for match in IPV6_RE.finditer(text):
        ip = match.group().lower()
        if ip not in seen["ipv6"]:
            seen["ipv6"].add(ip)
            iocs["ipv6"].append(ip)

    for match in URL_RE.finditer(text):
        url = match.group().rstrip(".,;:!?")
        if url not in seen["url"]:
            seen["url"].add(url)
            iocs["url"].append(url)

    for match in DOMAIN_RE.finditer(text):
        domain = _normalize_domain(match.group())
        if domain and domain not in seen["domain"]:
            seen["domain"].add(domain)
            iocs["domain"].append(domain)

    for match in EMAIL_RE.finditer(text):
        email = match.group().lower()
        if email not in seen["email"]:
            seen["email"].add(email)
            iocs["email"].append(email)

    for match in FILEPATH_RE.finditer(text):
        fp = match.group().rstrip(".,;:!?")
        if len(fp) >= 3 and fp not in seen["filepath"]:
            seen["filepath"].add(fp)
            iocs["filepath"].append(fp)

    for match in BTC_ADDRESS_RE.finditer(text):
        addr = match.group()
        if addr not in seen["btc_address"]:
            seen["btc_address"].add(addr)
            iocs["btc_address"].append(addr)

    for match in ETH_ADDRESS_RE.finditer(text):
        addr = match.group().lower()
        if addr not in seen["eth_address"]:
            seen["eth_address"].add(addr)
            iocs["eth_address"].append(addr)

    for match in MONERO_ADDRESS_RE.finditer(text):
        addr = match.group()
        if addr not in seen["monero_address"]:
            seen["monero_address"].add(addr)
            iocs["monero_address"].append(addr)

    return iocs

def extract_iocs_from_session(session: Dict) -> Dict[str, List[str]]:
    merged: Dict[str, List[str]] = {}
    all_text_parts: List[str] = []

    commands = session.get("commands", [])
    for cmd in commands:
        if isinstance(cmd, str):
            all_text_parts.append(cmd)
        elif isinstance(cmd, dict):
            all_text_parts.append(cmd.get("input", "") or cmd.get("command", "") or "")

    downloads = session.get("downloads", [])
    for dl in downloads:
        if isinstance(dl, dict):
            for field in ("url", "filename", "content", "path"):
                val = dl.get(field)
                if val and isinstance(val, str):
                    all_text_parts.append(val)

    login_attempts = session.get("login_attempts", [])
    for la in login_attempts:
        if isinstance(la, dict):
            for field in ("username", "password"):
                val = la.get(field)
                if val and isinstance(val, str):
                    all_text_parts.append(val)

    for part in all_text_parts:
        extracted = extract_iocs_from_text(part)
        for ioc_type, values in extracted.items():
            if values:
                if ioc_type not in merged:
                    merged[ioc_type] = []
                seen = set(merged[ioc_type])
                for v in values:
                    if v not in seen:
                        seen.add(v)
                        merged[ioc_type].append(v)

    base64_nested: List[str] = []
    for part in all_text_parts:
        base64_nested.extend(_decode_base64_nested(part))
    for ioc in base64_nested:
        parts = ioc.split(":", 1)
        if len(parts) == 2:
            ioc_type, value = parts
            if ioc_type not in merged:
                merged[ioc_type] = []
            if value not in merged[ioc_type]:
                merged[ioc_type].append(value)

    return merged

def store_iocs(
    session_id: str,
    iocs: Dict[str, List[str]],
    context_text: str = "",
) -> int:
    r = _get_redis()
    if not r:
        return 0

    now = datetime.now(timezone.utc).isoformat()
    context_truncated = context_text[:MAX_CONTEXT_LENGTH] if context_text else ""
    total = 0
    session_ioc_keys: List[str] = []

    for ioc_type, values in iocs.items():
        if not values:
            continue
        for value in values:
            total += 1
            key = f"ioc:{ioc_type}:{value}"
            session_ioc_keys.append(key)
            stored = r.hgetall(key)
            if stored:
                existing_ids_str = stored.get("session_ids", "[]")
                try:
                    existing_ids = json.loads(existing_ids_str)
                except (json.JSONDecodeError, TypeError):
                    existing_ids = []
                if session_id not in existing_ids:
                    existing_ids.append(session_id)
                    if len(existing_ids) > MAX_SESSION_IDS_PER_IOC:
                        existing_ids = existing_ids[-MAX_SESSION_IDS_PER_IOC:]
                count = int(stored.get("count", 0)) + 1
                r.hset(key, mapping={
                    "session_ids": json.dumps(existing_ids),
                    "last_seen": now,
                    "count": count,
                    "context": context_truncated or stored.get("context", ""),
                    "first_seen": stored.get("first_seen", now),
                })
            else:
                r.hset(key, mapping={
                    "session_ids": json.dumps([session_id]),
                    "first_seen": now,
                    "last_seen": now,
                    "count": 1,
                    "context": context_truncated,
                })
            r.expire(key, IOC_TTL)

    if session_ioc_keys:
        session_key = f"session_iocs:{session_id}"
        r.sadd(session_key, *session_ioc_keys)
        r.expire(session_key, IOC_TTL)

    return total

def get_shared_iocs(session_ids: List[str], min_shared: int = 2) -> Dict[str, List[str]]:
    r = _get_redis()
    if not r:
        return {}

    if len(session_ids) < 2:
        return {}

    all_ioc_keys: Dict[str, int] = {}
    for sid in session_ids:
        members = r.smembers(f"session_iocs:{sid}")
        for key in members:
            ioc_type_value = key.replace("ioc:", "", 1) if key.startswith("ioc:") else key
            all_ioc_keys[key] = all_ioc_keys.get(key, 0) + 1

    shared: Dict[str, List[str]] = {}
    for key, count in all_ioc_keys.items():
        if count >= min_shared:
            parts = key.split(":", 2)
            if len(parts) >= 3:
                ioc_type = parts[1]
                value = parts[2]
                if ioc_type not in shared:
                    shared[ioc_type] = []
                shared[ioc_type].append(value)

    return shared

def get_session_ioc_count(session_id: str) -> int:
    r = _get_redis()
    if not r:
        return 0
    members = r.smembers(f"session_iocs:{session_id}")
    return len(members)

def get_session_ioc_diversity(session_id: str) -> int:
    r = _get_redis()
    if not r:
        return 0
    members = r.smembers(f"session_iocs:{session_id}")
    types: Set[str] = set()
    for key in members:
        parts = key.split(":", 2)
        if len(parts) >= 3:
            types.add(parts[1])
    return len(types)

def lookup_ioc(ioc_type: str, value: str) -> Optional[Dict[str, Any]]:
    r = _get_redis()
    if not r:
        return None
    data = r.hgetall(f"ioc:{ioc_type}:{value}")
    if not data:
        return None
    return {
        "ioc_type": ioc_type,
        "value": value,
        "session_ids": json.loads(data.get("session_ids", "[]")),
        "first_seen": data.get("first_seen", ""),
        "last_seen": data.get("last_seen", ""),
        "count": int(data.get("count", 0)),
        "context": data.get("context", ""),
    }
