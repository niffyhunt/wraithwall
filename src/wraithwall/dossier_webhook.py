"""Outbound dossier webhook: HMAC over exact bytes, SSRF block, replay window."""
from __future__ import annotations

import hmac
import hashlib
import ipaddress
import json
import os
import socket
import time
from typing import Optional
from urllib.parse import urlparse

BLOCKED_HOSTS = {"localhost", "metadata.google.internal", "metadata"}
BLOCKED_NETS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)
ALLOWED_PORTS = {443, 80, 8443}
REPLAY_WINDOW = 300
SECRETS_PATH = "/opt/wraithwall-secrets/.webhook_secrets"


def _ip_blocked(ip: "ipaddress._BaseAddress") -> bool:
    """Net-block check including IPv4 embedded inside IPv6 addresses.

    ``::ffff:127.0.0.1`` parses as a global IPv6Address, so a plain
    ``ip in ip_network('127.0.0.0/8')`` check is a bypass. Unwrap the
    embedded IPv4 (mapped / 6to4 / Teredo) before evaluating BLOCKED_NETS.
    """
    candidates = [ip]
    if isinstance(ip, ipaddress.IPv6Address):
        mapped = ip.ipv4_mapped
        if mapped is not None:
            candidates.append(mapped)
        stf = ip.sixtofour
        if stf is not None:
            candidates.append(stf)
        teredo = ip.teredo
        if teredo is not None:
            candidates.extend(teredo)
    for cand in candidates:
        if any(cand in n for n in BLOCKED_NETS):
            return True
    return False


def _host_blocked(host: str) -> bool:
    h = (host or "").strip("[]").lower()
    if not h or h in BLOCKED_HOSTS or h.endswith(".internal") or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    if ip is not None:
        return _ip_blocked(ip)
    try:
        infos = socket.getaddrinfo(h, None)
    except Exception:
        return True
    if not infos:
        return True
    for info in infos:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except Exception:
            return True
        if _ip_blocked(ip):
            return True
    return False


def validate_webhook_url(url: str) -> Optional[str]:
    try:
        p = urlparse(url)
    except Exception:
        return "invalid_url"
    if p.scheme not in ("https", "http"):
        return "scheme"
    if p.username or p.password:
        return "userinfo"
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    if port not in ALLOWED_PORTS:
        return "port"
    if _host_blocked(host):
        return "private_or_local"
    return None


def sign_body(secret: str, timestamp: str, nonce: str, event_id: str, body: bytes) -> str:
    msg = timestamp.encode() + b"\n" + nonce.encode() + b"\n" + event_id.encode() + b"\n" + body
    return hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).hexdigest()


def verify_delivery(secret: str, timestamp: str, nonce: str, event_id: str, body: bytes, signature: str, now: Optional[int] = None) -> str:
    """Return empty string if ok, else error code. Never includes the secret."""
    now = int(now if now is not None else time.time())
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return "bad_timestamp"
    if abs(now - ts) > REPLAY_WINDOW:
        return "replay_window"
    expected = sign_body(secret, timestamp, nonce, event_id, body)
    if not hmac.compare_digest(expected, signature or ""):
        return "bad_signature"
    return ""


def load_or_create_secret() -> str:
    path = SECRETS_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if os.path.exists(path):
        data = open(path, "r").read().strip()
        if data:
            return data
    secret = hashlib.sha256(os.urandom(32)).hexdigest()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(secret + "\n")
    os.chmod(path, 0o600)
    return secret


def deliver(url: str, event: dict, secret: str) -> int:
    err = validate_webhook_url(url)
    if err:
        return 0
    body = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ts = str(int(time.time()))
    nonce = hashlib.sha256(os.urandom(16)).hexdigest()[:16]
    event_id = str(event.get("event_id") or "")
    sig = sign_body(secret, ts, nonce, event_id, body)
    import requests
    r = requests.post(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-WraithWall-Timestamp": ts,
            "X-WraithWall-Nonce": nonce,
            "X-WraithWall-Event-Id": event_id,
            "X-WraithWall-Signature": sig,
        },
        timeout=5,
        allow_redirects=False,
    )
    return int(r.status_code)
