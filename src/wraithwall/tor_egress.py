"""Tor-routed egress for public scanners.

The public link checker queries third-party vendors and resolves hostnames on
behalf of anonymous visitors. Sending that traffic from the platform's own
address would let vendors (and the local resolver) correlate what visitors
scan, and would expose the platform's origin to whatever is scanned. Everything
here therefore leaves through Tor.

Policy is FAIL-CLOSED by default: if Tor is not reachable, calls raise
`TorUnavailable` rather than silently falling back to a direct connection. An
operator can override with `PUBLIC_EGRESS_MODE=direct` (logged loudly at the
call site), which is the only way traffic leaves unproxied.

Environment:
    PUBLIC_EGRESS_MODE    tor | direct          (default: tor)
    TOR_SOCKS             host:port             (default: 127.0.0.1:9050)
    TOR_CONNECT_TIMEOUT   seconds               (default: 10)
    TOR_READY_TTL         seconds to cache the SOCKS liveness probe (default 30)
"""

from __future__ import annotations

import logging
import os
import socket
import time
from typing import Optional

import requests

logger = logging.getLogger(__name__)

DEFAULT_SOCKS = "127.0.0.1:9050"
_CONNECT_TIMEOUT = float(os.getenv("TOR_CONNECT_TIMEOUT", "10"))
_READY_TTL = float(os.getenv("TOR_READY_TTL", "30"))

_ready_cache = {"at": 0.0, "value": None}

_MODE_LOGGED = set()


class TorUnavailable(requests.exceptions.RequestException):
    """Raised when egress was required through Tor but Tor is not usable."""


def mode() -> str:
    """Active egress mode: 'tor' (default) or 'direct' (operator override)."""
    value = (os.getenv("PUBLIC_EGRESS_MODE", "tor") or "tor").strip().lower()
    return "direct" if value == "direct" else "tor"


def _socks_addr() -> tuple[str, int]:
    raw = os.getenv("TOR_SOCKS", DEFAULT_SOCKS)
    host, _, port = raw.rpartition(":")
    host = host or "127.0.0.1"
    try:
        return host, int(port or "9050")
    except ValueError:
        return host, 9050


def proxy_url() -> str:
    host, port = _socks_addr()
    # socks5h: resolve hostnames at the proxy (remote DNS) so lookups do not
    # leak to the local resolver.
    return f"socks5h://{host}:{port}"


def proxies() -> Optional[dict]:
    if mode() == "direct":
        return None
    url = proxy_url()
    return {"http": url, "https": url}


def _note_mode_once(function: str) -> None:
    if function in _MODE_LOGGED:
        return
    _MODE_LOGGED.add(function)
    if mode() == "direct":
        logger.warning(
            "EGRESS: PUBLIC_EGRESS_MODE=direct — %s is NOT anonymised. "
            "Vendor calls and DNS lookups leave from the platform address.", function,
        )


def available(force: bool = False) -> bool:
    """True when a SOCKS listener answers. Cached for TOR_READY_TTL seconds."""
    if mode() == "direct":
        return True
    now = time.time()
    if not force and _ready_cache["value"] is not None and now - _ready_cache["at"] < _READY_TTL:
        return bool(_ready_cache["value"])
    host, port = _socks_addr()
    ok = False
    try:
        with socket.create_connection((host, port), timeout=min(3.0, _CONNECT_TIMEOUT)):
            ok = True
    except OSError:
        ok = False
    _ready_cache.update(at=now, value=ok)
    return ok


def _require_tor(function: str) -> None:
    _note_mode_once(function)
    if mode() == "tor" and not available():
        raise TorUnavailable(
            "privacy egress unavailable: Tor SOCKS proxy is not reachable "
            f"({os.getenv('TOR_SOCKS', DEFAULT_SOCKS)})"
        )


def session() -> requests.Session:
    """A Session pinned to Tor (or a plain one in direct mode).

    `trust_env=False` so an ambient HTTP_PROXY/HTTPS_PROXY in the service
    environment can never silently reroute or bypass this policy.
    """
    _require_tor("session")
    s = requests.Session()
    s.trust_env = False
    if proxies():
        s.proxies.update(proxies())
    s.headers.update({"User-Agent": "WraithWall-LinkChecker/1.0"})
    return s


def request(method: str, url: str, **kwargs) -> requests.Response:
    _require_tor(f"request:{method}")
    if "timeout" not in kwargs:
        kwargs["timeout"] = _CONNECT_TIMEOUT
    kwargs.setdefault("allow_redirects", True)
    with session() as s:
        return s.request(method, url, **kwargs)


def get(url: str, **kwargs) -> requests.Response:
    return request("GET", url, **kwargs)


def post(url: str, **kwargs) -> requests.Response:
    return request("POST", url, **kwargs)


def resolve(host: str, timeout: Optional[float] = None) -> str:
    """Resolve a hostname to an IP through Tor's SOCKS5 RESOLVE command.

    Remote DNS is the point: a local `socket.gethostbyname` would leak which
    hostnames visitors scan to the machine's resolver. Returns '' when
    resolution fails or egress is unavailable — callers treat that as "no IP"
    and skip the sources that need one.
    """
    if not host:
        return ""
    _note_mode_once("resolve")
    if mode() == "tor" and not available():
        return ""

    host_part, _, _port = host.partition(":")
    if host_part.startswith("[") and "]" in host_part:      # [v6]
        host_part = host_part[1:host_part.index("]")]

    try:
        import ipaddress
        # Literal addresses need no lookup, but still normalise via the library.
        return str(ipaddress.ip_address(host_part))
    except ValueError:
        pass

    if mode() == "direct":
        try:
            return socket.gethostbyname(host_part)
        except OSError:
            return ""

    proxy_host, proxy_port = _socks_addr()
    try:
        return _socks5_resolve(host_part, proxy_host, proxy_port,
                               timeout or _CONNECT_TIMEOUT)
    except Exception as exc:
        logger.debug("EGRESS: tor resolve failed for %s: %s", host_part, exc)
        return ""


def _socks5_resolve(host: str, proxy_host: str, proxy_port: int, timeout: float) -> str:
    """SOCKS5 CMD=0xF0 (RESOLVE) — Tor answers with the resolved address.

    Implemented directly because the installed PySocks build exposes neither
    `getaddrinfo` nor the proxy's bound address for remote-DNS connects.
    """
    name = host.encode("idna") if host.isascii() else host.encode()
    if len(name) > 255:
        raise ValueError("hostname too long")
    with socket.create_connection((proxy_host, proxy_port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")                                  # no auth
        if s.recv(2) != b"\x05\x00":
            raise OSError("SOCKS5 handshake rejected")
        s.sendall(b"\x05\xf0\x00\x03" + bytes([len(name)]) + name + b"\x00\x00")
        head = _recv_exact(s, 4)
        if head[1] != 0:
            raise OSError(f"RESOLVE rejected (reply {head[1]})")
        atyp = head[3]
        if atyp == 0x01:
            return socket.inet_ntoa(_recv_exact(s, 4))
        if atyp == 0x04:
            return socket.inet_ntop(socket.AF_INET6, _recv_exact(s, 16))
        raise OSError(f"unexpected address type {atyp}")


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("short read from SOCKS proxy")
        buf += chunk
    return buf


def status() -> dict:
    """Operator-facing snapshot for status endpoints."""
    return {
        "mode": mode(),
        "proxy": None if mode() == "direct" else proxy_url(),
        "available": available(),
    }
