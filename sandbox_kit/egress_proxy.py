"""Egress enforcement addon for the research-sandbox proxy (Phase 11).

Runs inside ``sb-egress`` (mitmproxy, regular mode) as the ONLY route between
the detonation container and anything else. Two independent layers, both
fail-closed:

1. **Per-session allowlist** — ``WRAITHWALL_SANDBOX_ALLOWED_HOSTS`` (comma-
   separated, set by the launcher from ``up --allow-host``). A host that is
   not on it is denied outright. Empty list => everything is denied.
2. **Infrastructure deny policy** — ``egress_policy.classify`` runs even for
   allowlisted hosts, so a developer cannot allowlist their way into the
   cloud metadata service, the docker stub, or an internal range.

Every decision is logged with a fixed prefix (``EGRESS_ALLOW`` /
``EGRESS_DENY``) so `logs --service sb-egress` is an auditable record of what
the proxy did — the "logged" property of the five-property gate.

**Tunnel-only TLS (deliberate design, not a shortcut).** TLS is gated at the
CONNECT/SNI layer and then passed through *unmodified* — mitmproxy never
terminates or re-signs upstream TLS, so there is no interception CA to
generate, distribute, or steal. A per-session CA would add a private key to
the sandbox whose compromise would let the proxy silently impersonate every
allowlisted host; refusing that authority is the honest T2 boundary. The
enforcement points are exactly where the container can still be stopped:

* HTTPS: ``http_connect`` sees the CONNECT authority (SNI) — the decision.
* Plain HTTP: ``request`` sees the request authority — the decision.
* ``server_connect`` is a belt-and-braces re-check on the upstream target;
  the resolver may hand mitmproxy an IP, so name-based checks use the last
  known CONNECT authority for the client before falling back to the literal
  address. An unresolvable target can never look like an allowlisted name.

The mitmproxy import is guarded so this module can be unit-tested on any
machine (the enforcement functions are importable without mitmproxy).
"""
from __future__ import annotations

import os

try:  # inside the egress image the addon is imported flat; in-repo it is a package module
    from egress_policy import classify
except ImportError:  # pragma: no cover
    from sandbox_kit.egress_policy import classify


def allowed_hosts_from_env(value: str | None = None) -> frozenset[str]:
    """Parse the per-session allowlist. Strict: lowercase, trimmed, nonempty;
    anything else is dropped. An absent variable means an EMPTY allowlist —
    deny-by-default, never '*' semantics."""
    raw = os.environ.get("WRAITHWALL_SANDBOX_ALLOWED_HOSTS", "") \
        if value is None else value
    hosts = set()
    for part in (raw or "").split(","):
        part = part.strip().lower().rstrip(".")
        if part:
            hosts.add(part)
    return frozenset(hosts)


def decide(hostname: str, allowlist: frozenset[str], port=None,
           path: str | None = None) -> tuple[bool, str]:
    """The decision function, separated from mitmproxy for testability.

    Returns (allowed, reason). Layer 1 = allowlist; layer 2 = deny policy.
    Both must agree to allow.
    """
    hostname = (hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return False, "EGRESS_DENY: empty authority"
    if hostname not in allowlist:
        return False, (f"EGRESS_DENY: '{hostname}' is not on this session's "
                       "allowlist (deny-by-default)")
    denied, why = classify(hostname, port=port, path=path)
    if denied:
        return False, f"EGRESS_DENY: policy refuses allowlisted '{hostname}': {why}"
    return True, f"EGRESS_ALLOW: '{hostname}' (allowlisted, policy-clean)"


try:  # mitmproxy exists only inside the egress image
    from mitmproxy import http

    ALLOWLIST = allowed_hosts_from_env()
    # client_conn -> last CONNECT authority seen for that client, so the
    # upstream re-check can compare names, not resolver-provided IPs.
    _LAST_AUTHORITY: dict[object, str] = {}

    def _authority_host(authority) -> str:
        return ((authority or "").split(":")[0] or "").strip().lower().rstrip(".")

    def _address_host(address) -> str:
        try:
            return (address[0] or "").strip().lower().rstrip(".")
        except (TypeError, IndexError, ValueError):
            return ""

    def http_connect(flow: http.HTTPFlow) -> None:
        """The HTTPS decision point: the CONNECT authority (SNI)."""
        host = _authority_host(flow.request.authority or flow.request.host)
        ok, why = decide(host, ALLOWLIST, port=flow.request.port)
        print(why, flush=True)
        if ok:
            _LAST_AUTHORITY[flow.client_conn] = host
        else:
            flow.response = http.Response.make(
                403, b"Blocked by WraithWall research-sandbox egress policy\n",
                {"Content-Type": "text/plain"})

    def request(flow: http.HTTPFlow) -> None:
        """Plain HTTP decision point (never reached for tunneled TLS)."""
        authority = flow.request.authority or flow.request.host
        host = _authority_host(authority)
        ok, why = decide(host, ALLOWLIST, port=flow.request.port,
                         path=flow.request.path)
        print(why, flush=True)
        if not ok:
            flow.response = http.Response.make(
                403, b"Blocked by WraithWall research-sandbox egress policy\n",
                {"Content-Type": "text/plain"})

    def server_connect(data) -> None:
        """Belt-and-braces upstream re-check. Match by the client's CONNECT
        authority when known; otherwise judge the literal address (an IP can
        never pass the name allowlist — fail-closed, not name-guessing)."""
        addr_host = _address_host(getattr(data.server, "address", None))
        host = _LAST_AUTHORITY.get(getattr(data, "client_conn", None)) or addr_host
        ok, why = decide(host, ALLOWLIST)
        print(why, flush=True)
        if not ok:
            data.error = "Connection denied by research-sandbox egress policy"

    def server_disconnected(data) -> None:
        _LAST_AUTHORITY.pop(getattr(data, "client_conn", None), None)

except ImportError:  # pragma: no cover - exercised by unit tests on any host
    pass
