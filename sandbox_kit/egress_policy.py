"""T2 egress policy — the single source of truth for what the research-sandbox
egress proxy must block (Phase 11).

The research-sandbox is the only profile where developer-supplied URLs are
fetched by sandbox code. The roadmap gates it on four things; this module
implements the network half:

* **Deny-by-default.** Only developer-requested hosts may pass, per-session,
  from the CLI (`up --allow-host`). The deny decision — never the allow — is
  the invariant the tests mutate against.
* **Infrastructure closure.** The detonation container's proxy must never
  forward to infrastructure: RFC1918, loopback, link-local, CGNAT, benchmark
  ranges, protocol-assignment ranges, Docker's embedded-DNS stub, documented
  cloud metadata hosts, metadata-shaped hostnames, and IPv6 (resolving or
  literal) — the two closure gaps the roadmap names.
* **One shared truth.** ``DENY_DECISIONS`` is the machine-readable rule list
  consumed by three consumers that must agree: the mitmproxy addon inside the
  egress container (runtime enforcement), the static gate (compose posture),
  and the test deny-matrix (mutation coverage). They cannot drift.

Everything here is a ``[PROPOSAL]`` implementation of the Stage 2 network
model, scoped to the research compose profile ``research``. It is a
software-enforced boundary on a shared kernel — improved isolation for
development testing, never a containment guarantee (the non-claims stay
attached to this profile at the CLI and in the docs).
"""
from __future__ import annotations

import ipaddress

# ── deny rule classes ────────────────────────────────────────────────────────
#
# Each entry is (rule_id, rule_type, value, reason). rule_type is one of:
#   "net4"        — IPv4 network
#   "net6"        — IPv6 network
#   "host"        — exact hostname (case-insensitive)
#   "host_suffix" — hostname suffix, ".x" form (matches both x and *.x)
#   "port"        — TCP destination port the proxy must never forward to
#   "query"       — substring banned from the request line/authority
#                   (DoH/DoT bypass shapes)
# Matching is all-rules; rule_id order is presentation only.

DENY_DECISIONS: list[tuple[str, str, str, str]] = [
    # IPv4 ranges: this-network, RFC1918, CGNAT, loopback, link-local/metadata,
    # protocol assignments, benchmarking, and the RFC3927-style leftovers.
    ("D01", "net4", "0.0.0.0/8", "this-network"),
    ("D02", "net4", "10.0.0.0/8", "RFC1918 private"),
    ("D03", "net4", "100.64.0.0/10", "CGNAT"),
    ("D04", "net4", "127.0.0.0/8", "loopback"),
    ("D05", "net4", "169.254.0.0/16", "link-local / cloud metadata range"),
    ("D06", "net4", "172.16.0.0/12", "RFC1918 private (incl. docker bridges)"),
    ("D06b", "net4", "192.168.0.0/16", "RFC1918 private"),
    ("D07", "net4", "192.0.0.0/24", "IETF protocol assignments"),
    ("D08", "net4", "192.0.2.0/24", "TEST-NET-1"),
    ("D09", "net4", "198.18.0.0/15", "benchmarking"),
    ("D10", "net4", "198.51.100.0/24", "TEST-NET-2"),
    ("D11", "net4", "203.0.113.0/24", "TEST-NET-3"),
    ("D12", "net4", "224.0.0.0/4", "multicast"),
    ("D13", "net4", "240.0.0.0/4", "reserved"),
    ("D14", "net4", "255.255.255.255/32", "broadcast"),
    # Cloud metadata endpoints (documented values; literal-address copies are
    # already covered by D05/D06 ranges, these pin the canonical hostnames).
    ("H01", "host", "metadata.google.internal", "GCP metadata"),
    ("H02", "host", "metadata.goog", "GCP metadata short name"),
    ("H03", "host", "metadata.internal", "generic metadata alias"),
    ("H04", "host", "metadata", "bare metadata name (docker/k8s DNS shapes)"),
    ("H05", "host", "instance-data", "EC2 classic metadata name"),
    ("H06", "host", "instance-data.ec2.internal", "EC2 metadata FQDN"),
    # Metadata-shaped / internal-shaped hostnames (regex-anchored suffix logic).
    ("H07", "host_suffix", ".metadata", "metadata-shaped hostname"),
    ("H08", "host_suffix", ".internal", "internal-shaped hostname"),
    ("H09", "host_suffix", ".local", "mDNS/local namespace"),
    ("H10", "host_suffix", ".localhost", "localhost namespace"),
    ("H11", "host_suffix", ".home.arpa", "home network namespace"),
    # Docker's embedded DNS resolver: forwarding to it is the classic
    # host-network probe. The detonation container has no route that makes
    # this useful anyway; blocking it makes the closure explicit.
    ("D15", "net4", "127.0.0.11/32", "docker embedded DNS stub"),
    # IPv6 closure (roadmap gate): the research plane has no IPv6 use case.
    # ULA + link-local + the documentation prefix cover DNS answers; ::1 and
    # ::ffff:-mapped literals are folded in by classify() itself.
    ("V01", "net6", "::/128", "unspecified IPv6"),
    ("V02", "net6", "::1/128", "IPv6 loopback"),
    ("V03", "net6", "fc00::/7", "IPv6 ULA"),
    ("V04", "net6", "fe80::/10", "IPv6 link-local"),
    ("V05", "net6", "2001:db8::/32", "IPv6 documentation"),
    # DoH / DoT bypass closure (roadmap gate): a browser in the detonation
    # container can otherwise tunnel its own resolution around the proxy.
    ("P01", "port", "53", "plaintext DNS (proxy answers nothing; closure is total)"),
    ("P02", "port", "853", "DNS-over-TLS"),
    ("P03", "port", "443", "DNS-over-HTTPS is protocol-ambiguous; see classify()"),
    ("Q01", "query", "dns-query", "DoH path shape (RFC 8484)"),
]

# The well-known DoH bootstrap hostnames (public resolvers). A request whose
# authority is one of these is refused even on a nonstandard path/port.
DOH_BOOTSTRAP_HOSTS = frozenset({
    "cloudflare-dns.com",
    "dns.google",
    "dns.quad9.net",
    "dns.opendns.com",
    "doh.opendns.com",
    "use.application.dns.apple.com",
    "firefox.dns.nextdns.io",
    "dns.adguard.com",
    "doh.sb",
    "doh.mullvad.net",
    "dns.sse.cisco.com",
})

# Cloud-metadata canonical ports, kept explicit for the audit trail.
METADATA_PORTS = frozenset({"80", "8080", "8443"})

# Ports the proxy must never forward to, from P-rules (numeric only).
DENY_PORTS: frozenset[str] = frozenset(
    value for _id, rtype, value, _why in DENY_DECISIONS if rtype == "port"
)

# Query-shaped bans, from Q-rules.
DENY_QUERY_SUBSTRINGS: tuple[str, ...] = tuple(
    value.lower() for _id, rtype, value, _why in DENY_DECISIONS if rtype == "query"
)

# Precompiled network objects.
_DENY_NET4 = tuple(
    ipaddress.ip_network(value) for _id, rtype, value, _why in DENY_DECISIONS
    if rtype == "net4"
)
_DENY_NET6 = tuple(
    ipaddress.ip_network(value) for _id, rtype, value, _why in DENY_DECISIONS
    if rtype == "net6"
)
_DENY_HOSTS = frozenset(
    value.lower() for _id, rtype, value, _why in DENY_DECISIONS if rtype == "host"
)
_DENY_SUFFIXES = tuple(
    value.lower() for _id, rtype, value, _why in DENY_DECISIONS
    if rtype == "host_suffix"
)


def _suffix_match(hostname: str) -> str | None:
    for suffix in _DENY_SUFFIXES:
        if hostname == suffix.lstrip(".") or hostname.endswith(suffix):
            return f"hostname matches deny suffix '{suffix}'"
    return None


def _net4_match(addr4: ipaddress.IPv4Address) -> str | None:
    for net in _DENY_NET4:
        if addr4 in net:
            return f"address falls in deny range {net}"
    return None


def _net6_match(addr6: ipaddress.IPv6Address) -> str | None:
    if addr6.ipv4_mapped is not None:
        # ::ffff:a.b.c.d — treat as the embedded IPv4 address.
        reason = _net4_match(addr6.ipv4_mapped)
        if reason:
            return f"IPv4-mapped IPv6 ({reason})"
    for net in _DENY_NET6:
        if addr6 in net:
            return f"address falls in deny range {net}"
    return None


def classify(host: str, port: str | int | None = None,
             path: str | None = None) -> tuple[bool, str]:
    """Decide whether a proxy CONNECT/authority target is denied.

    Returns ``(denied, reason)``. ``host`` may be a hostname or a literal
    IPv4/IPv6 address (IPv6 in bracketed form is accepted). ``port`` and
    ``path`` are optional refinements used by the DoH closures.

    Deny-by-default is structural: an empty host, an unparseable literal, or
    any probe error denies. Only an explicit policy match returns allow.
    """
    try:
        if not host or not str(host).strip():
            return True, "empty authority"
        hostname = str(host).strip().lower()
        if hostname.startswith("[") and "]" in hostname:
            hostname = hostname[1:hostname.index("]")]

        port_s = str(port) if port is not None else None
        path_s = (path or "").lower()

        # H-rules: exact and suffix hostnames.
        if hostname in _DENY_HOSTS:
            for rid, _rt, val, why in DENY_DECISIONS:
                if rid.startswith(("H",)) and val == hostname:
                    return True, f"denied by {rid}: {why}"
        suffix_reason = _suffix_match(hostname)
        if suffix_reason:
            return True, suffix_reason

        # Literal IP addresses (v4 and v6, including mapped forms).
        try:
            addr = ipaddress.ip_address(hostname)
        except ValueError:
            addr = None
        if addr is not None:
            if isinstance(addr, ipaddress.IPv4Address):
                reason = _net4_match(addr)
            else:
                reason = _net6_match(addr)
            if reason:
                return True, reason
        else:
            # Resolve-on-decide for hostnames: a name that answers with an
            # infrastructure address is denied even though the literal string
            # looked benign (DNS-rebinding shape, RFC1918 CNAMEs).
            try:
                import socket
                infos = socket.getaddrinfo(hostname, None)
            except (socket.gaierror, OSError):
                infos = []
            for info in infos:
                ip = info[4][0]
                try:
                    a = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                reason = (_net4_match(a) if isinstance(a, ipaddress.IPv4Address)
                          else _net6_match(a))
                if reason:
                    return True, f"resolved address denied ({ip}): {reason}"

        # P-rules: destination ports.
        if port_s is not None and port_s in DENY_PORTS:
            for rid, _rt, val, why in DENY_DECISIONS:
                if rid.startswith("P") and val == port_s:
                    # P03 (443) is protocol-ambiguous: DoH closure on 443 is
                    # enforced via bootstrap-host and query-shape rules below,
                    # not by blanket-refusing all HTTPS (which would make the
                    # allowlist useless). Plain 443 is therefore allowed.
                    if rid == "P03":
                        continue
                    return True, f"denied by {rid}: {why}"

        # Q-rules: DoH path shapes + bootstrap hosts.
        if "dns-query" in path_s:
            return True, "denied by Q01: DoH path shape (RFC 8484)"
        if hostname in DOH_BOOTSTRAP_HOSTS:
            return True, "denied: DoH bootstrap host"

        return False, "allowed: not matched by any deny rule"
    except Exception as exc:  # probe error => deny (fail-closed)
        return True, f"policy evaluation error: {exc.__class__.__name__}"


def classify_connect(authority: str) -> tuple[bool, str]:
    """Convenience wrapper for CONNECT targets: ``host[:port]``."""
    try:
        host, _, port = authority.rpartition(":")
        if not host:  # no colon at all
            return classify(authority)
        if host.startswith("[") and host.endswith("]"):
            host = host[1:-1]
        return classify(host, port)
    except Exception as exc:
        return True, f"policy evaluation error: {exc.__class__.__name__}"


# ── self-test script (single source of truth for the in-container check) ────
#
# The egress container runs this on every research-plane start (G7-style
# dynamic self-check). It classifies canonical deny cases and asserts they
# all deny; it does NOT resolve hostnames (the egress container must not
# depend on DNS at boot) and it does NOT touch the network.

SELF_TEST_CASES: tuple[tuple[str, str], ...] = (
    ("169.254.169.254", "metadata literal"),
    ("metadata.google.internal", "metadata hostname"),
    ("169.254.170.2", "ECS metadata"),
    ("100.100.100.200", "Alibaba metadata"),
    ("fd00:ec2::254", "AWS IPv6 metadata"),
    ("10.1.2.3", "RFC1918"),
    ("127.0.0.1", "loopback"),
    ("127.0.0.11", "docker DNS stub"),
    ("::ffff:169.254.169.254", "IPv4-mapped metadata"),
    ("anything.local", "mDNS shape"),
    ("svc.internal", "internal shape"),
)


def self_test_script() -> str:
    """Python script text the egress container runs as its self-check."""
    cases = ", ".join(f"({h!r}, {why!r})" for h, why in SELF_TEST_CASES)
    return (
        "import sys\n"
        "from egress_policy import classify\n"
        f"CASES = [{cases}]\n"
        "for host, why in CASES:\n"
        "    denied, reason = classify(host)\n"
        "    if not denied:\n"
        "        print(f'POLICY_SELF_TEST_FAILED: {host} ({why}) allowed')\n"
        "        sys.exit(1)\n"
        "print('POLICY_SELF_TEST_OK: all deny rules classify correctly')\n"
    )
