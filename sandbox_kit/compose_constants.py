"""Shared constants for the sandbox kit (Phase 5).

`gates_static` parses compose as *data* and must not import the docker-driving
`compose` module, but both need the uplink network name. This tiny module keeps
that single source of truth without giving the static gate an import edge into
the runtime layer.
"""

#: Third network (Phase 5 loopback uplink). The only non-internal network the
#: static gates tolerate, and only for compose-profile-scoped services, with
#: masquerade and ICC disabled.
UPLINK_NETWORK = "ww-uplink-net"

#: Fourth network (Phase 11 research egress). NON-internal on purpose: it is
#: the ONLY path through which the detonation container may reach the hosts a
#: developer explicitly allowlisted for the session, and all traffic on it is
#: forced through the enforcing proxy (sb-egress). IP masquerade stays ON here
#: — without NAT the proxy's forward to an allowlisted public host cannot
#: return — which is exactly why every other control on this plane is stricter:
#: allowlist deny-by-default, infrastructure deny-policy inside the proxy, DNS
#: blackholed at the detonation container (the proxy resolves), no publishes,
#: and the self-test canaries asserting the closure on every start.
EGRESS_NETWORK = "ww-egress-net"

#: Compose profile under which the T2 research services ship. Off by default;
#: the launcher activates it only for --profile research-sandbox after the
#: per-session confirmation and the rootless gate (E203) have passed.
RESEARCH_PROFILE = "research"

