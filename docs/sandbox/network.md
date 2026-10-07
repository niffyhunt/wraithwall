# Sandbox network and egress model

Phase 3 implements the two-plane topology from the approved design. This page
records what is actually enforced, one deviation that the design could not be
built with, and the reason the deviation is the *safer* of the two options.

---

## 1. Zones

```text
HOST (developer machine) — management plane
  • sandbox launcher (./sandbox.sh, python -m sandbox_kit)
  • the only client that talks to a sandbox
  • NOT a member of any container network beyond the bridge it created
        │
        │  nothing is published; see §2
        ▼
┌─────────────────────────────────────────────────────────────────────┐
│ ww-app-net        internal: true, no gateway, no upstream DNS       │
│   sb-app        the application                                      │
│   sb-busybox    egress-deny self-check (one-shot)                    │
└──────────────────────────┬──────────────────────────────────────────┘
                           │ container DNS names only
┌──────────────────────────▼──────────────────────────────────────────┐
│ ww-telemetry-net  internal: true, no gateway, no upstream DNS       │
│   sb-redis      telemetry bus (ephemeral, tmpfs)                     │
│   sb-seed       synthetic producer (Phase 4, one-shot)               │
│   sb-busybox-t  egress-deny self-check for this plane (one-shot)      │
└─────────────────────────────────────────────────────────────────────┘
```

Both planes are `internal: true`. Every container is attached only to internal
networks, which is what makes "no egress" a property of the topology rather than
a promise. Since Phase 4 the egress canary runs on **both** planes at every
start (`sb-busybox` on the app plane, `sb-busybox-t` on the telemetry plane);
the telemetry plane carries the seed traffic and the bus, so it is verified
equally. The seed reaches the app's ship endpoint over the telemetry plane
with an HMAC key shared only inside this project — the endpoint is
origin-gate-exempt server-to-server API guarded by that HMAC, not by network
position alone.

## 2. Why nothing is published (the one deviation)

The approved design asked for both:

1. internal planes for the application and telemetry networks, and
2. the UI published on `127.0.0.1:<port>`.

**Docker cannot do both.** A port published from a container whose only
attachment is an internal network is silently dropped: the container runs, the
service listens, and the host connection is refused.

Measured on Docker 29.1.3:

| Network | Service listening inside | `docker port` | Host connect |
|---|---|---|---|
| `internal: true` | yes (`redis-cli ping` → `PONG`) | *empty* | **refused** |
| plain bridge (control) | yes | `127.0.0.1:…->6379/tcp` | works |
| bridge, `enable_ip_masquerade=false` | yes | lists the mapping | works |

The third row is the tempting workaround and it is **worse**: with masquerade
disabled a container still resolves DNS through the daemon and can still reach
the bridge gateway and the host, so "no route out" stops being true and a DNS
tunnelling path remains. The design's own egress table says the application
plane must be denied egress in T1, so the workaround contradicts the requirement
it was meant to satisfy.

**Decision:** both planes stay `internal: true` and the compose file publishes
nothing at all. This is strictly tighter than the production
`docker-compose.yml`, which publishes redis and postgres on loopback.

### The uplink must not rely on host→container routing

The original plan was for the launcher to bind `127.0.0.1` and forward to the
app's bridge address, on the assumption that "the host is a member of the
bridge it created". **That assumption is false as a general rule.** Measured on two
hosts running the same Docker version:

| Host | Host → container IP on a bridge |
|---|---|
| no restrictive firewall | reachable |
| `ufw` active, `INPUT`/`FORWARD` default `DROP` | **blocked (timeout)** |

And it is *not* about `internal: true`: on the firewalled host a plain
(non-internal) bridge was blocked in exactly the same way. Host→container
reachability is a property of the **host firewall**, not of this compose file.

Consequence for Phase 5: the loopback uplink cannot be built on that path. The
firewall-independent mechanism is Docker's own port publishing, because Docker
inserts its DNAT rules ahead of the host's input filtering. That requires a
non-internal bridge, which reintroduces egress unless it is constrained. The
recommended Phase 5 shape is therefore a third, dedicated **uplink** network:

* attached to the app **in addition to** the two internal planes,
* `internal: false` but `com.docker.network.bridge.enable_ip_masquerade: "false"`
  (no NAT → no internet), 
* an external resolver blackholed with `dns: [127.0.0.1]` so Docker's embedded
  DNS cannot forward lookups outward (the DNS exfiltration path measured on the
  masquerade-disabled bridge),
* the UI published as `127.0.0.1:<port>:8000` on that interface only.

Residual risk to state honestly: the uplink bridge has a gateway to the host, so
it is a wider surface than the current design. It must be introduced only with
the egress canary re-run against the app's full network set, and the claim stays
"verified default controls and documented network/data boundaries" — not a
containment guarantee.

> **Status (Phase 5): implemented as designed above.** The uplink is OFF by
> default (`WRAITHWALL_SANDBOX_UPLINK=1` to enable). Bring-up is two-phase —
> the core project boots first, then the launcher reads the app's actual
> bridge IP and starts the proxy with it explicitly (no DNS, no catch-22).
> The proxy is a ~20-line asyncio forwarder from the seed image (stdlib only,
> no new dependencies), refuses to start without a literal IPv4 target, and
> runs under the same hardening baseline as every other service. The
> in-app egress canary (`verify_egress_denied_all`) re-runs against the
> app's full network set on every uplink start; a live test asserts
> `UPLINK_EGRESS_DENY_OK` with the uplink attached. Verified residual risks:
> the uplink bridge has a host-side gateway (wider than the internal planes,
> still NAT-free and DNS-blackholed), and the UI is reachable from anything
> that can reach the host's loopback — local users only.

### 2.1 Host-firewall dependency of the loopback publish (E107)

The published port is host-originated traffic to a container IP. A host with a
default-deny OUTPUT chain (ufw `OUTPUT` policy `DROP`) silently discards it even
though docker-proxy, the DNAT rule and the container healthcheck are all green —
verified live on a hardened VPS (the container can reach itself; the host's SYN
dies in OUTPUT before it ever hits the wire).

`up` therefore probes `127.0.0.1:<port>` before reporting the uplink as running
and fails closed with **E107** plus the scoped remediation:

```bash
sudo ufw allow out from any to 172.16.0.0/12 comment 'wraithwall-sandbox-uplink'
```

That rule covers only host→docker-bridge-subnet traffic (the docker bridge pool
`172.16.0.0/12`) — it grants no WAN exposure and no new inbound path, and is
removable via `ufw status numbered` / `ufw delete <n>`.

The live suite asserts the portable half (`test_app_serves_health_from_inside_its_namespace`,
`test_app_has_no_egress_while_serving`) and *records* the host-firewall
dependency as a non-failing observation
(`test_host_to_bridge_reachability_is_characterised`) rather than asserting a
property that is not universally true.

## 3. Connection policy

| From → To | Policy | Mechanism |
|---|---|---|
| Host → app | allowed | bridge address (management plane); loopback uplink in Phase 5 |
| App → redis | allowed | container DNS name on `ww-telemetry-net` |
| Seed → redis | allowed | container DNS name |
| Anything → internet | **denied** | `internal: true`, no gateway, no NAT |
| Anything → host loopback / LAN | **denied** | no published ports, no gateway |
| Sandbox → other sandbox | **denied** | per-project networks (`-p ww-sb-<name>`); no hardcoded subnets |
| Anything → Docker socket | **denied always** | no socket is mounted (gate G2) |
| Browser → sandbox UI | loopback only | opt-in `sb-uplink` proxy (implemented, Phase 5) |

## 4. DNS

On an internal network Docker's embedded resolver has no upstream, so container
names resolve and external names do not. That absence is the control, not a bug.

The self-check asserts it explicitly: the canary fails the sandbox if
`nslookup example.com` succeeds, because a working external lookup from a sandbox
plane is an exfiltration path even when routing is blocked. No custom DNS
servers from the developer environment are honoured.

## 5. Egress policy by tier

| Tier | Mechanism | What it means |
|---|---|---|
| T0 `app-only` | no containers | nothing to isolate |
| T1 `local-sandbox` | both planes `internal: true` | nothing leaves; no DNS upstream |
| T2 `research-sandbox` | **shipped (Phase 11)**: the `ww-egress-net` plane — the only other non-internal network — routes every fetch through `sb-egress`, which enforces the per-session allowlist (deny-by-default, E210/E211) and the shared deny policy (`sandbox_kit/egress_policy.py`: RFC1918, loopback, metadata hosts/ranges, CGNAT, Docker DNS stub, all IPv6 incl. mapped, DoT/DoH shapes) even for allowlisted hosts; the detonation container has `dns: 127.0.0.1` (no resolution around the proxy) and two self-checks run on every start | per-session allowlist + policy deny + audited decisions (`EGRESS_ALLOW`/`EGRESS_DENY` in `logs --service sb-egress`) |

### TLS in the research plane is tunnel-only

The proxy gates HTTPS at the CONNECT/SNI layer and passes the TLS session
through **unmodified**. There is no interception CA: mitmproxy never
terminates upstream TLS, so no per-session CA key exists to generate,
distribute, or steal. The trade-off is deliberate — the proxy can see and
allow/deny *which hosts* are contacted, but not decrypt *what* is said. If a
fetch must be inspected in detail, that work belongs on a Tier 3+ VM lab,
not this sandbox.
| T3 `vm-sandbox` | *recipe only* — VM NAT + host firewall | default-deny at the hypervisor boundary |

Platform note: on macOS and Windows the enforcement happens inside the Docker
Desktop VM, so the boundary is relative to that VM. On Linux it is the host
kernel — which is exactly why T1 is described as blast-radius reduction and not
as hostile-code containment.

## 6. Enabling anything riskier (future)

Any egress-enabling action must be explicit, visibly risky, time-bounded,
logged and reversible. Never implied by an env file, never enabled by default.
T2 is the first tier that adds any egress path; it does so exactly once
(`--allow-host`, per-session, confirmed every `up`, every decision logged,
state destroyed with the project) and refuses E210 without it. T3+ remains a
recipe, not a feature.

## 7. Reproducing the measurements

```bash
docker network create --internal ww-probe
docker run -d --rm --name ww-probe-redis --network ww-probe \
    -p 127.0.0.1:16379:6379 redis:7-alpine
docker exec ww-probe-redis redis-cli ping      # PONG  → service is up
docker port ww-probe-redis                     # (empty) → publish was dropped
# host connect to 127.0.0.1:16379 fails; container has no default route:
docker run --rm --network ww-probe busybox sh -c 'ip route; wget -T3 -q -O- http://1.1.1.1; echo exit=$?'
docker rm -f ww-probe-redis && docker network rm ww-probe
```
