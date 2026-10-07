"""Security-state visibility (Phases 6–7).

Phase 6: one function, ``collect_security_posture``, assembles everything the
CLI needs to show a contributor what is actually enforced right now — profile
and tier, container hardening (read from the Docker daemon, not from compose
files), network/egress verification results, and telemetry provenance.

Phase 7: ``SECURITY_CHECKS`` is the machine-readable checklist those results
are scored against; ``sandbox.sh verify`` runs the same checks against a live
sandbox and exits non-zero on any failure, so the isolation claims stay
testable instead of rhetorical.

No claims are invented here: every field is either read from the daemon,
executed live, or reported as ``unknown``. The module never raises for
missing pieces — degraded visibility is data, not an error.
"""
from __future__ import annotations

from typing import Callable

from sandbox_kit import compose, state
from sandbox_kit.gates import GateFailure

def _svc(h: dict) -> bool:
    """True when at least one container was actually inspected."""
    return bool(h.get("services_seen"))


# (id, description, extract_fn(result_dict) -> True | False | None)
# None means "cannot know from the collected data" — reported as unknown,
# never silently scored as a pass. result_dict keys match
# collect_security_posture(); a missing key means unknown too.
SECURITY_CHECKS: list[tuple[str, str, Callable[[dict], bool | None]]] = [
    ("no-privileged",
     "no container runs privileged",
     lambda r: None if not _svc(r["hardening"]) else r["hardening"]["privileged"] is False),
    ("caps-dropped-all",
     "every container dropped ALL Linux capabilities",
     lambda r: None if not _svc(r["hardening"]) else r["hardening"]["caps_dropped_all"] is True),
    ("no-new-privileges",
     "no-new-privileges set on every container",
     lambda r: None if not _svc(r["hardening"]) else r["hardening"]["no_new_privileges"] is True),
    ("readonly-rootfs",
     "every container root filesystem read-only",
     lambda r: None if not _svc(r["hardening"]) else r["hardening"]["readonly_rootfs"] is True),
    ("nonroot-1000",
     "every container runs as uid 1000 (non-root)",
     lambda r: None if not _svc(r["hardening"]) else r["hardening"]["uid_1000"] is True),
    ("no-bind-mounts",
     "zero host bind mounts into the sandbox",
     lambda r: None if not _svc(r["hardening"]) else r["hardening"]["bind_mounts"] == 0),
    ("resource-limits",
     "CPU/memory/PID limits set on every container",
     lambda r: None if not _svc(r["hardening"]) else r["hardening"]["resource_limits"] is True),
    ("egress-denied",
     "egress self-check denies outbound connectivity on every plane",
     lambda r: r["egress"].get("denied")),
    ("no-docker-socket",
     "no docker socket reachable from the app container",
     lambda r: None if r["docker_socket"].get("reachable") is None
     else (r["docker_socket"]["reachable"] is False)),
    ("loopback-only-publish",
     "every published port binds 127.0.0.1 (or nothing is published)",
     lambda r: r["ports"].get("all_loopback")),
    ("telemetry-local-marked",
     "synthetic telemetry carries the LOCAL marker (provenance intact)",
     lambda r: r["provenance"].get("local_marked")),
    ("no-restart-policies",
     "no restart policies (sandbox never resurrects itself)",
     lambda r: None if not _svc(r["hardening"]) else r["hardening"]["restart_never"] is True),
]


def _extract_hardening(project: str) -> tuple[dict, list]:
    """Read effective per-container settings from the daemon. Never raises for
    missing containers; returns (aggregate, per_service_errors)."""
    agg = {
        "services_seen": 0,
        "privileged": None,
        "caps_dropped_all": None,
        "no_new_privileges": None,
        "readonly_rootfs": None,
        "uid_1000": None,
        "bind_mounts": 0,
        "resource_limits": None,
        "restart_never": None,
    }
    errors: list[str] = []
    rows = compose.ps(project)
    names = [r.get("Service") for r in rows if r.get("Service")]
    if not names:
        return agg, ["no containers found for project"]
    for svc in names:
        cid = compose.container_id(project, svc)
        if not cid:
            errors.append(f"{svc}: no container")
            continue
        try:
            d = compose.inspect(cid)
        except Exception as exc:  # daemon hiccup = data, not crash
            errors.append(f"{svc}: inspect failed ({exc})")
            continue
        host = d.get("HostConfig") or {}
        cfg = d.get("Config") or {}
        agg["services_seen"] += 1
        priv = bool(host.get("Privileged"))
        caps = host.get("CapDrop") or []
        sec = " ".join(host.get("SecurityOpt") or [])
        user = str(cfg.get("User") or "")
        mem = bool(host.get("Memory"))
        cpu = bool(host.get("NanoCpus"))
        pids = bool(host.get("PidsLimit"))
        restart = (host.get("RestartPolicy") or {}).get("Name", "no")
        binds = [m for m in (d.get("Mounts") or []) if m.get("Type") == "bind"]
        agg["bind_mounts"] += len(binds)
        # AND across services; None stays None until at least one service seen
        agg["privileged"] = (agg["privileged"] if agg["privileged"] is not None else False) or priv
        agg["caps_dropped_all"] = (caps == ["ALL"]) if agg["caps_dropped_all"] is None \
            else (agg["caps_dropped_all"] and caps == ["ALL"])
        agg["no_new_privileges"] = ("no-new-privileges" in sec) if agg["no_new_privileges"] is None \
            else (agg["no_new_privileges"] and "no-new-privileges" in sec)
        agg["readonly_rootfs"] = (host.get("ReadonlyRootfs") is True) if agg["readonly_rootfs"] is None \
            else (agg["readonly_rootfs"] and host.get("ReadonlyRootfs") is True)
        agg["uid_1000"] = (user.split(":")[0] == "1000") if agg["uid_1000"] is None \
            else (agg["uid_1000"] and user.split(":")[0] == "1000")
        rl = mem and cpu and pids
        agg["resource_limits"] = rl if agg["resource_limits"] is None else (agg["resource_limits"] and rl)
        agg["restart_never"] = (restart in ("no", "")) if agg["restart_never"] is None \
            else (agg["restart_never"] and restart in ("no", ""))
    return agg, errors


def _check_docker_socket(project: str) -> dict:
    """Is the docker socket reachable from inside sb-app? The only correct
    answer for the sandbox is no — verified by trying, not by trusting compose."""
    out = {"reachable": None, "checked": False}
    cid = compose.container_id(project, "sb-app")
    if not cid:
        return out
    try:
        result = compose._run(
            ["docker", "exec", cid, "sh", "-c",
             "ls /var/run/docker.sock >/dev/null 2>&1 && echo REACHABLE || echo ABSENT"],
            timeout=30)
        out["checked"] = True
        out["reachable"] = "REACHABLE" in (result.stdout or "")
    except Exception as exc:
        out["error"] = str(exc)[:120]
    return out


def _published_ports(project: str) -> dict:
    """Real publishes from the daemon. Contract: none, or all loopback-bound."""
    out = {"published": [], "all_loopback": None}
    try:
        rows = compose.ps(project)
    except Exception as exc:
        out["error"] = str(exc)[:120]
        return out
    for r in rows:
        for pub in (r.get("Publishers") or []):
            # compose ps JSON: "PublishedPort" (0/None = merely exposed, NOT
            # published); docker ps JSON: "PublicPort". Tolerate both — and
            # never count a bare exposure as a publish (that conflation once
            # flipped all_loopback on a perfectly-hardened boot).
            port = pub.get("PublishedPort", pub.get("PublicPort"))
            if not port:
                continue
            url = pub.get("URL") or ""
            out["published"].append(f"{url}:{port}->{pub.get('TargetPort')}")
            out["all_loopback"] = (url == "127.0.0.1") if out["all_loopback"] is None \
                else (out["all_loopback"] and url == "127.0.0.1")
    if out["all_loopback"] is None:
        out["all_loopback"] = True  # nothing published = vacuously compliant
    return out


def collect_security_posture(name: str, deep: bool = True,
                             project: str | None = None) -> dict:
    """Assemble the full security picture for one sandbox. Never raises for
    degraded visibility; every block carries its own ok/unknown/error state.

    ``project`` overrides the compose project (used by the live suite, which
    boots containers directly without a launcher state file)."""
    st = state.read_state(name) or {}
    explicit = project is not None  # caller manages this boot themselves
    project = project or st.get("project") or compose.project_name(name)
    if not st and not explicit:
        # Unbuilt: return before any daemon probing — there is nothing to
        # inspect, and a vacuous 'nothing published = pass' would be a lie.
        return {
            "sandbox": name, "state": None, "profile": None, "tier": None,
            "hardening": {}, "egress": {"denied": None},
            "ports": {"published": [], "all_loopback": None},
            "docker_socket": {"checked": False, "reachable": None},
            "provenance": {"local_marked": None},
            "errors": ["sandbox is unbuilt; nothing to inspect"],
        }
    out = {
        "sandbox": name,
        "state": st.get("state"),
        "profile": st.get("profile"),
        "tier": st.get("tier"),
        "hardening": {},
        "egress": {"denied": None},
        "ports": _published_ports(project),
        "docker_socket": _check_docker_socket(project) if deep else {"checked": False},
        "provenance": {"local_marked": None},
        "errors": [],
    }
    if not st or st.get("state") != "RUNNING":
        # Only noise on the launcher path; an explicitly-passed project means
        # the caller is verifying a boot they manage themselves (live suite).
        if not explicit:
            out["errors"].append("no RUNNING state marker; posture read live from the daemon")

    agg, errs = _extract_hardening(project)
    out["hardening"] = agg
    out["errors"].extend(errs)

    if deep and agg.get("services_seen") and compose.container_id(project, "sb-app"):
        # Live egress verification reuses the exact canary `up` ran, so the
        # claim in `status`/`verify` is the same control, re-executed. With no
        # containers there is nothing to verify — that stays unknown, not FAIL.
        try:
            verdict = compose.verify_egress_denied_all(project)
            out["egress"]["denied"] = True
            out["egress"]["verdict"] = verdict
        except GateFailure as gf:
            out["egress"]["denied"] = False
            out["egress"]["error"] = gf.code
            out["errors"].append(f"egress: {gf.message.splitlines()[0]}")
        except Exception as exc:
            out["egress"]["error"] = str(exc)[:120]
            out["errors"].append(f"egress check failed: {exc}")

    # Provenance: receipt digest must equal the deterministic corpus digest.
    try:
        receipt = compose.read_seed_receipt(project)
        if receipt:
            expected = seed_corpus_digest()
            out["provenance"] = {
                "local_marked": True,
                "digest_matches": receipt.get("corpus_sha256") == expected,
                "events": receipt.get("events"),
                "sessions": receipt.get("sessions"),
            }
    except Exception:
        pass  # receipt absent — provenance stays unknown
    return out


def seed_corpus_digest() -> str:
    """Digest of the deterministic corpus the seed is expected to produce."""
    from sandbox_kit.seed import corpus as seed_corpus
    return seed_corpus.corpus_digest()


def run_security_checks(result: dict) -> list[dict]:
    """Score collected posture against SECURITY_CHECKS. Tri-state: True→pass,
    False→FAIL, None/missing→unknown. Never raises; degraded visibility is
    reported, never silently scored as a pass."""
    rows = []
    for cid, desc, fn in SECURITY_CHECKS:
        try:
            res = fn(result)
        except (KeyError, TypeError, IndexError):
            res = None
        except Exception as exc:  # noqa: BLE001 — a broken check is data
            rows.append({"id": cid, "desc": desc,
                         "status": "error", "passed": None, "detail": str(exc)[:80]})
            continue
        if res is True:
            rows.append({"id": cid, "desc": desc, "status": "pass", "passed": True})
        elif res is False:
            rows.append({"id": cid, "desc": desc, "status": "FAIL", "passed": False})
        else:
            rows.append({"id": cid, "desc": desc, "status": "unknown", "passed": None})
    return rows


def format_posture(result: dict, checks: list[dict]) -> str:
    """Human rendering — the security-state card."""
    lines = []
    lines.append(f"sandbox '{result['sandbox']}' — security state "
                 f"[{result.get('profile') or '?'} / {result.get('tier') or '?'}] "
                 f"state={result.get('state')}")
    h = result.get("hardening") or {}
    if h:
        lines.append(f"  containers:      {h.get('services_seen')} inspected")
        lines.append(f"  privileged:      {h.get('privileged')}")
        lines.append(f"  caps dropped:    ALL={h.get('caps_dropped_all')}")
        lines.append(f"  no-new-privs:    {h.get('no_new_privileges')}")
        lines.append(f"  readonly rootfs: {h.get('readonly_rootfs')}")
        lines.append(f"  uid:             1000-only={h.get('uid_1000')}")
        lines.append(f"  bind mounts:     {h.get('bind_mounts')}")
        lines.append(f"  resource limits: {h.get('resource_limits')}")
        lines.append(f"  restart policy:  never={h.get('restart_never')}")
    e = result.get("egress") or {}
    lines.append(f"  egress denied:   {e.get('denied')}"
                 + (f"  ({e['verdict']})" if e.get("verdict") else ""))
    p = result.get("ports") or {}
    lines.append(f"  published ports: {p.get('published') or 'none'}"
                 + ("" if p.get("all_loopback") else "  ⚠ NON-LOOPBACK"))
    d = result.get("docker_socket") or {}
    if d.get("checked"):
        lines.append(f"  docker socket:   reachable={d.get('reachable')}")
    pr = result.get("provenance") or {}
    if pr:
        lines.append(f"  provenance:      LOCAL-marked={pr.get('local_marked')}"
                     + (f", digest matches={pr.get('digest_matches')}"
                        if pr.get("digest_matches") is not None else ""))
    lines.append("")
    lines.append("  isolation checks:")
    for c in checks:
        mark = {"pass": "✓", "FAIL": "✗"}.get(c["status"], "?")
        lines.append(f"    [{mark}] {c['id']}: {c['desc']}"
                     + ("" if c["status"] in ("pass", "FAIL") else f" ({c['status']})"))
    if result.get("errors"):
        lines.append("")
        lines.append("  notes:")
        for err in result["errors"]:
            lines.append(f"    • {err}")
    lines.append("")
    lines.append(f"  {state._NON_CLAIMS}")
    return "\n".join(lines)
