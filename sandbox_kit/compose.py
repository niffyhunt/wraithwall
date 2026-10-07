"""Docker/compose orchestration for the sandbox (Phase 3).

Everything that touches the container runtime goes through this module so there
is exactly one place to audit. Rules it follows:

* **Argument lists, never a shell.** `subprocess.run([...])` with a list, so no
  developer-supplied value is ever interpreted by a shell.
* **One project per sandbox.** `-p ww-sb-<name>` is passed on every compose
  invocation. Two sandboxes therefore get distinct projects, networks and volume
  prefixes (G11).
* **Fail-closed.** A missing image, a non-zero exit, an unreadable inspection, a
  canary that cannot be evaluated — all are failures, never a silent pass.
* **Build context is an allowlist.** Images are built from a prepared directory
  containing only the paths named in `images.BUILD_CONTEXT_ALLOWLIST`, so the
  ~5 GB repository is never streamed to the daemon and a newly added secret
  cannot slip into an image.

The launcher owns the lifecycle: `up` builds (if needed), starts the project,
waits for the egress canary, verifies the hardening posture from `docker
inspect`, and only then reports success. Any failure tears the project down
(`down -v`) so a failed start never leaves containers behind (E2xx).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

from sandbox_kit import assets
from sandbox_kit.compose_constants import EGRESS_NETWORK, RESEARCH_PROFILE
from sandbox_kit.gates import GateFailure
from sandbox_kit.images import APP_IMAGE, DOCKERFILES, SEED_IMAGE, allowed_paths

#: Synthetic session ids are fixed-length lowercase hex (corpus.session_ids).
_SID_RE = re.compile(r"^[0-9a-f]{16}$")

REPO_ROOT = assets.ASSET_ROOT
COMPOSE_FILE = REPO_ROOT / "compose.sandbox.yml"

BUILD_TIMEOUT = 1800
COMPOSE_TIMEOUT = 300

CODE_EGRESS = "E202"
CODE_BANNED_OPTION = "E205"
CODE_UNHEALTHY = "E305"

_DOCS = "Docs: docs/sandbox/network.md"

#: The egress-deny canary, as executed by `sb-busybox`. This is the single
#: source of truth: `compose.sandbox.yml` embeds the same script inline, and
#: `tests/test_sandbox_static_gates.py` asserts the two stay identical so the
#: two can never drift apart.
#:
#: It deliberately contains **no shell variables**. Compose interpolates
#: `$name` inside these strings, so an earlier version using a `$fail` flag was
#: silently rewritten to `if [ "" = "1" ]` and passed unconditionally — a false
#: pass that the live suite caught. Any future edit must keep it variable-free.
#: Built line-by-line rather than as one triple-quoted literal: a triple-quoted
#: string cannot end with a quote character, which silently swallowed the
#: closing quote of the final `echo` when this was first written.
CANARY_SCRIPT = "\n".join([
    "if wget -T 3 -q -O- http://1.1.1.1 >/dev/null 2>&1 \\",
    "   || wget -T 3 -q -O- http://example.com >/dev/null 2>&1 \\",
    "   || nslookup example.com >/dev/null 2>&1 \\",
    "   || ping -c1 -W2 1.1.1.1 >/dev/null 2>&1; then",
    '  echo "EGRESS_PROBE_FAILED: an egress path exists from this plane"',
    "  exit 1",
    "fi",
    'echo "EGRESS_DENY_OK: no internet or DNS path from this plane"',
])


def normalize_canary(text: str) -> str:
    """Whitespace-insensitive view of a canary script, for drift checks."""
    return " ".join(text.split())


# ── primitives ─────────────────────────────────────────────────────────────

def project_name(sandbox_name: str) -> str:
    """Compose project name for a sandbox instance (G11 separation)."""
    safe = "".join(ch for ch in sandbox_name.lower() if ch.isalnum() or ch in "-_")
    if not safe:
        raise ValueError(f"invalid sandbox name: {sandbox_name!r}")
    return f"ww-sb-{safe}"


def _run(cmd: list, timeout: int = COMPOSE_TIMEOUT, check: bool = True,
         env: dict | None = None) -> subprocess.CompletedProcess:
    result = subprocess.run(
        cmd, cwd=str(REPO_ROOT), capture_output=True, text=True,
        timeout=timeout, env=env,
    )
    if check and result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd[:4])}…\n"
            f"{(result.stderr or result.stdout or '').strip()[:2000]}"
        )
    return result


def _run_bytes(cmd: list, timeout: int = COMPOSE_TIMEOUT,
               check: bool = True) -> subprocess.CompletedProcess:
    """Binary-safe `_run`. ttylogs contain arbitrary bytes (length prefixes,
    command payloads) and text-mode capture UTF-8-decodes them, so any byte
    >= 0x80 would explode before the caller ever sees the content."""
    result = subprocess.run(
        cmd, cwd=str(REPO_ROOT), capture_output=True, timeout=timeout,
    )
    if check and result.returncode != 0:
        err = (result.stderr or b"").decode("utf-8", "replace")
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(cmd[:4])}…\n"
            f"{err.strip()[:2000]}"
        )
    return result


def _compose(project: str, args: list, **kw) -> subprocess.CompletedProcess:
    return _run(["docker", "compose", "-p", project, "-f", str(COMPOSE_FILE)] + args, **kw)


def docker_available() -> bool:
    try:
        return _run(["docker", "version", "--format", "{{.Server.Version}}"],
                    timeout=30, check=False).returncode == 0
    except Exception:
        return False


# ── build context + images ─────────────────────────────────────────────────

def prepare_build_context(dest: Path) -> Path:
    """Materialise the allowlisted build context under `dest`. Returns it.

    Both layouts produce the *same* tree the Dockerfiles read:
    ``src/ sandbox_kit/ detonate_sandbox/ requirements.txt``. In a checkout
    that is a copy of the allowlist; in an installed wheel the package
    directories are staged under ``src/`` because the wheel layout has no
    source directory to copy.
    """
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True, exist_ok=True)
    if assets.IS_CHECKOUT:
        for rel in allowed_paths(REPO_ROOT):
            _copy_into(REPO_ROOT / rel, dest / rel)
    else:
        sp = assets.site_packages()
        _copy_into(sp / "wraithwall", dest / "src" / "wraithwall")
        _copy_into(sp / "sandbox_kit", dest / "sandbox_kit")
        _copy_into(assets.ASSET_ROOT / "detonate_sandbox", dest / "detonate_sandbox")
        _copy_into(assets.ASSET_ROOT / "requirements.txt", dest / "requirements.txt")
    return dest


def _copy_into(src: Path, target: Path) -> None:
    """Copy a file or directory into the build context, skipping caches."""
    if not src.exists():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    if src.is_dir():
        shutil.copytree(src, target, dirs_exist_ok=True, ignore=assets.ignored)
    else:
        shutil.copy2(src, target)


def images_present() -> bool:
    for tag in (APP_IMAGE, SEED_IMAGE):
        if _run(["docker", "image", "inspect", tag], timeout=60, check=False).returncode != 0:
            return False
    return True


# ── lifecycle ──────────────────────────────────────────────────────────────

def up(project: str, extra_env: dict | None = None,
       profiles: list | None = None) -> None:
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    if profiles:
        # Global-flag placement (`docker compose --profile X up`): the
        # subcommand-level `up --profile` is rejected by some compose plugin
        # versions still in the wild; the global form works on all of them.
        _run(["docker", "compose", "--profile", ",".join(profiles),
              "-p", project, "-f", str(COMPOSE_FILE), "up", "-d"],
             env=env, timeout=COMPOSE_TIMEOUT)
        return
    _compose(project, ["up", "-d"], env=env, timeout=COMPOSE_TIMEOUT)


def build_images(context_dir: Path, log=print, services: list | None = None) -> None:
    """Build sandbox images from the prepared context (one at a time).

    `services` limits the build to the images for those compose services
    (`rebuild-images`); the default builds everything.
    """
    wanted = set(services or ("sb-app", "sb-seed"))
    for tag, dockerfile in DOCKERFILES.items():
        if tag == APP_IMAGE and "sb-app" not in wanted:
            continue
        if tag == SEED_IMAGE and "sb-seed" not in wanted:
            continue
        log(f"  building {tag} from {dockerfile} …")
        _run(["docker", "build", "-f", str(REPO_ROOT / dockerfile), "-t", tag,
              str(context_dir)], timeout=BUILD_TIMEOUT)


def down(project: str, remove_volumes: bool = True) -> None:
    args = ["down", "--remove-orphans"]
    if remove_volumes:
        args.append("-v")
    _compose(project, args, check=False)


def ps(project: str) -> list:
    result = _compose(project, ["ps", "-a", "--format", "json"], check=False)
    out = (result.stdout or "").strip()
    if not out:
        return []
    rows = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def digest_rows(project: str) -> list:
    """One row per running/stopped service with the daemon's actual image
    identity: {Service, Image, ImageID, RepoDigests}. Powers the Phase 10
    digest manifest ("what am I really running?")."""
    rows = []
    for ps_row in ps(project):
        svc = ps_row.get("Service") or ""
        image = ps_row.get("Image") or ""
        if not svc or not image:
            continue
        row = {"Service": svc, "Image": image,
               "ImageID": ps_row.get("ID") or "", "RepoDigests": []}
        try:
            r = _run(["docker", "image", "inspect", "--format",
                      "{{json .RepoDigests}}", image], timeout=60)
            digests = json.loads((r.stdout or "").strip() or "[]")
            if isinstance(digests, list):
                row["RepoDigests"] = digests
        except Exception:
            pass  # recorded honestly as empty — unknown, not matched
        rows.append(row)
    return rows


def container_id(project: str, service: str) -> str | None:
    result = _compose(project, ["ps", "-a", "-q", service], check=False)
    cid = (result.stdout or "").strip().splitlines()
    return cid[0].strip() if cid and cid[0].strip() else None


def inspect(container: str) -> dict:
    result = _run(["docker", "inspect", container], timeout=60)
    data = json.loads(result.stdout)
    if not data:
        raise RuntimeError(f"no inspect data for {container}")
    return data[0]


def wait_healthy(project: str, service: str = "sb-app", timeout: int = 180) -> str:
    """Wait for a container healthcheck. Returns 'healthy', 'exited' or the
    last observed status on timeout.

    The launcher refuses to report RUNNING on anything but 'healthy'. Without
    this, a container that boots and immediately dies (exit 3 from a failed
    import, for example) still satisfies the canary and posture checks and the
    sandbox would claim to be running while nothing was serving.
    """
    deadline = time.time() + timeout
    last = "unknown"
    while time.time() < deadline:
        cid = container_id(project, service)
        if cid:
            state = inspect(cid).get("State") or {}
            if state.get("Status") == "exited":
                return "exited"
            last = ((state.get("Health") or {}).get("Status")) or state.get("Status") or "unknown"
            if last == "healthy":
                return last
        time.sleep(3)
    return last


def require_healthy(project: str, service: str = "sb-app", timeout: int = 180) -> None:
    """Raise E305 unless the service reports healthy within the timeout."""
    status = wait_healthy(project, service, timeout=timeout)
    if status != "healthy":
        raise GateFailure(
            CODE_UNHEALTHY,
            f"✗ Service '{service}' is not healthy after {timeout}s "
            f"(gates and self-check passed, health failed; last status: {status}).\n"
            f"  Inspect: docker logs $(docker compose -p {project} ps -a -q {service})\n"
            f"  Code: {CODE_UNHEALTHY}\n  {_DOCS}",
        )


def wait_for_exit(project: str, service: str, timeout: int = 120) -> int | None:
    """Wait for a one-shot service to exit; return its exit code (None = timeout)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        cid = container_id(project, service)
        if cid:
            state = inspect(cid).get("State") or {}
            if state.get("Status") == "exited":
                return int(state.get("ExitCode", -1))
        time.sleep(1)
    return None


# ── seed lifecycle (Phase 4) ────────────────────────────────────────────────

SEED_SERVICE = "sb-seed"
SEED_RECEIPT_PATH = "/state/synthetic/seed_receipt.json"


# ── uplink (Phase 5) ────────────────────────────────────────────────────────

#: Third network (Phase 5 uplink). NON-internal by necessity — a loopback
#: publish requires a DNAT path — but with IP masquerade disabled (no NAT out)
#: and the container's resolv.conf pointed at 127.0.0.1 so Docker's embedded
#: DNS cannot forward lookups outward (the DNS exfiltration path measured on
#: masquerade-disabled bridges; see docs/sandbox/network.md). The egress
#: canary re-runs against this network on every up with the uplink attached.
UPLINK_SERVICE = "sb-uplink"          # the proxy container (published port)
UPLINK_NETWORK = "ww-uplink-net"
UPLINK_SERVICE_NET = "uplink"
#: The in-app egress canary runs INSIDE the application container — it is the
#: app that gained a gateway-bearing network, so it is the app whose egress
#: must be denied. (Deliberately a separate constant from UPLINK_SERVICE:
#: conflating them once made the launcher read the port off the wrong
#: container.)
UPLINK_PROBE_SERVICE = "sb-app"


def verify_egress_denied_all(project: str, timeout: int = 120) -> str:
    """G7 over the app's full network set, including the uplink (Phase 5).

    `verify_egress_denied` covers the two internal planes via their dedicated
    canaries. This adds the decisive control for the uplink bridge: the app
    itself — which has a gateway on that network — must have no egress path
    from inside it. Runs only when the app container is up.
    """
    cid = container_id(project, UPLINK_PROBE_SERVICE)
    if not cid:
        return "UPLINK_CANARY_SKIPPED_APP_DOWN"
    result = _run(["docker", "exec", cid, "sh", "-c", CANARY_SCRIPT],
                  check=False, timeout=timeout)
    if result.returncode != 0:
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        raise GateFailure(
            CODE_EGRESS,
            "✗ ISOLATION SELF-CHECK FAILED: the application has an egress path "
            "on the uplink network.\n"
            f"  This must never happen. Startup refused; containers are being stopped.\n"
            f"  Canary output: {output[-500:]}\n"
            f"  Code: {CODE_EGRESS}\n  {_DOCS}")
    return "UPLINK_EGRESS_DENY_OK"


def reset_uplink_network(project: str) -> None:
    """Remove the project's uplink network so compose recreates it with the
    CURRENT driver options.

    Driver options apply only at creation; compose silently reuses an
    existing network under its original options. The live suite caught
    exactly that: a network created while ``enable_icc`` was disabled kept
    dropping same-subnet traffic after the file enabled it, because Docker
    never inserts the intra-bridge ACCEPT rule for a network created with
    ICC off — and on a default-deny host that means FORWARD DROP.
    """
    name = f"{project}_ww-uplink-net"
    _run(["docker", "network", "rm", name], check=False, timeout=60)


def probe_loopback_publish(host_port: int, timeout: float = 8.0) -> bool:
    """E107 probe: can the host actually reach a published loopback port?

    The uplink publish is host-originated traffic to a container IP, which
    default-deny host firewalls (ufw OUTPUT policy DROP) can silently discard
    even though docker-proxy, DNAT, and the container itself are all healthy.
    Verified live: exactly that failure mode on a hardened VPS. Fail-closed
    beats silent: a proxy that the developer cannot reach must not report up.
    """
    import socket as _socket
    try:
        with _socket.create_connection(("127.0.0.1", host_port), timeout=timeout):
            return True
    except OSError:
        return False


def uplink_port(project: str) -> int | None:
    """The loopback host port the app's UI is published on, if any."""
    cid = container_id(project, UPLINK_SERVICE)
    if not cid:
        return None
    ports = (inspect(cid).get("NetworkSettings") or {}).get("Ports") or {}
    binding = (ports.get("8000/tcp") or [])
    if not binding:
        return None
    try:
        return int(binding[0].get("HostPort"))
    except (TypeError, ValueError):
        return None

def wait_seed_complete(project: str, timeout: int = 300) -> int | None:
    """Wait for the one-shot seed container to finish (exit code; None = timeout)."""
    return wait_for_exit(project, SEED_SERVICE, timeout=timeout)


# ── research plane (Phase 11, T2) ───────────────────────────────────────────

#: One-shot services whose clean exit proves the research plane's closure.
RESEARCH_CHECK_SERVICES = ("sb-policy-selftest", "sb-research-canary")


def verify_research_plane(project: str, timeout: int = 180) -> str:
    """T2 dynamic self-checks: policy classification + research-plane closure.

    Two one-shot containers must exit 0:
    * ``sb-policy-selftest`` — the deny policy inside the egress image
      classifies every canonical deny case as DENIED (E212 path if not);
    * ``sb-research-canary`` — from inside the detonation image, direct IP
      egress and DNS must both fail (the classic E202, on the new plane).

    Any timeout or non-zero exit refuses startup; the caller tears the
    sandbox down. A missing container is a failure, never a skip: a research
    start without its self-checks is not a research start.
    """
    for svc in RESEARCH_CHECK_SERVICES:
        code = wait_for_exit(project, svc, timeout=timeout)
        if code is None:
            raise GateFailure(
                CODE_EGRESS if svc == "sb-research-canary" else "E212",
                f"✗ Research self-check '{svc}' did not complete within "
                f"{timeout}s. Startup refused; containers are being stopped.\n"
                f"  Code: {'E202' if svc == 'sb-research-canary' else 'E212'}\n  {_DOCS}")
        if code != 0:
            output = ""
            cid = container_id(project, svc)
            if cid:
                logs = _run(["docker", "logs", cid], check=False)
                output = ((logs.stdout or "") + (logs.stderr or "")).strip()
            if svc == "sb-research-canary":
                raise GateFailure(
                    CODE_EGRESS,
                    "✗ ISOLATION SELF-CHECK FAILED: the research plane has a "
                    "direct egress or DNS path.\n"
                    f"  This must never happen. Startup refused; containers are being stopped.\n"
                    f"  Canary output: {output[-500:]}\n"
                    f"  Code: {CODE_EGRESS}\n  {_DOCS}")
            raise GateFailure(
                "E212",
                "✗ EGRESS POLICY SELF-TEST FAILED: the deny policy inside the "
                "egress image misclassified a canonical deny case.\n"
                f"  Output: {output[-500:]}\n"
                "  The research plane must not start with a policy that cannot\n"
                "  prove itself. Rebuild the egress image and re-run.\n"
                "  Code: E212\n  " + _DOCS)
    return "RESEARCH_PLANE_CLOSED_OK"


def read_seed_receipt(project: str) -> dict:
    """Read the seed receipt from the shared in-project volume via the app
    container (no docker socket, no host bind — the file lives on the same
    named volume as the corpus, and `docker exec cat` on the project's own
    container is how the launcher inspects sandbox state)."""
    cid = container_id(project, "sb-app")
    if not cid:
        raise RuntimeError("sb-app container not found")
    result = _run(["docker", "exec", cid, "cat", SEED_RECEIPT_PATH],
                  check=False, timeout=60)
    if result.returncode != 0:
        raise RuntimeError("seed receipt not found (seed did not complete?)")
    return json.loads(result.stdout)


def read_ttylog(project: str, session_id: str) -> bytes:
    """Fetch one synthetic ttylog from the shared volume (validated id)."""
    if not _SID_RE.fullmatch(session_id):
        raise ValueError("invalid session id")
    cid = container_id(project, "sb-app")
    if not cid:
        raise RuntimeError("sb-app container not found")
    result = _run_bytes(["docker", "exec", cid, "cat",
                         "/state/synthetic/tty/" + session_id],
                        check=False, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"ttylog for {session_id} not found")
    return result.stdout or b""


# ── logs / lifecycle (Phase 5) ─────────────────────────────────────────────

def service_logs(project: str, service: str | None = None, tail: int = 200,
                 follow: bool = False) -> int:
    """Print container logs (optionally one service). Returns a process exit code.

    Read-only: `docker compose logs` never mutates state. `-f` is only offered
    in the foreground; this call streams until interrupted, which is exactly
    what the user asked for.
    """
    args = ["logs", "--tail", str(tail), "--no-color"]
    if follow:
        args.append("-f")
    if service:
        args.append(service)
    result = _compose(project, args, check=False,
                      timeout=None if follow else COMPOSE_TIMEOUT)
    if result.stdout:
        print(result.stdout, end="" if result.stdout.endswith("\n") else "\n")
    if result.stderr:
        print(result.stderr, end="" if result.stderr.endswith("\n") else "\n",
              file=sys.stderr)
    return result.returncode


def export_bundle(project: str, dest: Path) -> dict:
    """Assemble the sanitized telemetry export bundle into ``dest``.

    Everything is read from the sandbox's own volume/containers: the synthetic
    JSONL, the tty logs, the pipeline session records and the seed receipt.
    Nothing here talks to the network. The caller (CLI) runs the E307
    secret-shape gate over the finished file list before it is announced.
    Returns a manifest dict.
    """
    cid = container_id(project, "sb-app")
    if not cid:
        raise RuntimeError("sb-app container not found; is the sandbox running?")

    files: dict[str, bytes] = {}
    for name in ("synthetic/synthetic.jsonl", "synthetic/seed_receipt.json"):
        r = _run_bytes(["docker", "exec", cid, "cat", f"/state/{name}"],
                       check=False, timeout=60)
        if r.returncode == 0 and r.stdout:
            files[name.split("/")[-1]] = r.stdout
    if "synthetic.jsonl" not in files:
        raise RuntimeError("synthetic.jsonl not found in the sandbox volume")

    tty_names = _run_bytes(
        ["docker", "exec", cid, "sh", "-c", "ls /state/synthetic/tty"],
        check=False, timeout=60)
    if tty_names.returncode == 0 and tty_names.stdout:
        for sid in sorted(tty_names.stdout.decode("ascii", "replace").split()):
            if not _SID_RE.fullmatch(sid):
                continue
            r = _run_bytes(["docker", "exec", cid, "cat",
                            f"/state/synthetic/tty/{sid}"],
                           check=False, timeout=60)
            if r.returncode == 0:
                files[f"tty/{sid}.ttylog"] = r.stdout

    sessions = _run(["docker", "exec", cid, "python", "-c",
                     "import json,os,redis\n"
                     "r=redis.from_url(os.environ.get('REDIS_URL',"
                     "'redis://127.0.0.1:6379/0'),decode_responses=True)\n"
                     "out=[r.get('cowrie_completed:'+s) "
                     "for s in r.lrange('cowrie_sessions:recent',0,-1)]\n"
                     "print(json.dumps([json.loads(x) for x in out if x]))"],
                    check=False, timeout=120)
    if sessions.returncode == 0 and sessions.stdout.strip():
        files["sessions.json"] = sessions.stdout.strip().encode() + b"\n"

    dest.mkdir(parents=True, exist_ok=False)
    manifest = {
        "exported_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "project": project,
        "marker": "WRAITHWALL-LOCAL-SYNTHETIC",
        "files": {},
    }
    import hashlib
    for rel, blob in sorted(files.items()):
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(blob)
        manifest["files"][rel] = {
            "bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
        }
    (dest / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return manifest


SECRET_RULES = (
    ("AWS access key id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS secret key shape", re.compile(r"\b[A-Za-z0-9/+=]{40}\b")),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.")),
    ("Slack token", re.compile(r"xox[baprs]-")),
    ("OpenAI-style key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("seed phrase", re.compile(
        r"\b(?:abandon|boy|retrieve)\s+(?:\w+\s+){10,12}\w+\b", re.I)),
)


def scan_bundle_for_secrets(dest: Path) -> list:
    """Scan every exported file for secret-shaped strings (E307 gate).

    Returns a list of (rule, path, sample) findings. An empty list is a pass.
    """
    findings = []
    for p in sorted(dest.rglob("*")):
        if not p.is_file():
            continue
        try:
            text = p.read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        for rule, rx in SECRET_RULES:
            m = rx.search(text)
            if m:
                findings.append((rule, str(p), m.group(0)[:8] + "…"))
    return findings


def reset_bundle(project: str, settle_timeout: int = 60) -> list:
    """Reset disposable telemetry state to the clean baseline (G8).

    Removes the synthetic corpus, tty logs, pipeline session records and the
    seed receipt inside the sandbox volume — everything `sb-seed` writes and
    the watcher consumes — while keeping the sandbox itself up. Returns the
    removed key/path inventory.

    Settle wait: the watcher finalizes sessions a few seconds *after* the seed
    exits (tail latency + close handling), so a purge that runs immediately
    after `up` races records that are still being written. `reset` waits until
    the recent-sessions count is stable across a short interval before
    deleting — then purges exactly once.
    """
    cid = container_id(project, "sb-app")
    if not cid:
        raise RuntimeError("sb-app container not found; nothing to reset")

    import time as _time
    _count_py = (
        "import os,redis\n"
        "r=redis.from_url(os.environ.get('REDIS_URL',"
        "'redis://127.0.0.1:6379/0'),decode_responses=True)\n"
        "print(len(r.lrange('cowrie_sessions:recent',0,-1)))")
    deadline = _time.time() + settle_timeout
    last = None
    while _time.time() < deadline:
        r = _run(["docker", "exec", cid, "python", "-c", _count_py],
                 check=False, timeout=30)
        n = (r.stdout or "").strip()
        if r.returncode == 0 and n.isdigit() and n == last:
            break
        last = n
        _time.sleep(3)

    removed = []
    if not cid:
        raise RuntimeError("sb-app container not found; nothing to reset")
    removed = []
    r = _run_bytes(["docker", "exec", cid, "sh", "-c",
                    "rm -rf /state/synthetic/tty && "
                    "rm -f /state/synthetic/synthetic.jsonl "
                    "/state/synthetic/seed_receipt.json"],
                   check=False, timeout=60)
    if r.returncode != 0:
        raise RuntimeError("volume reset failed: "
                           + ((r.stderr or b"").decode("utf-8", "replace")[-300:]))
    removed.append("volume:/state/synthetic (corpus, tty, receipt)")
    result = _run(["docker", "exec", cid, "python", "-c",
                   "import os,redis\n"
                   "r=redis.from_url(os.environ.get('REDIS_URL',"
                   "'redis://127.0.0.1:6379/0'),decode_responses=True)\n"
                   "sids=r.lrange('cowrie_sessions:recent',0,-1)\n"
                   "n=0\n"
                   "for s in sids:\n"
                   "    n+=r.delete('cowrie_completed:'+s)\n"
                   "n+=r.delete('cowrie_sessions:recent')\n"
                   "n+=r.delete('deception:events')\n"
                   "print(n)"], check=False, timeout=120)
    if result.returncode == 0:
        removed.append(f"redis: {result.stdout.strip()} keys "
                       "(sessions, completed, deception events)")
    else:
        removed.append("redis: key purge reported an error "
                       f"({(result.stderr or result.stdout or '')[-200:]})")
    return removed

def verify_hardening(project: str, services: list | None = None) -> dict:
    """Inspect every service against the Stage 2 baseline. Raises on any gap.

    Services passed here are the ones actually known to exist; `up` verifies
    the full set, `recover`/lifecycle callers may pass a subset. Optional
    compose-profile services (the Phase 5 uplink) are verified only when the
    caller lists them — their absence is never a failure by itself.
    """
    services = services or ["sb-redis", "sb-app", "sb-seed", "sb-busybox"]
    findings = []
    seen = {}
    for svc in services:
        cid = container_id(project, svc)
        if not cid:
            findings.append(f"  • {svc}: container not found")
            continue
        d = inspect(cid)
        host = d.get("HostConfig") or {}
        cfg = d.get("Config") or {}
        seen[svc] = {
            "image": cfg.get("Image"),
            "user": cfg.get("User"),
            "caps_dropped": host.get("CapDrop"),
            "security_opt": host.get("SecurityOpt"),
            "readonly_rootfs": host.get("ReadonlyRootfs"),
            "privileged": host.get("Privileged"),
            "memory": host.get("Memory"),
            "nano_cpus": host.get("NanoCpus"),
            "pids_limit": host.get("PidsLimit"),
            "restart": (host.get("RestartPolicy") or {}).get("Name"),
            "network_mode": host.get("NetworkMode"),
        }
        if host.get("Privileged"):
            findings.append(f"  • {svc}: privileged")
        if (host.get("CapDrop") or []) != ["ALL"]:
            findings.append(f"  • {svc}: cap_drop is {host.get('CapDrop')!r}, expected ['ALL']")
        sec = " ".join(host.get("SecurityOpt") or [])
        if "no-new-privileges" not in sec:
            findings.append(f"  • {svc}: no-new-privileges missing")
        if host.get("ReadonlyRootfs") is not True:
            findings.append(f"  • {svc}: root filesystem is writable")
        user = str(cfg.get("User") or "")
        if user.split(":")[0] != "1000":
            findings.append(f"  • {svc}: runs as user {user!r}, expected 1000")
        for key, label in (("Memory", "mem_limit"), ("NanoCpus", "cpus"), ("PidsLimit", "pids_limit")):
            if not host.get(key):
                findings.append(f"  • {svc}: {label} not set")
        if (host.get("RestartPolicy") or {}).get("Name") not in ("no", ""):
            findings.append(f"  • {svc}: restart policy is {host['RestartPolicy']['Name']!r}")
        if host.get("NetworkMode") == "host":
            findings.append(f"  • {svc}: host networking")
        for mount in d.get("Mounts") or []:
            if mount.get("Type") == "bind":
                findings.append(f"  • {svc}: host bind mount {mount.get('Source')}")

    if findings:
        raise GateFailure(
            CODE_BANNED_OPTION,
            "✗ Effective container configuration failed the hardening gates:\n"
            + "\n".join(findings)
            + f"\n  Code: {CODE_BANNED_OPTION}\n  {_DOCS}",
        )
    return seen


def run_canary_on_network(network: str, image: str) -> subprocess.CompletedProcess:
    """Run the canary against an arbitrary network.

    Used by the negative-control test: on a network that *does* have egress the
    canary must exit non-zero. Without that control, an "OK" from the canary in
    the happy path could be vacuous — which is exactly the bug it exists to
    prevent.
    """
    return _run([
        "docker", "run", "--rm",
        "--user", "1000:1000",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges:true",
        "--read-only",
        "--tmpfs", "/tmp:size=16M,nosuid,nodev",
        "--memory", "64m", "--pids-limit", "32",
        "--network", network,
        image,
        "sh", "-c", CANARY_SCRIPT,
    ], check=False, timeout=120)


def verify_egress_denied(project: str, timeout: int = 120) -> str:
    """Run/locate the canaries and require no egress path on ANY plane (G7).

    Since Phase 4 the canary runs on BOTH planes: the application plane
    (``sb-busybox``) and the telemetry plane (``sb-busybox-t``). The telemetry
    plane carries the seed traffic and the event bus, so it must be equally
    unable to reach the internet. A non-zero exit is E202 (isolation self-check
    failed). The canary is only meaningful together with its negative control
    (`test_canary_actually_detects_egress`).
    """
    outputs = []
    for canary in ("sb-busybox", "sb-busybox-t"):
        code = wait_for_exit(project, canary, timeout=timeout)
        if code is None:
            # The canary may not have started with the project; run it explicitly.
            result = _compose(project, ["run", "--rm", "--no-deps", canary],
                              check=False, timeout=timeout)
            code = result.returncode
            output = (result.stdout or "").strip()
        else:
            cid = container_id(project, canary)
            output = ""
            if cid:
                logs = _run(["docker", "logs", cid], check=False)
                output = ((logs.stdout or "") + (logs.stderr or "")).strip()

        if code != 0:
            raise GateFailure(
                CODE_EGRESS,
                "✗ ISOLATION SELF-CHECK FAILED: an egress path exists from a sandbox plane.\n"
                f"  Plane: {canary}. This must never happen. Startup refused; containers are being stopped.\n"
                f"  Canary output: {output[-500:]}\n"
                f"  Code: {CODE_EGRESS}\n  {_DOCS}",
            )
        outputs.append(output or "EGRESS_DENY_OK")
    return " | ".join(outputs)


def runtime_uid(project: str, service: str = "sb-app") -> str:
    """`id -u` inside a running container — the runtime half of G4."""
    cid = container_id(project, service)
    if not cid:
        raise RuntimeError(f"{service} container not found")
    return (_run(["docker", "exec", cid, "id", "-u"], timeout=60).stdout or "").strip()


def address_on(project: str, service: str, net_suffix: str) -> str | None:
    """A container's address on one specific network (suffix match)."""
    cid = container_id(project, service)
    if not cid:
        return None
    nets = (inspect(cid).get("NetworkSettings") or {}).get("Networks") or {}
    for name, cfg in nets.items():
        if name.endswith(net_suffix) or name == net_suffix:
            ip = cfg.get("IPAddress")
            if ip:
                return ip
    return None


def app_address(project: str, net_suffix: str = "ww-app-net") -> str | None:
    """The app container's address on the named network.

    Default: the internal bridge (management-plane path). The Phase 5 uplink
    passes ``ww-uplink-net`` explicitly — the proxy must target the app on
    the SAME subnet, because cross-bridge host forwarding is blocked by
    default-deny host firewalls (measured; see docs/sandbox/network.md).
    """
    return address_on(project, "sb-app", net_suffix)


def teardown(project: str) -> None:
    """Stop and remove a project (containers + networks + volumes)."""
    down(project, remove_volumes=True)
