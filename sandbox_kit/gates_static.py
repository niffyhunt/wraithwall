"""Static (compose-parse) security gates — G1–G6 and G9-static (Phase 3).

These gates read `compose.sandbox.yml` as *data* and refuse to continue when the
declared posture is weaker than the Stage 2 hardening requirements. They are the
cheap half of the gate set: they run in milliseconds, need no daemon, and can
therefore run in CI on every commit. The dynamic half (the egress-deny canary,
capability inspection, uid checks) runs against a live sandbox in
`sandbox_kit.compose`.

Design rules, matching the rest of the kit:

* **Fail-closed.** A missing file, unparseable YAML, or a service whose posture
  cannot be established is a refusal, never a pass.
* **Absolute bans, not thresholds** where the requirement is absolute: no
  privileged containers, no docker socket, no host bind mounts, no host
  networking, no `latest` tags.
* **One failure type.** Findings are reported through `GateFailure` so the CLI
  has a single error path.

Gate → failure code mapping follows the Stage 3 catalog: banned container
options are reported as **E205**, secret-shaped values as **E204**.
"""
from __future__ import annotations

import re
from pathlib import Path

import yaml

from sandbox_kit.gates import GateFailure
from sandbox_kit.compose_constants import EGRESS_NETWORK, RESEARCH_PROFILE, UPLINK_NETWORK
from sandbox_kit.images import DOCKERFILES

# ── secret shapes (G9). Versioned here so CI diffing is meaningful. ─────────

SECRET_PATTERNS = (
    ("aws_access_key_id", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("stripe_or_openai_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("db_uri_with_password", re.compile(r"postgres(ql)?://[^:\s]+:[^@\s]+@")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("github_pat", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}")),
    ("telegram_bot_token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}")),
)

#: A secret-shaped match is tolerated when the same line marks it as a
#: placeholder. This is the only escape hatch and it is deliberately narrow:
#: bare words like "example" or "dummy" are NOT accepted, because a line such as
#: `# Example: AKIA…` would otherwise smuggle a real key past the scan. Use an
#: explicit placeholder token instead.
PLACEHOLDER_MARKER = re.compile(
    r"(PLACEHOLDER|CHANGEME|CHANGE_ME|NOT_A_SECRET|NOT_FOR_PRODUCTION|replace[-_ ]?me)",
    re.IGNORECASE,
)

#: Failure codes (Stage 3 catalog).
CODE_BANNED_OPTION = "E205"
CODE_SECRET_SHAPED = "E204"
#: Key names that must never appear in a sandbox service environment.
#: Deliberately does not match the sandbox's own required settings
#: (DATABASE_URL, REDIS_URL, CORS_ORIGINS, WRAITHWALL_SANDBOX, *_PATH).
_CREDENTIAL_KEY = re.compile(
    r"(_API_KEY|_KEY_ID|_ACCESS_KEY|_SECRET|_TOKEN|SECRET_KEY|WEBHOOK"
    r"|PASSWORD|_ENDPOINT_URL|_ACCOUNT_ID)$",
    re.IGNORECASE,
)

_LOOPBACK_PORT = re.compile(
    r"^127\.0\.0\.1:(\$\{[^}]+\}|\d{1,5}):(\$\{[^}]+\}|\d{1,5})$")
_TMPFS_SIZE = re.compile(r"(?:^|[:,\s])size=(\d+)([kKmMgG])(?=,|$)")
_SIZE_MB = {"k": 1 / 1024, "m": 1, "g": 1024}

_DOCS = "Docs: docs/sandbox/security-model.md"


# ── helpers ────────────────────────────────────────────────────────────────

def load_compose(path) -> dict:
    """Parse the sandbox compose file. Refuses (E205) on any problem."""
    p = Path(path)
    if not p.exists():
        raise _refuse(["✗ Sandbox compose file not found.", f"  Expected: {p}"])
    try:
        doc = yaml.safe_load(p.read_text())
    except Exception as exc:  # unparseable is a refusal, not a pass
        raise _refuse(["✗ Sandbox compose file could not be parsed.", f"  {exc}"])
    if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict):
        raise _refuse(["✗ Sandbox compose file has no `services:` mapping."])
    return doc


def _refuse(lines: list) -> GateFailure:
    body = "\n".join(lines)
    return GateFailure(
        CODE_BANNED_OPTION,
        f"{body}\n  Startup refused (fail-closed). Nothing was started.\n"
        f"  Code: {CODE_BANNED_OPTION}\n  {_DOCS}",
    )


def _secret_refuse(lines: list) -> GateFailure:
    body = "\n".join(lines)
    return GateFailure(
        CODE_SECRET_SHAPED,
        f"{body}\n  Startup refused (fail-closed). Nothing was started.\n"
        f"  Code: {CODE_SECRET_SHAPED}\n  {_DOCS}",
    )


def _iter_mounts(svc: dict):
    for spec in svc.get("volumes") or []:
        if isinstance(spec, str):
            yield spec, spec.split(":", 1)[0]
        elif isinstance(spec, dict):
            yield spec, str(spec.get("source") or "")
        else:
            yield spec, ""


# ── individual gates ───────────────────────────────────────────────────────

def gate_g1_no_privileged(services: dict) -> list:
    findings = []
    for name, svc in services.items():
        if svc.get("privileged") in (True, "true"):
            findings.append(f"  • {name}: privileged: true")
        cap_add = svc.get("cap_add") or []
        if cap_add:
            findings.append(
                f"  • {name}: cap_add {cap_add} "
                "(no capability may be added back in the MVP; a written "
                "justification is required before this gate can pass)"
            )
    return findings


def gate_g2_no_docker_socket(services: dict) -> list:
    findings = []
    for name, svc in services.items():
        for _spec, source in _iter_mounts(svc):
            if "docker.sock" in source or (source.endswith(".sock") and "/var/run" in source):
                findings.append(f"  • {name}: socket mount '{source}'")
    return findings


def gate_g3_no_host_binds(services: dict) -> list:
    findings = []
    for name, svc in services.items():
        for _spec, source in _iter_mounts(svc):
            if not source:
                continue
            if source.startswith(("/", "~", ".")) or source.startswith("$"):
                findings.append(
                    f"  • {name}: host path bind mount '{source}' "
                    "(named volumes and in-project tmpfs only)"
                )
    return findings


def gate_g4_non_root(services: dict) -> list:
    findings = []
    for name, svc in services.items():
        user = svc.get("user")
        if user is None:
            findings.append(f"  • {name}: no `user:` set (must be a non-root numeric uid)")
            continue
        uid = str(user).split(":")[0]
        if not uid.isdigit():
            findings.append(f"  • {name}: `user: {user}` is not a numeric uid")
        elif int(uid) == 0:
            findings.append(f"  • {name}: runs as uid 0")
        elif int(uid) < 1000:
            findings.append(f"  • {name}: uid {uid} is below the 1000 floor")
    return findings


def gate_g5_bounded_resources(services: dict) -> list:
    findings = []
    for name, svc in services.items():
        for key in ("mem_limit", "cpus", "pids_limit"):
            if not svc.get(key):
                findings.append(f"  • {name}: missing `{key}`")
        logging = svc.get("logging") or {}
        if logging.get("driver") != "json-file":
            findings.append(f"  • {name}: log driver must be json-file")
        else:
            opts = logging.get("options") or {}
            if not opts.get("max-size") or not opts.get("max-file"):
                findings.append(f"  • {name}: log rotation (max-size/max-file) missing")
        for entry in svc.get("tmpfs") or []:
            m = _TMPFS_SIZE.search(str(entry))
            if not m:
                findings.append(f"  • {name}: tmpfs '{entry}' has no explicit size cap")
                continue
            mb = float(m.group(1)) * _SIZE_MB.get(m.group(2).lower(), 1)
            if mb > 256:
                findings.append(f"  • {name}: tmpfs '{entry}' exceeds the 256 MB cap")
    return findings


def gate_g6_restricted_binding(services: dict) -> list:
    findings = []
    for name, svc in services.items():
        if svc.get("network_mode") == "host":
            findings.append(f"  • {name}: network_mode: host")
        for entry in svc.get("ports") or []:
            spec = entry if isinstance(entry, str) else (
                f"{entry.get('host_ip', '')}:{entry.get('published', '')}:{entry.get('target', '')}"
                if isinstance(entry, dict) else str(entry)
            )
            if not _LOOPBACK_PORT.match(spec):
                findings.append(
                    f"  • {name}: port '{spec}' must be 127.0.0.1:<host>:<container>"
                )
    return findings


def gate_g7_internal_networks(doc: dict) -> list:
    """G7 static half: the planes the sandbox depends on must be internal.

    Phase 5 exception, deliberately narrow: only the two first-party services
    (``sb-app`` and the optional profile-scoped proxy ``sb-uplink``) may
    attach the dedicated uplink network, which must disable IP masquerade.
    Everything else stays absolute: `internal: true`.

    Phase 11 exception, equally narrow: the four T2 research services may
    attach the research egress network (the only sanctioned route for
    developer-directed fetches, enforced by the in-proxy allowlist + policy
    layers) — and only under the `research` profile. Any other service on
    ``ww-egress-net`` is a refusal; a T2 service reaching any *other*
    non-internal network is a refusal too.

    The dynamic halves of both controls are the egress canaries that run on
    every boot (`verify_egress_denied` / `verify_research_plane_closed`).
    """
    findings = []
    networks = doc.get("networks") or {}
    allowed_on_uplink = {"sb-app", "sb-uplink"}
    allowed_on_egress = {
        "sb-egress", "sb-detonate", "sb-policy-selftest", "sb-research-canary",
    }
    for svc_name, svc in (doc.get("services") or {}).items():
        optional = bool(svc.get("profiles"))
        on_egress = EGRESS_NETWORK in (svc.get("networks") or [])
        for net in (svc.get("networks") or []):
            spec = networks.get(net) or {}
            if spec.get("internal") is True:
                continue
            if net == UPLINK_NETWORK and svc_name in allowed_on_uplink:
                if optional or svc_name == "sb-app":
                    opts = spec.get("driver_opts") or {}
                    if opts.get(
                            "com.docker.network.bridge.enable_ip_masquerade") != "false":
                        findings.append(
                            f"  • network '{net}' must disable ip masquerade")
                    continue
            if net == EGRESS_NETWORK and svc_name in allowed_on_egress:
                profiles = svc.get("profiles") or []
                if RESEARCH_PROFILE in profiles:
                    continue
                findings.append(
                    f"  • '{svc_name}' attaches '{net}' but is not scoped to "
                    f"the '{RESEARCH_PROFILE}' compose profile")
                continue
            if net == EGRESS_NETWORK and svc_name not in allowed_on_egress:
                findings.append(
                    f"  • service '{svc_name}' may not attach the research "
                    f"egress network '{net}' (allowed: {sorted(allowed_on_egress)})")
                continue
            findings.append(
                f"  • network '{net}' attached to '{svc_name}' must declare "
                "`internal: true` (only sb-app / optional sb-uplink may use "
                "the uplink; only the four research services may use the "
                "egress plane)")
        # T2 services must not reach ANY other non-internal network.
        if on_egress:
            for net in (svc.get("networks") or []):
                spec = networks.get(net) or {}
                if net != EGRESS_NETWORK and spec.get("internal") is not True:
                    findings.append(
                        f"  • T2 service '{svc_name}' also attaches non-internal "
                        f"network '{net}' — the research plane must be the only "
                        "egress-shaped interface")
    return findings


def gate_t2_research_topology(doc: dict) -> list:
    """Phase 11: pin the research plane's exact isolation shape.

    Asserted properties (all refuse as E205 when violated):
    * every research service is profile-scoped (`research`), so the T2 plane
      can never start with a default T1 `up`;
    * the detonation container has a DNS blackhole (`dns: 127.0.0.1`) — it
      must not resolve names around the enforcing proxy;
    * the detonation container's only network is the egress plane;
    * the egress proxy is the only service whose image ships the enforcement
      addon; the detonation image is not the app image (no shared namespace
      with the T1 application plane);
    * nothing on the egress plane publishes a port (G6 covers the general
      case; this restates it for the T2 services explicitly).
    """
    findings = []
    services = doc.get("services") or {}
    research_svcs = {n: s for n, s in services.items()
                     if RESEARCH_PROFILE in (s.get("profiles") or [])}
    for name, svc in research_svcs.items():
        if name not in {"sb-egress", "sb-detonate", "sb-policy-selftest",
                        "sb-research-canary"}:
            findings.append(f"  • {name}: unknown research-profile service")
        nets = svc.get("networks") or []
        if EGRESS_NETWORK not in nets:
            findings.append(
                f"  • {name}: research service must attach '{EGRESS_NETWORK}'")
        if svc.get("ports"):
            findings.append(f"  • {name}: research services publish nothing")
    det = services.get("sb-detonate") or {}
    if research_svcs:
        if not det:
            findings.append("  • sb-detonate missing from the research profile")
        else:
            if (det.get("dns") or []) != ["127.0.0.1"]:
                findings.append(
                    "  • sb-detonate: `dns: [127.0.0.1]` blackhole required "
                    "(the proxy resolves; the browser must not)")
            if (det.get("networks") or []) != [EGRESS_NETWORK]:
                findings.append(
                    f"  • sb-detonate: its ONLY network must be '{EGRESS_NETWORK}'")
        eg = services.get("sb-egress") or {}
        if not eg:
            findings.append("  • sb-egress missing from the research profile")
        elif str(eg.get("image")) != "wraithwall-sandbox-egress:local":
            findings.append(
                "  • sb-egress must run the local enforcing image "
                "(wraithwall-sandbox-egress:local)")
    return findings


def gate_h_restart_and_ro(services: dict) -> list:
    """Roadmap requirement: `restart: no` and a read-only rootfs everywhere."""
    findings = []
    for name, svc in services.items():
        if str(svc.get("restart", "no")) != "no":
            findings.append(f"  • {name}: restart must be 'no' (found {svc.get('restart')!r})")
        if svc.get("read_only") is not True:
            findings.append(f"  • {name}: read_only root filesystem required")
    return findings


def gate_h10_images_pinned(doc: dict) -> list:
    """H10: digest-pinned, or a locally built tag from our own Dockerfiles."""
    findings = []
    local_tags = set(DOCKERFILES)
    for name, svc in (doc.get("services") or {}).items():
        image = str(svc.get("image") or "")
        if not image:
            findings.append(f"  • {name}: no image")
            continue
        if "@sha256:" in image:
            continue
        if image in local_tags:
            continue
        findings.append(
            f"  • {name}: image '{image}' is not digest-pinned "
            "(add @sha256:… or build it from a sandbox Dockerfile)"
        )
    return findings


def gate_g9_no_secrets(doc: dict, raw_text: str) -> list:
    """G9 static: no env_file, no secret-shaped values, no credential keys.

    Credential-shaped variables must be *absent*, not set to an empty string.
    Empty looks configured to libraries (an empty R2_ENDPOINT_URL makes boto3
    raise "Invalid endpoint" during import), and it makes the container
    environment harder to audit than simply not listing the key.
    """
    findings = []
    for name, svc in (doc.get("services") or {}).items():
        env_file = svc.get("env_file")
        if env_file:
            findings.append(f"  • {name}: env_file is banned ({env_file!r})")
        for key in (svc.get("environment") or {}):
            if key == "SECRET_KEY":
                continue  # required; the text scan below still checks its value
            if _CREDENTIAL_KEY.search(str(key)):
                findings.append(
                    f"  • {name}: credential-shaped env var {key!r} is set — "
                    "credentials must be absent, not empty"
                )
    for lineno, line in enumerate(raw_text.splitlines(), start=1):
        if PLACEHOLDER_MARKER.search(line):
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(f"  • line {lineno}: {label} appears in the compose file")
    return findings


# ── runner ─────────────────────────────────────────────────────────────────

def inspect_compose(compose_path) -> dict:
    """Run every static gate. Returns a summary; raises GateFailure on any finding."""
    doc = load_compose(compose_path)
    services = doc["services"]
    raw_text = Path(compose_path).read_text()

    banned = {
        "G1 privileged/cap_add": gate_g1_no_privileged(services),
        "G2 docker socket": gate_g2_no_docker_socket(services),
        "G3 host bind mounts": gate_g3_no_host_binds(services),
        "G4 non-root": gate_g4_non_root(services),
        "G5 bounded resources": gate_g5_bounded_resources(services),
        "G6 restricted binding": gate_g6_restricted_binding(services),
        "G7 internal networks": gate_g7_internal_networks(doc),
        "G7-T2 research topology": gate_t2_research_topology(doc),
        "restart/read-only": gate_h_restart_and_ro(services),
        "H10 image pinning": gate_h10_images_pinned(doc),
    }

    offenders = {gate: f for gate, f in banned.items() if f}
    if offenders:
        lines = ["✗ Sandbox compose failed the static security gates:"]
        for gate, findings in offenders.items():
            lines.append(f"  [{gate}]")
            lines.extend(findings)
        lines.append(
            "  If this came from a local override file, remove it "
            "(docker-compose.sandbox.override.yml)."
        )
        raise _refuse(lines)

    secret_findings = gate_g9_no_secrets(doc, raw_text)
    if secret_findings:
        raise _secret_refuse(
            ["✗ Generated sandbox configuration failed the secret scan (Gate G9)."]
            + secret_findings
            + ["  This indicates a poisoned template — nothing was started."]
        )

    return {
        "services": sorted(services),
        "gate_count": len(banned) + 1,
        "image_count": len({str(s.get("image")) for s in services.values()}),
    }


def verify_env_allowlist(env_keys) -> list:
    """G9 dynamic: container env key names must not leak host credentials.

    `env_keys` is the set of key names reported by the container. A
    credential-shaped name is acceptable only when it is in the explicit
    allowlist below (required app settings or the sandbox-internal ship key);
    anything else means the host environment (or a local override) leaked into
    the sandbox.
    """
    findings = []
    # Image-level ENV keys are legitimate; credential-shaped names are not,
    # unless they are part of the explicit empty allowlist in the compose file.
    for key in sorted(env_keys):
        if NOT_A_CREDENTIAL.search(key):
            continue
        if CREDENTIAL_SHAPED.search(key) and key not in ALLOWED_CREDENTIAL_NAMES:
            findings.append(f"  • unexpected credential-shaped env var: {key}")
    return findings


#: Names that are legitimately set by the base image or the sandbox itself.
NOT_A_CREDENTIAL = re.compile(r"^(PATH|LANG|HOME|HOSTNAME|PYTHON[A-Z_]*|PIP_[A-Z_]*|WRAITHWALL_SANDBOX|GPG_KEY|DEBIAN_FRONTEND)$")

#: Narrow credential-shaped detector. Deliberately not `.*TOKEN.*`, because the
#: base image sets PYTHON_SHA256 and similar; this matches the exact names the
#: provider integrations use.
CREDENTIAL_SHAPED = re.compile(
    r"^(.*_(API_)?KEY|.*_TOKEN|.*_SECRET|.*WEBHOOK.*|.*PASSWORD|SECRET_KEY)$"
)


#: Credential-shaped names the compose file deliberately pins to empty strings.
ALLOWED_CREDENTIAL_NAMES = {
    "VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "IPQS_API_KEY", "ABUSEIPDB_API_KEY",
    "WHOISXML_API_KEY", "WHOIS_API_KEY", "URLHAUS_API_KEY", "IPINFO_TOKEN",
    "SHODAN_API_KEY", "CLOUDFLARE_API_TOKEN", "BROWSERLESS_API_KEY", "GITHUB_TOKEN",
    "GITLAB_TOKEN", "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GROQ_API_KEY",
    "DEEPSEEK_API_KEY", "HF_TOKEN", "RESEND_API_KEY", "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID", "TELEGRAM_WEBHOOK_SECRET", "DISCORD_WEBHOOK_URL",
    "SLACK_WEBHOOK_URL", "PAYSTACK_SECRET_KEY", "PAYSTACK_PUBLIC_KEY",
    "BACHS_API_KEY", "BACHS_WEBHOOK_SECRET", "R2_ACCESS_KEY_ID",
    "R2_SECRET_ACCESS_KEY", "R2_BUCKET_NAME", "R2_ENDPOINT_URL",
    "BREACH_MONITOR_API_KEY", "BREACH_MONITOR_INTERNAL_URL",
    "SECRET_KEY", "GOOGLE_CLIENT_ID", "RECAPTCHA_SECRET_KEY",
    # Phase 4: the sandbox-internal HMAC key for the ship-protocol exercise.
    # Generated per boot by the launcher (or the clearly non-secret default),
    # shared only between sb-app and sb-seed of the same project, and guarding
    # nothing beyond the sandbox's internal networks. Not a credential.
    "COWRIE_SHIP_KEY", "SANDBOX_SHIP_KEY",
}
