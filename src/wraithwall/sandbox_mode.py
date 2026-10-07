"""Import-time sandbox-mode flag (``WRAITHWALL_SANDBOX``) — fail closed.

The local sandbox (``sandbox.sh`` / ``compose.sandbox.yml``) starts this
package with ``WRAITHWALL_SANDBOX=1`` so the process runs with **zero ambient
authority**: no external alert transports, a self-contained rate limiter that
never depends on a host-provided Redis, and a startup line that states exactly
which gates are active.

Parser contract (identical to the private monolith, so an operator reading
either log reads the same thing):

* ``True`` only for the exact string ``'1'``.
* Anything else — unset, ``''``, ``'0'``, ``'true'``, ``'yes'``, ``' 1'``,
  ``'1 '``, ``'01'``, ``'1.0'``, garbage — is **false**. Absence,
  misconfiguration and corruption all yield default (non-sandbox) behavior.
* Explicit disable tokens (``0``/``false``/``no``/``off``) report
  ``disabled``; enable-looking or garbage values report ``malformed`` so a
  botched ``true``/``yes`` is visible in the startup log. That distinction is
  log-only — the effective behavior is identical.

The flag is read once at import time and cannot be flipped at runtime (the
environment of a process is static), which is what makes it a boundary rather
than a preference.
"""
from __future__ import annotations

import logging
import os
import subprocess

__all__ = [
    "SANDBOX_FLAG_ENV",
    "SANDBOX_STUB_MARKER",
    "SANDBOX_LEAK_MARKER",
    "RAW_FLAG",
    "SANDBOX_MODE",
    "FLAG_MALFORMED",
    "parse_sandbox_flag",
    "active",
    "announce",
    "startup_line",
    "stub_transport",
]

logger = logging.getLogger("wraithwall.sandbox")

#: Environment variable that arms sandbox mode.
SANDBOX_FLAG_ENV = "WRAITHWALL_SANDBOX"

#: Marker prefixed to every locally-recorded alert intent (zero network I/O).
SANDBOX_STUB_MARKER = "[SANDBOX-STUB]"

#: Marker prefixed to every blocked external-egress attempt.
SANDBOX_LEAK_MARKER = "[SANDBOX-LEAK]"

_DISABLE_TOKENS = {"0", "false", "no", "off"}


def parse_sandbox_flag(raw: str | None) -> bool:
    """Strict allowlist parser for the sandbox flag.

    Returns ``True`` only for the exact string ``'1'``; every other value
    returns ``False`` (fail closed to default mode).
    """
    return raw == "1"


#: Raw env value, captured once (``None`` when unset).
RAW_FLAG = os.environ.get(SANDBOX_FLAG_ENV)

#: Effective mode for this process.
SANDBOX_MODE = parse_sandbox_flag(RAW_FLAG)

#: Log-only classification of a botched enable attempt.
FLAG_MALFORMED = (
    RAW_FLAG is not None
    and RAW_FLAG != ""
    and RAW_FLAG != "1"
    and RAW_FLAG.strip().lower() not in _DISABLE_TOKENS
)


def _commit_sha() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001 — provenance is best-effort only
        return "unknown"


def startup_line() -> str:
    """The single startup line describing this process's sandbox posture.

    A security control, not debugging: exactly one line per process start.
    """
    version = os.getenv("APP_VERSION", "unknown")
    commit = _commit_sha()
    if SANDBOX_MODE:
        return (
            f"SANDBOX FLAG: enabled | flag={SANDBOX_FLAG_ENV}=1 | "
            f"version={version} | commit={commit} | "
            "gates: rate limiter MEMORY-BACKED, alert transports STUBBED "
            "(local record, zero network I/O)"
        )
    if FLAG_MALFORMED:
        return (
            f"SANDBOX FLAG: disabled (malformed value={RAW_FLAG!r}; "
            f"strict allowlist accepts only '1') | version={version} | "
            f"commit={commit} | default mode active"
        )
    return (
        f"SANDBOX FLAG: disabled | version={version} | "
        f"commit={commit} | default mode active"
    )


def announce() -> None:
    """Emit the startup line. Called once per :func:`wraithwall.create_app`."""
    logger.info(startup_line())


def active() -> bool:
    """Whether this process is running in sandbox mode."""
    return SANDBOX_MODE


def stub_transport(transport: str, summary: str = "") -> None:
    """Record alert intent locally instead of sending it anywhere.

    Zero network I/O. In default mode the real transports run and this is
    never called.
    """
    tail = f" — {summary}" if summary else ""
    logger.info("%s %s: alert recorded locally (no external send)%s",
                SANDBOX_STUB_MARKER, transport, tail)