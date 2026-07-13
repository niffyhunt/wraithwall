"""Deception Markup Language (DML) — spec types and enums.

A DML document is a versioned set of *traps*. Each trap pairs one trigger
(what an attacker must do to set it off) with one response (how the trap
reacts) plus metadata, alerting config and a tamper-detection signature.

This module defines the canonical enums (trigger types, response types,
severity levels, MITRE ATT&CK tactics) and the dataclasses that describe a
DML document. The dataclasses are intentionally permissive: validation of
required fields and known enum values is handled separately by
:class:`dml.validator.DMLValidator`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# Current DML spec version. Documents must declare this version to validate.
DML_VERSION: str = "0.2.0"

# The nine trigger types — the kind of attacker activity that fires a trap.
TRIGGER_TYPES: set[str] = {
    "http_request",
    "dns_resolution",
    "api_key_use",
    "file_access",
    "login_attempt",
    "data_access",
    "timing_probe",
    "canary_email",
    "jwt_use",
}

# The eight response types — how a trap reacts once triggered.
RESPONSE_TYPES: set[str] = {
    "fake_data",
    "redirect_sandbox",
    "delay_response",
    "mirror_engage",
    "block_ip",
    "log_only",
    "alert_only",
    "honeypot_auth",
}

# Allowed trap severity levels.
SEVERITY_LEVELS: set[str] = {"critical", "high", "medium", "low", "info"}

# Allowed MITRE ATT&CK tactics for trap classification.
MITRE_TACTICS: set[str] = {
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "command_and_control",
    "impact",
    "reconnaissance",
}


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DMLAlert:
    """Alerting configuration for a trap.

    Describes which channels to notify when a trap fires and what context to
    include. Channel delivery itself is out of scope for this library — DML
    only carries the intent.
    """

    channels: list = field(default_factory=lambda: ["discord", "telegram"])
    include_ip: bool = True
    include_ua: bool = True
    include_headers: bool = False
    include_body_hash: bool = True
    throttle_seconds: int = 0


@dataclass
class DMLResponse:
    """How a trap responds once its trigger matches.

    ``type`` must be one of :data:`RESPONSE_TYPES`. The remaining fields are
    optional knobs whose relevance depends on the chosen response type (e.g.
    ``delay_ms`` for ``delay_response``, ``redirect_url`` for
    ``redirect_sandbox``, ``fake_data_template`` for ``fake_data``).
    """

    type: str = "log_only"
    delay_ms: Optional[int] = None
    fake_data_template: Optional[str] = None
    llm_prompt_override: Optional[str] = None
    llm_model: Optional[str] = None
    sandbox_reason: Optional[str] = None
    redirect_url: Optional[str] = None
    http_status: int = 200
    content_type: str = "application/json"


@dataclass
class DMLTrigger:
    """What attacker activity fires a trap.

    ``type`` must be one of :data:`TRIGGER_TYPES`. The remaining fields are
    optional matchers whose relevance depends on the chosen trigger type
    (e.g. ``path``/``method`` for ``http_request``, ``hostname`` for
    ``dns_resolution``, ``email`` for ``canary_email``,
    ``timing_target_ms`` for ``timing_probe``).
    """

    type: str = "http_request"
    path: Optional[str] = None
    method: Optional[str] = None
    hostname: Optional[str] = None
    api_key_prefix: Optional[str] = None
    email: Optional[str] = None
    record_id: Optional[int] = None
    timing_target_ms: Optional[int] = None
    match_regex: Optional[str] = None


@dataclass
class DMLTrap:
    """A single deception trap: trigger + response + metadata.

    The ``signature`` field is populated by :class:`dml.signing.DMLSigner`
    and carries a per-trap HMAC so individual traps can be checked for
    tampering independently of the whole-document signature.
    """

    id: str
    name: str
    version: str = DML_VERSION
    namespace: str = "default"
    enabled: bool = True
    severity: str = "high"
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    description: str = ""
    tags: list = field(default_factory=list)
    trigger: DMLTrigger = field(default_factory=DMLTrigger)
    response: DMLResponse = field(default_factory=DMLResponse)
    alert: DMLAlert = field(default_factory=DMLAlert)
    created_at: str = field(default_factory=_utc_now_iso)
    author: str = ""
    plant_in: list = field(default_factory=list)
    signature: Optional[str] = None

    @property
    def fully_qualified_id(self) -> str:
        """Return ``namespace:id``, the document-unique identifier of a trap."""
        return f"{self.namespace}:{self.id}"


@dataclass
class DMLDocument:
    """A versioned collection of deception traps.

    ``document_signature`` is populated by :class:`dml.signing.DMLSigner` and
    is an HMAC over the document's identity fields plus its (unsigned) traps,
    so that adding, removing or altering any trap invalidates the document.
    """

    dml_version: str = DML_VERSION
    platform: str = ""
    namespace: str = ""
    description: str = ""
    author: str = ""
    created_at: str = field(default_factory=_utc_now_iso)
    traps: list = field(default_factory=list)
    document_signature: Optional[str] = None
