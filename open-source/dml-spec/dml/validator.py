"""Validation of DML documents against the spec.

The validator works on plain ``dict`` documents (as produced by
:func:`dml.io.load` or :func:`dml.io.to_dict`) and returns a list of
human-readable error strings — empty when the document is valid. This keeps
validation decoupled from the dataclasses so it can run on freshly parsed
YAML/JSON without an intermediate conversion step.
"""

from __future__ import annotations

import re

from .spec import (
    DEFAULT_EGRESS_ALLOWLIST,
    DML_VERSION,
    MITRE_TACTICS,
    RESPONSE_TYPES,
    SENSOR_CLASSES,
    SUPPORTED_VERSIONS,
    SEVERITY_LEVELS,
    TRIGGER_TYPES,
)

# Trap IDs: lowercase alphanumeric with hyphens, 3-50 chars, no leading/
# trailing hyphen.
_TRAP_ID_RE = re.compile(r"^[a-z0-9][a-z0-9\-]{1,48}[a-z0-9]$")


class DMLValidationError(Exception):
    """Raised to signal a single field-level validation failure.

    Carries the offending ``field`` and a descriptive ``message``. The
    :class:`DMLValidator` methods accumulate plain error strings rather than
    raising; this exception is provided for callers who prefer to raise.
    """

    def __init__(self, field: str, message: str) -> None:
        self.field = field
        self.message = message
        super().__init__(f"DML validation error at '{field}': {message}")


class DMLValidator:
    """Validates DML documents and individual traps against the spec."""

    def validate_document(self, doc: dict) -> list[str]:
        """Validate a whole DML document.

        Checks the declared ``dml_version``, that at least one trap is
        present, that every trap validates, and that fully-qualified trap
        IDs (``namespace:id``) are unique within the document.

        Args:
            doc: The DML document as a plain dict.

        Returns:
            A list of error strings; empty if the document is valid.
        """
        errors: list[str] = []
        version = doc.get("dml_version")
        if version not in SUPPORTED_VERSIONS:
            errors.append(
                f"dml_version must be one of {sorted(SUPPORTED_VERSIONS)}, got '{version}'"
            )
        traps = doc.get("traps") or []
        sensors = doc.get("sensors") or []
        if not traps and not sensors:
            errors.append("Document must contain at least one trap or sensor")
        if sensors and version == "0.2.0":
            errors.append("sensors require dml_version 0.3.0 or later")
        if doc.get("mesh_policy") and version == "0.2.0":
            errors.append("mesh_policy requires dml_version 0.3.0 or later")
        ids_seen: set[str] = set()
        for i, trap in enumerate(traps):
            trap_errors = self.validate_trap(trap)
            for e in trap_errors:
                errors.append(f"traps[{i}].{e}")
            ns = trap.get("namespace", "default")
            tid = trap.get("id", "")
            fqid = f"{ns}:{tid}"
            if fqid in ids_seen:
                errors.append(f"traps[{i}]: duplicate fully-qualified ID '{fqid}'")
            ids_seen.add(fqid)
        sensor_ids: set[str] = set()
        for i, sensor in enumerate(sensors):
            sensor_errors = self.validate_sensor(sensor)
            for e in sensor_errors:
                errors.append(f"sensors[{i}].{e}")
            sid = sensor.get("id", "")
            if sid in sensor_ids:
                errors.append(f"sensors[{i}]: duplicate sensor id '{sid}'")
            sensor_ids.add(sid)
        if doc.get("mesh_policy"):
            errors.extend(self.validate_mesh_policy(doc["mesh_policy"]))
        return errors

    def validate_mesh_policy(self, policy: dict) -> list[str]:
        errors: list[str] = []
        min_corr = policy.get("tie_min_corroboration", 2)
        if not isinstance(min_corr, int) or min_corr < 1:
            errors.append("mesh_policy.tie_min_corroboration must be a positive integer")
        for field in ("canary_weight", "cowrie_weight"):
            val = policy.get(field)
            if val is not None and (not isinstance(val, (int, float)) or val <= 0):
                errors.append(f"mesh_policy.{field} must be a positive number")
        return errors

    def validate_sensor(self, sensor: dict) -> list[str]:
        errors: list[str] = []
        if not sensor.get("id"):
            errors.append("id is required")
        elif not _TRAP_ID_RE.match(sensor["id"]):
            errors.append("id must be lowercase alphanumeric with hyphens (3-50 chars)")
        if not sensor.get("name"):
            errors.append("name is required")
        sensor_class = sensor.get("sensor_class")
        if not sensor_class:
            errors.append("sensor_class is required")
        elif sensor_class not in SENSOR_CLASSES:
            errors.append(f"sensor_class must be one of: {sorted(SENSOR_CLASSES)}")
        if sensor_class == "cowrie" and not sensor.get("cowrie_log_path"):
            errors.append("cowrie_log_path required for cowrie sensor_class")
        if sensor_class == "canary" and not sensor.get("beacon_inbox_path"):
            errors.append("beacon_inbox_path required for canary sensor_class")
        egress = sensor.get("egress_allowlist")
        if egress is not None:
            forbidden = {"src_ip", "commands", "session_id", "password", "hostname"}
            if forbidden & set(egress):
                errors.append(f"egress_allowlist must not include: {sorted(forbidden & set(egress))}")
        thresholds = sensor.get("thresholds") or {}
        cooldown = thresholds.get("uplink_cooldown_seconds")
        if cooldown is not None and (not isinstance(cooldown, int) or cooldown < 0):
            errors.append("thresholds.uplink_cooldown_seconds must be a non-negative integer")
        if egress is not None and not egress:
            errors.append("egress_allowlist must not be empty when provided")
        return errors

    def validate_trap(self, trap: dict) -> list[str]:
        """Validate a single trap dict.

        Checks the required ``id``/``name``, the ID format, enum membership
        for ``severity`` and ``mitre_tactic``, that the trigger and response
        types are known, and trigger/response-type-specific required fields.

        Args:
            trap: A single trap as a plain dict.

        Returns:
            A list of error strings; empty if the trap is valid.
        """
        errors: list[str] = []
        if not trap.get("id"):
            errors.append("id is required")
        elif not _TRAP_ID_RE.match(trap["id"]):
            errors.append("id must be lowercase alphanumeric with hyphens (3-50 chars)")
        if not trap.get("name"):
            errors.append("name is required")
        if trap.get("severity") and trap["severity"] not in SEVERITY_LEVELS:
            errors.append(f"severity must be one of: {SEVERITY_LEVELS}")
        if trap.get("mitre_tactic") and trap["mitre_tactic"] not in MITRE_TACTICS:
            errors.append(f"mitre_tactic must be one of: {MITRE_TACTICS}")

        trigger = trap.get("trigger", {})
        trigger_type = trigger.get("type")
        if not trigger_type:
            errors.append("trigger.type is required")
        elif trigger_type not in TRIGGER_TYPES:
            errors.append(f"trigger.type must be one of: {TRIGGER_TYPES}")
        else:
            if trigger_type == "http_request" and not trigger.get("path"):
                errors.append("trigger.path required for http_request trigger")
            if trigger_type == "dns_resolution" and not trigger.get("hostname"):
                errors.append("trigger.hostname required for dns_resolution trigger")
            if trigger_type == "timing_probe" and not trigger.get("timing_target_ms"):
                errors.append(
                    "trigger.timing_target_ms required for timing_probe trigger"
                )
            if trigger_type == "canary_email" and not trigger.get("email"):
                errors.append("trigger.email required for canary_email trigger")
            if trigger_type == "cowrie_session" and not trigger.get("equivalence_key"):
                errors.append("trigger.equivalence_key required for cowrie_session trigger")
            if trigger_type == "canary_beacon" and not trigger.get("package_name"):
                errors.append("trigger.package_name required for canary_beacon trigger")
            if trigger_type == "equivalence_match" and not trigger.get("equivalence_key"):
                errors.append("trigger.equivalence_key required for equivalence_match trigger")

        response = trap.get("response", {})
        resp_type = response.get("type")
        if resp_type and resp_type not in RESPONSE_TYPES:
            errors.append(f"response.type must be one of: {RESPONSE_TYPES}")
        if resp_type == "delay_response" and not response.get("delay_ms"):
            errors.append("response.delay_ms required for delay_response type")
        if resp_type == "mesh_uplink" and not response.get("aggregator_url"):
            errors.append("response.aggregator_url required for mesh_uplink type")

        return errors

    def is_valid(self, doc: dict) -> bool:
        """Return ``True`` if the document passes all validation checks."""
        return len(self.validate_document(doc)) == 0
