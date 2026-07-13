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
    DML_VERSION,
    MITRE_TACTICS,
    RESPONSE_TYPES,
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
        if doc.get("dml_version") != DML_VERSION:
            errors.append(
                f"dml_version must be '{DML_VERSION}', got '{doc.get('dml_version')}'"
            )
        if not doc.get("traps"):
            errors.append("Document must contain at least one trap")
        ids_seen: set[str] = set()
        for i, trap in enumerate(doc.get("traps", [])):
            trap_errors = self.validate_trap(trap)
            for e in trap_errors:
                errors.append(f"traps[{i}].{e}")
            ns = trap.get("namespace", "default")
            tid = trap.get("id", "")
            fqid = f"{ns}:{tid}"
            if fqid in ids_seen:
                errors.append(f"traps[{i}]: duplicate fully-qualified ID '{fqid}'")
            ids_seen.add(fqid)
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

        response = trap.get("response", {})
        resp_type = response.get("type")
        if resp_type and resp_type not in RESPONSE_TYPES:
            errors.append(f"response.type must be one of: {RESPONSE_TYPES}")
        if resp_type == "delay_response" and not response.get("delay_ms"):
            errors.append("response.delay_ms required for delay_response type")

        return errors

    def is_valid(self, doc: dict) -> bool:
        """Return ``True`` if the document passes all validation checks."""
        return len(self.validate_document(doc)) == 0
