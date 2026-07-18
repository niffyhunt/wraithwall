"""Deception Markup Language (DML).

A versioned, signable schema for declaring deception traps — honeypots,
canaries, and tripwires — as portable documents. A DML document is a set of
traps; each trap pairs a *trigger* (what an attacker does) with a *response*
(how the trap reacts), plus metadata and alerting intent. Documents are
signed with HMAC-SHA256 at both the per-trap and whole-document level so
tampering is detectable.

Public API:

    Spec types / enums:
        DML_VERSION, TRIGGER_TYPES, RESPONSE_TYPES, SEVERITY_LEVELS,
        MITRE_TACTICS, DMLDocument, DMLTrap, DMLTrigger, DMLResponse,
        DMLAlert

    Validation:
        DMLValidator, DMLValidationError

    Signing:
        DMLSigner

    I/O & building:
        load, loads, dump, dumps, to_dict, build_document

Part of the WraithWall project — https://wraithwall.online · by niffy_hunt.
"""

from __future__ import annotations

from .io import build_document, dump, dumps, load, loads, to_dict
from .mesh import export_mesh_manifest, export_mesh_manifest_json, node_id_from_key
from .signing import DMLSigner
from .spec import (
    DEFAULT_EGRESS_ALLOWLIST,
    DML_VERSION,
    MITRE_TACTICS,
    RESPONSE_TYPES,
    SENSOR_CLASSES,
    SUPPORTED_VERSIONS,
    SEVERITY_LEVELS,
    TRIGGER_TYPES,
    DMLAlert,
    DMLDocument,
    DMLMeshPolicy,
    DMLResponse,
    DMLSensor,
    DMLSensorThresholds,
    DMLTrap,
    DMLTrigger,
)
from .validator import DMLValidationError, DMLValidator

__version__ = "0.2.0"

__all__ = [
    "DML_VERSION",
    "SUPPORTED_VERSIONS",
    "TRIGGER_TYPES",
    "RESPONSE_TYPES",
    "SEVERITY_LEVELS",
    "MITRE_TACTICS",
    "SENSOR_CLASSES",
    "DEFAULT_EGRESS_ALLOWLIST",
    "DMLDocument",
    "DMLTrap",
    "DMLTrigger",
    "DMLResponse",
    "DMLAlert",
    "DMLSensor",
    "DMLSensorThresholds",
    "DMLMeshPolicy",
    "DMLValidator",
    "DMLValidationError",
    "DMLSigner",
    "export_mesh_manifest",
    "export_mesh_manifest_json",
    "node_id_from_key",
    "load",
    "loads",
    "dump",
    "dumps",
    "to_dict",
    "build_document",
    "__version__",
]
