"""WraithMesh — distributed deception sensor mesh (Phase 1).

Nodes emit signed equivalence-class observations. Regional aggregators corroborate
without ever receiving raw commands, IPs, or customer identifiers.
"""

from __future__ import annotations

from .aggregator import CorroborationRecord, InMemoryAggregatorStore, ingest_batch, ingest_observation
from .equivalence import equivalence_key
from .manifest import MeshManifest, load_manifest, write_manifest
from .models import Observation, verify_observation
from .reputation import NodeReputation, ReputationStore
from .sensor import CanaryInboxSensor, CowrieTailSensor, create_sensor
from .signing import node_id_from_key

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "equivalence_key",
    "Observation",
    "verify_observation",
    "MeshManifest",
    "load_manifest",
    "write_manifest",
    "CowrieTailSensor",
    "CanaryInboxSensor",
    "create_sensor",
    "NodeReputation",
    "ReputationStore",
    "CorroborationRecord",
    "InMemoryAggregatorStore",
    "ingest_observation",
    "ingest_batch",
    "node_id_from_key",
]