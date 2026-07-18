"""Campaign equivalence primitives.

WraithMesh identity is the honeypot-mitre order-independent command multiset
signature. MITRE technique sets are enrichment metadata, not the primary key.
"""

from __future__ import annotations

from honeypot_mitre import dedup_key

__all__ = ["equivalence_key", "dedup_key"]


def equivalence_key(commands: list[str]) -> str:
    """Return the 16-char equivalence key for a command multiset."""
    return dedup_key(commands)