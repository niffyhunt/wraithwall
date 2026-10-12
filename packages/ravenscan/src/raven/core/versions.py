"""Version stamps for the two inputs that pin report determinism (R-02).

- ``RULESET_VERSION``: bump when any security analyzer rule changes meaning.
- ``TEMPLATE_VERSION``: bump when any reporting template/layout changes.

Both are recorded in every decision trace and in ``scan_records`` so a
version mismatch between runs can be detected and surfaced to the operator
(ruleset drift), never silently absorbed.
"""

from __future__ import annotations

RULESET_VERSION = "1.0"
TEMPLATE_VERSION = "1.0"
