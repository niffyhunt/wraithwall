"""JSON renderer — the canonical output format.

All reports are serialized via `.model_dump_json()` from their Pydantic model.
Markdown is rendered FROM this JSON, never independently.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

from raven.core.config import RavenConfig
from raven.core.models import (
    RepositoryProfile,
    ArchitectureGraph,
    SecurityReport,
    DailyReport,
    RiskScore,
)
from raven.utils.logging import get_logger

logger = get_logger(__name__)


def render_json(data: Any, indent: int = 2) -> str:
    """Render any Pydantic model or dict as formatted JSON."""
    if hasattr(data, "model_dump_json"):
        return data.model_dump_json(indent=indent)  # type: ignore[no-any-return]
    return json.dumps(data, indent=indent, default=str)


def write_artifact(
    data: Any,
    name: str,
    config: RavenConfig,
    format: Optional[str] = None,
) -> Path:
    """Write an analysis artifact to disk.

    If format is 'json', writes the canonical JSON.
    If format is 'markdown', renders markdown FROM the model.
    """
    fmt = format or config.format
    output_dir = config.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    if fmt == "markdown":
        from raven.reporting.renderers.markdown import render_markdown
        content = render_markdown(data)
        ext = ".md"
    else:
        content = render_json(data)
        ext = ".json"

    path = output_dir / f"{name}{ext}"
    try:
        path.write_text(content)
    except OSError as exc:
        logger.error("Failed to write artifact %s: %s", path, exc)
        raise
    return path
