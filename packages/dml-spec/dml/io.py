"""Load, dump and build DML documents.

This module provides:

* :func:`load` / :func:`loads` — parse a DML document from a file or string
  (YAML or JSON; YAML is a superset of JSON so both parse with the YAML
  loader, with a JSON fast path).
* :func:`dump` / :func:`dumps` — serialize a DML document to YAML or JSON.
* :func:`to_dict` — turn the spec dataclasses into a plain dict.
* :func:`build_document` — assemble a DML document from plain dicts (or
  :class:`~dml.spec.DMLTrap` instances). This is the pluggable replacement
  for the original database-coupled generator: it has no knowledge of any
  ORM, framework or external store — callers map their own records to trap
  dicts and pass them in.
"""

from __future__ import annotations

import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Union

import yaml

from .spec import DML_VERSION, DMLDocument, DMLTrap

PathLike = Union[str, Path]


def to_dict(obj: Any) -> Any:
    """Recursively convert DML dataclasses to plain dicts.

    Dataclass instances become dicts; everything else is returned unchanged.
    """
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    return obj


def loads(text: str) -> dict:
    """Parse a DML document from a YAML or JSON string.

    Args:
        text: The document source. JSON is valid YAML, so both work.

    Returns:
        The document as a plain dict.

    Raises:
        ValueError: If the parsed top level is not a mapping.
    """
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise ValueError("DML document must be a mapping at the top level")
    return data


def load(path: PathLike) -> dict:
    """Load a DML document from a file.

    The format is chosen by extension: ``.json`` is parsed as JSON, anything
    else (``.yaml``, ``.yml``, ...) as YAML.

    Args:
        path: Path to the document file.

    Returns:
        The document as a plain dict.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() == ".json":
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError("DML document must be a mapping at the top level")
        return data
    return loads(text)


def dumps(doc: Union[dict, DMLDocument], fmt: str = "yaml") -> str:
    """Serialize a DML document to a string.

    Args:
        doc: A document dict or :class:`~dml.spec.DMLDocument`.
        fmt: ``"yaml"`` (default) or ``"json"``.

    Returns:
        The serialized document.

    Raises:
        ValueError: If ``fmt`` is not ``"yaml"`` or ``"json"``.
    """
    data = to_dict(doc)
    if fmt == "json":
        return json.dumps(data, indent=2, ensure_ascii=False)
    if fmt == "yaml":
        return yaml.safe_dump(data, sort_keys=False, default_flow_style=False)
    raise ValueError(f"Unsupported format: {fmt!r} (use 'yaml' or 'json')")


def dump(doc: Union[dict, DMLDocument], path: PathLike) -> None:
    """Serialize a DML document and write it to a file.

    The format is chosen by extension (``.json`` → JSON, else YAML).

    Args:
        doc: A document dict or :class:`~dml.spec.DMLDocument`.
        path: Destination path.
    """
    p = Path(path)
    fmt = "json" if p.suffix.lower() == ".json" else "yaml"
    p.write_text(dumps(doc, fmt=fmt), encoding="utf-8")


def build_document(
    traps: Iterable[Union[dict, DMLTrap]],
    *,
    platform: str = "",
    namespace: str = "",
    description: str = "",
    author: str = "",
) -> dict:
    """Assemble a DML document dict from a collection of traps.

    This is the framework-agnostic replacement for the original
    database-backed generator. Callers are responsible for mapping their own
    records (DB rows, API responses, config, ...) to trap dicts — for
    example by populating a :class:`~dml.spec.DMLTrap` and passing it here.

    Args:
        traps: An iterable of trap dicts or :class:`~dml.spec.DMLTrap`
            instances.
        platform: Optional platform identifier for the document.
        namespace: Optional document-level namespace.
        description: Optional human description.
        author: Optional author string.

    Returns:
        An unsigned DML document as a plain dict, ready for validation,
        signing and serialization.
    """
    trap_dicts = [to_dict(t) for t in traps]
    return {
        "dml_version": DML_VERSION,
        "platform": platform,
        "namespace": namespace,
        "description": description,
        "author": author,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "traps": trap_dicts,
    }
