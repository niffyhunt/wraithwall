"""RavenScan — public import surface.

Usage::

    from ravenscan import scan, Raven
    profile = scan(".")
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from raven import Raven, __version__
from raven.core.config import RavenConfig

__all__ = ["Raven", "scan", "__version__"]


def scan(path: str | Path = ".", **config_kwargs: Any):
    """Run repository intelligence analysis and return a RepositoryProfile."""
    cfg = RavenConfig(path=str(path), **config_kwargs)
    return Raven(cfg).scan()