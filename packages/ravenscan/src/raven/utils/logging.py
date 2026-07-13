"""Centralized logging for Raven.

Provides structured logging with configurable levels and consistent formatting.
"""

from __future__ import annotations

import logging
import sys
from typing import Optional


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """Return a configured logger for the given module name.

    Args:
        name: Module name (typically __name__).
        level: Optional log level override. Defaults to WARNING if not set.

    Returns:
        A configured Logger instance.
    """
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter(
            fmt="%(asctime)s [%(levelname)-7s] %(name)s: %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S",
        ))
        logger.addHandler(handler)
    if level is not None:
        logger.setLevel(level)
    elif not logger.hasHandlers() or logger.level == logging.NOTSET:
        logger.setLevel(logging.WARNING)
    return logger


def configure_root(verbose: bool = False, quiet: bool = False) -> None:
    """Configure the root logger for CLI use.

    Args:
        verbose: If True, set DEBUG level.
        quiet: If True, suppress all but ERROR level.
    """
    if quiet:
        logging.getLogger("raven").setLevel(logging.ERROR)
    elif verbose:
        logging.getLogger("raven").setLevel(logging.DEBUG)
    else:
        logging.getLogger("raven").setLevel(logging.WARNING)
