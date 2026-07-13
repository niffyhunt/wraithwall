"""Shared runtime symbols that production modules import from ``main``.

Blueprint modules use ``from main import get_redis``, ``from main import db``
etc. as *late imports* (inside functions, not at module top). This module
provides the same symbols, bridged from the Flask application context, so the
extracted packages work without a monolithic ``main.py``.
"""
from __future__ import annotations

import logging
import os

from flask import current_app, g

logger = logging.getLogger("wraithwall")


def init_app(app):
    """Stash shared components on the app instance for late-import consumers."""
    from wraithwall.database import db

    app.extensions.setdefault("wraithwall", {})
    app.extensions["wraithwall"]["db"] = db


def get_redis():
    """Equivalent of ``main.get_redis()`` — returns a ``decode_responses=True``
    Redis client or ``None`` if unavailable."""
    try:
        return current_app.extensions.get("redis", None) or None
    except Exception:
        return None


def send_telegram_alert_bg(message, **kwargs):
    """Background Telegram alert stub that real modules import from main.
    In the OSS workspace, Telegram is optional — logs the alert instead."""
    logger.info("telegram_alert_bg: %s", message[:200] if message else "")


def send_discord_alert_bg(payload):
    """Background Discord alert stub."""
    logger.info("discord_alert_bg: %s", str(payload)[:200])


def write_immutable_log(**kwargs):
    """Stub — the OSS workspace omits the production immutable log pipeline."""
    logger.debug("immutable_log: %s", kwargs.get("event", "")[:120])


def get_real_ip():
    """Extract the client IP from Flask request headers."""
    from flask import request as _req  # noqa: F811

    if "X-Forwarded-For" in _req.headers:
        return _req.headers["X-Forwarded-For"].split(",")[0].strip()
    if "CF-Connecting-IP" in _req.headers:
        return _req.headers["CF-Connecting-IP"]
    return _req.remote_addr or "127.0.0.1"
