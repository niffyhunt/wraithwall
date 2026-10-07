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
    app.extensions["wraithwall"]["app"] = app


def get_app():
    """The Flask app built by :func:`wraithwall.create_app`, if one exists.

    Needed by code that runs outside a request (background worker threads)
    and therefore has no application context to borrow.
    """
    try:
        app = current_app.extensions.get("wraithwall", {}).get("app")
        if app is not None:
            return app
    except Exception:
        pass
    from wraithwall import get_app as _package_app

    return _package_app()


def get_redis():
    """Equivalent of ``main.get_redis()`` — returns a ``decode_responses=True``
    Redis client or ``None`` if unavailable."""
    try:
        return current_app.extensions.get("redis", None) or None
    except Exception:
        return None


def send_telegram_alert_bg(message, **kwargs):
    """Background Telegram alert stub that production modules import from main.
    In the OSS package, Telegram is optional — the intent is recorded locally
    instead of being sent anywhere."""
    from wraithwall import sandbox_mode

    sandbox_mode.stub_transport("telegram", (message or "")[:100])


def send_discord_alert_bg(payload):
    """Background Discord alert stub — recorded locally, never sent."""
    from wraithwall import sandbox_mode

    sandbox_mode.stub_transport("discord", str(payload)[:100])


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
