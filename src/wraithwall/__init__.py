"""WraithWall — deception and threat-intelligence platform.

Public surface::

    from wraithwall import create_app, Client
    from wraithwall.link_checker import analyze
    from wraithwall.gateway import Gateway
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from flask import Flask
from flask_cors import CORS
from flask_limiter import Limiter

from wraithwall import shared
from wraithwall.client import Client, WraithWallClient
from wraithwall.database import db

__all__ = ["create_app", "Client", "WraithWallClient", "__version__"]
__version__ = "0.1.0"

logger = logging.getLogger("wraithwall")

_PKG_DIR = Path(__file__).resolve().parent


def create_app(config_overrides: dict | None = None) -> Flask:
    """Build and return the WraithWall Flask application.

    Args:
        config_overrides: Optional dict of Flask config keys/values applied
            after defaults.

    Returns:
        A configured Flask application instance with all public blueprints
        registered.
    """
    template_dir = os.getenv("WRAITHWALL_TEMPLATE_DIR", str(_PKG_DIR / "templates"))
    static_dir = os.getenv("WRAITHWALL_STATIC_DIR", str(_PKG_DIR / "static"))
    app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)
    app.config.setdefault("SECRET_KEY", os.getenv("SECRET_KEY", "change-me"))
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    if config_overrides:
        app.config.update(config_overrides)
    if app.config.get("TESTING"):
        app.config.setdefault("SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    else:
        app.config.setdefault(
            "SQLALCHEMY_DATABASE_URI",
            os.getenv("DATABASE_URL", "sqlite:///wraithwall.db"),
        )

    db.init_app(app)
    shared.init_app(app)

    _setup_redis(app)
    cors_origins = os.getenv("CORS_ORIGINS", "")
    if cors_origins:
        CORS(app, origins=[o.strip() for o in cors_origins.split(",") if o.strip()])

    limiter = Limiter(
        app=app,
        key_func=getattr(shared, "get_real_ip", lambda: "127.0.0.1"),
        default_limits=["1000 per day", "200 per hour"],
    )

    with app.app_context():
        _register_bp("link_checker", app, limiter)
        _register_bp("public_api", app, limiter)
        _register_bp("gateway", app, limiter)
        _register_bp("incident_response", app, limiter)

        from wraithwall.architecture_viz import register_architecture_viz

        register_architecture_viz(app, limiter)
        from wraithwall.live_events import register_live_events

        register_live_events(app, limiter)

        _register_bp("campaign_correlator", app, limiter)
        _register_bp("asn_intelligence", app, limiter)
        _register_bp("bgp_monitor", app, limiter)
        _register_bp("cowrie_intelligence", app, limiter)

        _register_bp("canary_service", app, limiter)
        _register_bp("fingerprint_corpus", app, limiter)
        _register_bp("sandbox", app, limiter)
        from wraithwall.dml_engine import register_dml_routes

        register_dml_routes(app)
        from wraithwall.deception_event_bus import register_deception_event_bus

        register_deception_event_bus(app, limiter)

    return app


def _register_bp(module_name: str, app: Flask, limiter: Limiter) -> None:
    try:
        mod = __import__(f"wraithwall.{module_name}", fromlist=["*"])
    except Exception:
        logger.warning("Skipping blueprint %s (import failed)", module_name, exc_info=False)
        return
    bp = getattr(mod, f"{module_name}_bp", None) or getattr(mod, "bp", None)
    if bp is None:
        for attr in dir(mod):
            if attr.endswith("_bp"):
                bp = getattr(mod, attr)
                break
    if bp is None:
        logger.warning("Skipping %s: no blueprint found", module_name)
        return
    app.register_blueprint(bp)
    logger.info("Registered blueprint: %s", module_name)


def _setup_redis(app: Flask) -> None:
    url = os.getenv("REDIS_URL", "")
    if not url:
        return
    try:
        import redis as _redis

        client = _redis.from_url(url, decode_responses=True, socket_connect_timeout=2, socket_timeout=2)
        app.extensions["redis"] = client
    except Exception:  # noqa: BLE001
        logger.warning("Redis unavailable; dependent blueprints will degrade.")
