"""Host-application auth symbols for optional modules.

The published package deliberately ships **no user/auth stack** — no User or
APIKeyUsage tables, no session login, no API-key signature verification. That
surface belongs to the deployment, not to the library, so an OSS install cannot
accidentally expose a half-configured account system.

Modules that need it (:mod:`wraithwall.ai_runtime_security`,
:mod:`wraithwall.dossier_auth`) import the names from
here instead of from a monolith. A deployment supplies its own by binding them
once at startup::

    import wraithwall.host_auth as host_auth
    host_auth.bind(User=User, APIKeyUsage=APIKeyUsage, db=db,
                   is_logged_in=is_logged_in,
                   verify_api_signature=verify_api_signature,
                   has_permission=has_permission,
                   log_audit=log_audit)

Reading any symbol before ``bind()`` raises :data:`AUTH_RUNTIME_ERROR` — a
loud, actionable failure rather than a silent ImportError that would let an
unauthenticated path look configured.
"""
from __future__ import annotations

__all__ = ["bind", "bound", "AUTH_RUNTIME_ERROR"]

AUTH_RUNTIME_ERROR = (
    "this module requires the host app's auth stack (User, APIKeyUsage, db, "
    "is_logged_in, verify_api_signature, has_permission, log_audit, "
    "auth_context); call wraithwall.host_auth.bind(...) at startup to supply "
    "them"
)

_bound: dict[str, object] = {}


def bind(**symbols: object) -> None:
    """Register the host application's auth symbols."""
    _bound.update(symbols)


def bound() -> frozenset:
    """Names currently bound by the host application."""
    return frozenset(_bound)


def __getattr__(name: str):
    if name in _bound:
        return _bound[name]
    # PEP 562: dunders (``__path__`` during ``from ... import``, repr probes,
    # introspection) must raise AttributeError — raising RuntimeError here would
    # break hasattr()/importlib even for a fully bound auth stack.
    if name.startswith("__") and name.endswith("__"):
        raise AttributeError(name)
    raise RuntimeError(AUTH_RUNTIME_ERROR)