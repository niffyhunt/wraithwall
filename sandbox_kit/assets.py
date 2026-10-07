"""Where the sandbox's deployment assets live, in both supported layouts.

``sandbox_kit`` runs from two places:

* a **repo checkout** — ``<repo>/sandbox_kit/…`` with ``compose.sandbox.yml``
  and the four Dockerfiles sitting next to it;
* a **pip install** — ``site-packages/sandbox_kit/…`` with those files
  installed as shared data under ``<prefix>/share/wraithwall/``.

Everything that needs an asset (compose file, Dockerfiles, the build context)
resolves through :data:`ASSET_ROOT` so neither layout needs a special case at
the call site. The build context itself is staged by
:func:`sandbox_kit.compose.prepare_build_context`, which maps each layout onto
the same ``src/ sandbox_kit/ detonate_sandbox/ requirements.txt`` tree the
Dockerfiles expect — that mapping is what makes an installed wheel bootable
with no repo checkout.
"""
from __future__ import annotations

import sys
from pathlib import Path

#: Parent of the ``sandbox_kit`` package — the repo root in a checkout, and
#: ``site-packages`` in an installed wheel.
REPO_ROOT = Path(__file__).resolve().parent.parent

#: The file whose presence identifies a real asset directory.
_MARKER = "compose.sandbox.yml"


def _shared_candidates() -> list[Path]:
    seen: list[Path] = []
    for base in (sys.prefix, sys.base_prefix, Path(sys.executable).resolve().parent.parent):
        cand = Path(base) / "share" / "wraithwall"
        if cand not in seen:
            seen.append(cand)
    return seen


def asset_root() -> Path:
    """Directory holding ``compose.sandbox.yml`` and the Dockerfiles.

    Falls back to :data:`REPO_ROOT` so an asset-less install fails with the
    real "file not found" at build time rather than an ``AttributeError``
    here.
    """
    if (REPO_ROOT / _MARKER).is_file():
        return REPO_ROOT
    for cand in _shared_candidates():
        if (cand / _MARKER).is_file():
            return cand
    return REPO_ROOT


#: Resolved once at import — the environment does not change under a process.
ASSET_ROOT = asset_root()

#: True when running from a repository checkout (assets sit beside the package).
IS_CHECKOUT = ASSET_ROOT == REPO_ROOT


def describe() -> str:
    """One-line layout description for ``status`` / ``verify`` output."""
    layout = "repo checkout" if IS_CHECKOUT else "installed (shared data)"
    return f"sandbox assets: {ASSET_ROOT} [{layout}]"


def site_packages() -> Path:
    """The import root holding the installed ``wraithwall`` package.

    Used to build ``src/`` for an installed-wheel build context.
    """
    import wraithwall

    return Path(wraithwall.__file__).resolve().parent.parent


def ignored(_src, names) -> set:
    """shutil.copytree ignore hook: never ship caches into a build context."""
    return {n for n in names if n == "__pycache__" or n.endswith(".pyc")}