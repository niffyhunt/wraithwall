"""Raven — open-source engineering intelligence agent.

Public SDK surface: import `Raven` from here.
"""

from raven.__about__ import __version__, __package_name__
from raven.sdk.client import Raven

__all__ = ["Raven", "__version__", "__package_name__"]
