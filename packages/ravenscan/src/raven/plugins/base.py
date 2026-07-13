"""Raven plugin system.

Plugins are discovered via entry_points (group: raven.plugins) and must
satisfy the RavenPlugin Protocol. Core checks api_version at load time and
refuses incompatible plugins.
"""

from __future__ import annotations

import sys
from typing import Protocol, runtime_checkable

from raven.core.context import RepositoryContext

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class PluginFindings:
    """Container for plugin analysis results."""

    def __init__(self) -> None:
        self.findings: list[dict[str, object]] = []
        self.warnings: list[str] = []
        self.errors: list[str] = []

    def to_dict(self) -> dict[str, object]:
        return {
            "findings": self.findings,
            "warnings": self.warnings,
            "errors": self.errors,
        }


@runtime_checkable
class RavenPlugin(Protocol):
    """Protocol that all Raven plugins must satisfy.

    Attributes:
        name: Unique plugin identifier.
        api_version: Declared compatibility range (e.g., "1.x").
        analyze: Entry point for analysis. Receives a read-only RepositoryContext.
    """

    name: str
    api_version: str

    def analyze(self, ctx: RepositoryContext) -> PluginFindings: ...


class PluginRegistry:
    """Discovers and manages Raven plugins."""

    def __init__(self) -> None:
        self._plugins: dict[str, RavenPlugin] = {}

    def discover(self) -> dict[str, RavenPlugin]:
        """Discover plugins from entry_points group raven.plugins."""
        try:
            from importlib.metadata import entry_points
        except ImportError:
            from importlib_metadata import entry_points  # type: ignore[import-not-found,no-redef]

        discovered: dict[str, RavenPlugin] = {}
        try:
            eps = entry_points(group="raven.plugins")
        except TypeError:
            eps = entry_points().get("raven.plugins", [])  # type: ignore[attr-defined]

        for ep in eps:
            try:
                plugin_cls = ep.load()
                instance = plugin_cls()
                if not isinstance(instance, RavenPlugin):
                    continue
                if not self._check_version(instance.api_version):
                    print(
                        f"Warning: plugin '{instance.name}' requires api_version "
                        f"'{instance.api_version}' which is not compatible — skipping."
                    )
                    continue
                discovered[instance.name] = instance
            except Exception as exc:
                print(f"Warning: failed to load plugin '{ep.name}': {exc}")

        self._plugins.update(discovered)
        return self._plugins

    def register(self, plugin: RavenPlugin) -> None:
        """Manually register a plugin instance."""
        if not self._check_version(plugin.api_version):
            raise ValueError(
                f"Plugin '{plugin.name}' api_version '{plugin.api_version}' "
                f"is not compatible."
            )
        self._plugins[plugin.name] = plugin

    def get(self, name: str) -> RavenPlugin | None:
        return self._plugins.get(name)

    def list_all(self) -> list[str]:
        return sorted(self._plugins.keys())

    @staticmethod
    def _check_version(api_version: str) -> bool:
        """Check if the plugin's declared api_version is compatible.

        Accepts versions starting with '0.' or '1.' for v0.1 compatibility.
        """
        return api_version.startswith("1.") or api_version.startswith("0.")


registry = PluginRegistry()
