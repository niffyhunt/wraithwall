"""Tests for the plugin system."""

from raven.plugins.base import RavenPlugin, PluginRegistry, PluginFindings


class MockPlugin(RavenPlugin):
    name = "mock"
    api_version = "1.x"

    def analyze(self, ctx):
        return PluginFindings()


def test_plugin_registration():
    registry = PluginRegistry()
    plugin = MockPlugin()
    registry.register(plugin)

    assert "mock" in registry.list_all()
    assert registry.get("mock") is plugin


def test_plugin_version_check():
    registry = PluginRegistry()
    assert registry._check_version("1.0") is True
    assert registry._check_version("1.x") is True
    assert registry._check_version("0.5") is True
    assert registry._check_version("2.0") is False
    assert registry._check_version("3.x") is False


def test_plugin_findings():
    pf = PluginFindings()
    pf.findings.append({"severity": "high", "message": "test"})
    pf.warnings.append("warning")
    pf.errors.append("error")

    d = pf.to_dict()
    assert len(d["findings"]) == 1
    assert len(d["warnings"]) == 1
    assert len(d["errors"]) == 1
