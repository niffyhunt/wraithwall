"""Tests for Operational Intelligence (Phase 6)."""

from raven.operational.inspector import analyze


def test_operational_analyze_graceful_degradation():
    """Operational analysis should not crash when Docker/psutil are absent."""
    health = analyze()
    assert health.scanned_at is not None
    assert health.overall_status in ("healthy", "unknown", "degraded", "warning")
    assert isinstance(health.anomalies, list)
    assert isinstance(health.warnings, list)


def test_operational_has_attributes():
    """OperationalHealth should have all expected fields."""
    health = analyze()
    assert hasattr(health, "has_docker")
    assert hasattr(health, "has_systemd")
    assert hasattr(health, "has_psutil")
    assert hasattr(health, "containers")
    assert hasattr(health, "systemd_services")
    assert hasattr(health, "overall_status")
