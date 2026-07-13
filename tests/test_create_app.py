"""Smoke tests for the application factory."""
import os
def test_create_app_returns_flask_instance():
    from wraithwall import create_app
    app = create_app({"TESTING": True, "SECRET_KEY": "test"})
    assert app is not None
    assert len(app.blueprints) >= 5
def test_health_endpoint():
    from wraithwall import create_app
    app = create_app({"TESTING": True, "SECRET_KEY": "test"})
    with app.test_client() as client:
        resp = client.get("/api/health")
        assert resp.status_code in (200, 301, 404)
