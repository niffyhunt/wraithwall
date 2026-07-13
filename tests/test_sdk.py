"""Smoke tests for the Python SDK client."""
from wraithwall import Client, WraithWallClient


def test_client_initialization():
    client = Client("http://localhost:8000")
    assert client.base_url == "http://localhost:8000"


def test_client_headers():
    client = Client(api_key="test-key-123")
    headers = client._headers()
    assert headers["X-API-Key"] == "test-key-123"
    assert headers["X-Requested-With"] == "XMLHttpRequest"


def test_backward_compatible_alias():
    assert WraithWallClient is Client