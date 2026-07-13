"""Public import surface smoke tests."""
from wraithwall import Client, create_app
from wraithwall.gateway import Gateway
from wraithwall.link_checker import analyze


def test_public_imports():
    assert callable(create_app)
    assert callable(analyze)
    assert hasattr(Gateway, "is_ip_blocked")
    assert Client("http://127.0.0.1:1").base_url == "http://127.0.0.1:1"