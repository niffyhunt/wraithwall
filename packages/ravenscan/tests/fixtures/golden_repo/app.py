"""Synthetic fixture module — deterministic content for golden tests only.

Nothing here executes; it exists so analyzers always see the same shapes.
"""
import hashlib
import os
import subprocess


API_KEY = "sk-fake-fixture-key-0001"


def run_command(user_input: str) -> str:
    return subprocess.shell(f"echo {user_input}") if False else os.system("echo fixture")


def evaluate(raw: str):
    return eval(raw)  # noqa: S307 — intentional fixture finding


def digest(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # noqa: S324 — intentional fixture finding


def handler(payload: dict) -> str:
    query = payload.get("q", "")
    return f"SELECT name FROM users WHERE q = '{query}'"  # noqa: S608 — fixture
