"""HTTP client for the WraithWall platform API."""
from __future__ import annotations

import os

import httpx


class Client:
    """Programmatic access to a running WraithWall instance."""

    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = (base_url or os.getenv("WRAITHWALL_URL", "http://localhost:8000")).rstrip("/")
        self.api_key = api_key
        self._client = httpx.Client(timeout=15)

    def _headers(self) -> dict:
        headers = {"X-Requested-With": "XMLHttpRequest", "Accept": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    def scan_url(self, url: str) -> dict:
        response = self._client.post(
            f"{self.base_url}/api/link/scan",
            json={"url": url},
            headers=self._headers(),
        )
        response.raise_for_status()
        return response.json()

    def public_stats(self) -> dict:
        response = self._client.get(f"{self.base_url}/api/public/stats", headers=self._headers())
        return response.json()

    def health(self) -> dict:
        response = self._client.get(f"{self.base_url}/api/health", headers=self._headers())
        return response.json()

    def detonate(self, url: str, async_mode: bool = True) -> dict:
        endpoint = "/api/link/detonate/async" if async_mode else "/api/link/detonate"
        response = self._client.post(
            f"{self.base_url}{endpoint}",
            json={"url": url},
            headers=self._headers(),
        )
        return response.json()


# Backward-compatible alias
WraithWallClient = Client