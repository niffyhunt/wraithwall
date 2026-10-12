"""Tenant-scoped, read-only WraithWall intelligence client.

The client consumes only authorized Raven feeds. It never sends source code and
never treats threat intelligence as repository evidence. Transport validation is
fail-closed: tenant identity, HTTPS, DNS destination safety, request integrity,
replay resistance, response scope, and response tenant all must validate.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import socket
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests

from raven.core.models import IntelligencePrioritization, SecurityFinding


class WraithWallIntelError(RuntimeError):
    """Raised when authorized intelligence cannot be safely consumed."""


class WraithWallIntelClient:
    """Fetch tenant-scoped WraithWall context using the Raven auth contract."""

    def __init__(self, base_url: str | None = None, api_key: str | None = None, api_secret: str | None = None, tenant_id: str | None = None, timeout: float = 5.0, max_response_bytes: int = 2 * 1024 * 1024) -> None:
        self.base_url = (base_url or os.getenv("WRAITHWALL_URL", "https://wraithwall.online")).rstrip("/")
        self.expected_tenant = (tenant_id or os.getenv("WRAITH_TENANT_ID", "")).strip()
        self.allowed_hosts = {host.strip().lower() for host in os.getenv("WRAITHWALL_ALLOWED_HOSTS", "wraithwall.online").split(",") if host.strip()}
        # Credential precedence: explicit args > env vars > stored device-login
        # file. The stored file is refused (not silently used) when its
        # permissions are too open — see raven.wraithwall.login.
        stored: dict[str, str] | None = None
        if not (api_key and api_secret and self.expected_tenant):
            from raven.wraithwall.login import credentials_path, load_credentials
            try:
                stored = load_credentials(credentials_path())
            except Exception as exc:
                raise WraithWallIntelError(str(exc)) from exc
        self.api_key = api_key or os.getenv("WRAITH_API_KEY") or (stored or {}).get("api_key")
        self.api_secret = api_secret or os.getenv("WRAITH_API_SECRET") or (stored or {}).get("secret")
        self.expected_tenant = self.expected_tenant or (stored or {}).get("tenant_id", "").strip()
        if self.expected_tenant and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", self.expected_tenant):
            raise WraithWallIntelError("WraithWall tenant identity is invalid")
        self.timeout = min(max(float(timeout), 0.5), 15.0)
        self.max_response_bytes = max(1024, int(max_response_bytes))

    def _validate_destination(self) -> str:
        parsed = urlparse(self.base_url)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host or host not in self.allowed_hosts:
            raise WraithWallIntelError("WraithWall URL is not on the HTTPS allowlist")
        if parsed.username or parsed.password or parsed.port not in (None, 443):
            raise WraithWallIntelError("WraithWall URL contains unsafe connection details")
        try:
            addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        except OSError as exc:
            raise WraithWallIntelError("WraithWall destination could not be resolved") from exc
        if not addresses:
            raise WraithWallIntelError("WraithWall destination could not be resolved")
        for address in {row[4][0] for row in addresses}:
            try:
                parsed_ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise WraithWallIntelError("WraithWall destination resolved to an invalid address") from exc
            if parsed_ip.is_private or parsed_ip.is_loopback or parsed_ip.is_link_local or parsed_ip.is_multicast or parsed_ip.is_reserved or parsed_ip.is_unspecified:
                raise WraithWallIntelError("WraithWall destination resolved to a private address")
        return host

    def _headers(self, method: str, path: str, body: str = "") -> dict[str, str]:
        if not self.api_key or not self.api_secret:
            raise WraithWallIntelError("WraithWall authorization is not configured")
        if not self.expected_tenant:
            raise WraithWallIntelError("WraithWall tenant identity is not configured")
        timestamp = str(int(time.time()))
        nonce = secrets.token_urlsafe(18)
        message = f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{body}"
        signature = hmac.new(self.api_secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
        # The public key identifies the credential. The signing secret is used
        # only in-process to produce the HMAC and is never concatenated into a
        # bearer token, URL, response, or request header. The signature binds
        # method, path, body, timestamp, and nonce.
        return {"Authorization": f"Bearer {self.api_key}", "Accept": "application/json", "X-Requested-With": "XMLHttpRequest", "X-Raven-Tenant": self.expected_tenant, "X-API-Timestamp": timestamp, "X-API-Nonce": nonce, "X-API-Signature": signature}

    def _decode_response(self, response: Any, *, expected_status: int = 200) -> dict[str, Any]:
        """Bound and validate a JSON response for any Raven transport verb."""
        response_headers = getattr(response, "headers", {}) or {}
        content_length = response_headers.get("Content-Length", "")
        try:
            content_length_value = int(content_length) if content_length else 0
        except (TypeError, ValueError) as exc:
            raise WraithWallIntelError("WraithWall response length is invalid") from exc
        if content_length_value > self.max_response_bytes:
            raise WraithWallIntelError("WraithWall response exceeded the size limit")
        raw = getattr(response, "content", None)
        if raw is None:
            import json
            raw = json.dumps(response.json()).encode("utf-8")
        if not isinstance(raw, (bytes, bytearray)) or len(raw) > self.max_response_bytes:
            raise WraithWallIntelError("WraithWall response exceeded the size limit")
        if response.status_code in (301, 302, 303, 307, 308):
            raise WraithWallIntelError("WraithWall redirected an intelligence request")
        if response.status_code in (401, 403):
            raise WraithWallIntelError("WraithWall authorization denied")
        if response.status_code != expected_status:
            raise WraithWallIntelError("WraithWall intelligence unavailable")
        try:
            import json
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise WraithWallIntelError("WraithWall returned invalid JSON") from exc
        if not isinstance(payload, dict) or payload.get("ok") is not True:
            raise WraithWallIntelError("WraithWall response failed validation")
        if payload.get("scope") != "tenant-threat-intelligence":
            raise WraithWallIntelError("WraithWall response is not tenant-scoped")
        if payload.get("tenant_id") != self.expected_tenant:
            raise WraithWallIntelError("WraithWall response tenant mismatch")
        return payload

    def _get(self, path: str) -> dict[str, Any]:
        self._validate_destination()
        headers = self._headers("GET", path)
        try:
            response = requests.get(self.base_url + path, headers=headers, timeout=self.timeout, allow_redirects=False, stream=True)
            return self._decode_response(response)
        except WraithWallIntelError:
            raise
        except (requests.RequestException, ValueError) as exc:
            raise WraithWallIntelError("WraithWall intelligence unavailable") from exc

    def submit_scan(self, profile: dict[str, Any]) -> dict[str, Any]:
        """Submit a validated profile through the same signed transport contract."""
        import json
        if not isinstance(profile, dict):
            raise WraithWallIntelError("WraithWall scan profile is invalid")
        self._validate_destination()
        body = json.dumps({"profile": profile}, separators=(",", ":"), sort_keys=True)
        headers = self._headers("POST", "/api/raven/submit-scan", body)
        headers["Content-Type"] = "application/json"
        try:
            response = requests.post(
                self.base_url + "/api/raven/submit-scan",
                headers=headers,
                data=body,
                timeout=self.timeout,
                allow_redirects=False,
            )
            return self._decode_response(response)
        except WraithWallIntelError:
            raise
        except (requests.RequestException, ValueError) as exc:
            raise WraithWallIntelError("WraithWall submission unavailable") from exc

    def whoami(self) -> dict[str, Any]:
        """Return validated caller identity without exposing credentials."""
        payload = self._get("/api/raven/whoami")
        user = payload.get("user")
        if not isinstance(user, str) or not isinstance(payload.get("tenant_id"), str):
            raise WraithWallIntelError("WraithWall identity payload invalid")
        return {"ok": True, "user": user, "tenant_id": payload["tenant_id"], "platform": payload.get("platform", "wraithwall"), "version": payload.get("version", "")}

    @staticmethod
    def _valid_tenant_item(item: Any, tenant_id: str) -> bool:
        return isinstance(item, dict) and item.get("tenant_id") == tenant_id

    def campaigns(self) -> list[dict[str, Any]]:
        payload = self._get("/api/raven/campaigns")
        campaigns = payload.get("campaigns")
        if not isinstance(campaigns, list):
            raise WraithWallIntelError("WraithWall campaigns payload invalid")
        valid = []
        for item in campaigns:
            if not self._valid_tenant_item(item, self.expected_tenant):
                raise WraithWallIntelError("WraithWall campaign crossed the tenant boundary")
            if isinstance(item.get("campaign_id", item.get("id", "")), str):
                valid.append(item)
        return valid

    def bgp_alerts(self) -> list[dict[str, Any]]:
        payload = self._get("/api/raven/bgp-alerts")
        alerts = payload.get("alerts")
        if not isinstance(alerts, list):
            raise WraithWallIntelError("WraithWall BGP payload invalid")
        if any(not self._valid_tenant_item(item, self.expected_tenant) for item in alerts):
            raise WraithWallIntelError("WraithWall BGP alert crossed the tenant boundary")
        return alerts

    @staticmethod
    def _freshness(item: dict[str, Any]) -> tuple[str, float | None]:
        observed = item.get("observed_at") or item.get("last_seen") or item.get("timestamp")
        if not observed:
            return "", None
        try:
            value = str(observed).replace("Z", "+00:00")
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return str(observed), max(0.0, (datetime.now(timezone.utc) - dt).total_seconds())
        except ValueError:
            return "", None

    def prioritize(self, findings: list[SecurityFinding]) -> list[IntelligencePrioritization]:
        campaigns = self.campaigns()
        alerts = self.bgp_alerts()
        output: list[IntelligencePrioritization] = []
        for finding in findings:
            matched_ids: list[str] = []
            matched_techniques: list[str] = []
            matched_bgp: list[str] = []
            observed_at = ""
            freshness: float | None = None
            finding_text = f"{finding.cwe.cwe_id} {finding.title}".lower()
            tokens = {token for token in finding_text.split() if len(token) > 3}
            for campaign in campaigns:
                techniques = campaign.get("mitre_techniques", campaign.get("techniques", campaign.get("observed_techniques", [])))
                if not isinstance(techniques, list):
                    continue
                technique_text = " ".join(str(value).lower() for value in techniques)
                if technique_text and any(token in technique_text for token in tokens):
                    cid = campaign.get("campaign_id", campaign.get("id"))
                    if isinstance(cid, str):
                        matched_ids.append(cid)
                        matched_techniques.extend(str(value) for value in techniques)
                        observed_at, freshness = self._freshness(campaign)
            for alert in alerts:
                alert_text = " ".join(str(alert.get(key, "")) for key in ("type", "prefix", "origin_asn", "hijacker_asn", "description")).lower()
                if any(token in alert_text for token in tokens):
                    aid = alert.get("alert_id") or alert.get("id") or alert.get("prefix")
                    if isinstance(aid, str):
                        matched_bgp.append(aid)
                        observed_at, freshness = self._freshness(alert)
            matched = bool(matched_ids or matched_bgp)
            sources = (["WraithWall /api/raven/campaigns"] if matched_ids else []) + (["WraithWall /api/raven/bgp-alerts"] if matched_bgp else [])
            output.append(IntelligencePrioritization(finding_id=finding.finding_id, base_severity=finding.severity, contextual_priority="active-threat-context" if matched else "baseline", priority_score=100.0 if matched else 0.0, matched_campaigns=sorted(set(matched_ids)), matched_techniques=sorted(set(matched_techniques)), matched_bgp_alerts=sorted(set(matched_bgp)), freshness_seconds=freshness, observed_at=observed_at, rationale="Fresh tenant-scoped WraithWall evidence matched repository context." if matched else "No validated tenant-scoped WraithWall match.", provenance=sources))
        return output
