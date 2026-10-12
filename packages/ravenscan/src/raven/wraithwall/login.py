"""CLI device-login flow — authenticate in the browser, continue in the terminal.

Implements the CLI half of the WraithWall device-authorization grant:
request a device+user code pair, hand the operator a browser URL, poll
until they approve, then persist the minted raven:use credentials for the
existing WraithWallIntelClient transport.

Security properties:
- The device code is 256-bit random, held only in process (the server
  keeps a sha256 hash); never written to logs or disk.
- Credentials land in ~/.raven/credentials.json with mode 0600; the file
  is refused (not silently used) if it is group/world readable.
- The stored secret is used only by the existing HMAC transport; it is
  never echoed to stdout after the write.
- The verification URL host is validated against the same HTTPS
  allowlist the intelligence client enforces (no arbitrary hosts).
"""
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

import requests


class DeviceLoginError(RuntimeError):
    """Device login could not complete safely."""


def credentials_path() -> Path:
    return Path(os.getenv("RAVEN_HOME", str(Path.home() / ".raven"))) / "credentials.json"


def load_credentials(path: Path | None = None) -> dict[str, str] | None:
    """Load stored credentials; refuse (raise) if permissions are too open.

    Returns None when the file simply does not exist. A world/group-readable
    file is a hard error: silently continuing would normalize secret leakage.
    """
    target = path or credentials_path()
    if not target.exists():
        return None
    mode = stat.S_IMODE(target.stat().st_mode)
    if mode & 0o077:
        raise DeviceLoginError(
            f"{target} is group/world readable (mode {oct(mode)}). "
            f"Fix with: chmod 600 {target}"
        )
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise DeviceLoginError(f"credentials file is unreadable: {exc}") from exc
    if not isinstance(data, dict) or not all(
        isinstance(data.get(k), str) and data[k] for k in ("api_key", "secret", "tenant_id")
    ):
        raise DeviceLoginError("credentials file is malformed — run 'raven login' again")
    return data


def save_credentials(creds: dict[str, str], path: Path | None = None) -> Path:
    """Persist credentials with 0600 perms (created via O_EXCL-style open)."""
    target = path or credentials_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(creds, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.chmod(target, 0o600)
    return target


def logout(path: Path | None = None) -> bool:
    """Remove stored credentials. Returns True if a file was removed."""
    target = path or credentials_path()
    if target.exists():
        target.unlink()
        return True
    return False


def _validate_verification_url(url: str, allowed_hosts: set[str]) -> str:
    """The URL we tell the operator to visit must be HTTPS + allowlisted."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host or host not in allowed_hosts:
        raise DeviceLoginError("verification URL host is not on the HTTPS allowlist")
    return url


def device_login(
    base_url: str,
    *,
    open_browser: Callable[[str], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    stdout: Callable[[str], None] = lambda msg: print(msg),
    timeout_total: float = 600.0,
    poll_grace: float = 1.0,
) -> dict[str, str]:
    """Run the device flow end to end; returns minted credentials.

    ``open_browser`` is injectable for tests; when None the command layer
    decides (webbrowser module, best-effort, never fatal).
    """
    allowed_hosts = {
        host.strip().lower()
        for host in os.getenv("WRAITHWALL_ALLOWED_HOSTS", "wraithwall.online").split(",")
        if host.strip()
    }
    base = base_url.rstrip("/")
    parsed = urlparse(base)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or host not in allowed_hosts:
        raise DeviceLoginError("WraithWall URL must be HTTPS and on the allowlist")

    try:
        resp = requests.post(
            f"{base}/api/device/code",
            json={},
            headers={"X-Requested-With": "XMLHttpRequest"},
            timeout=10,
        )
        resp.raise_for_status()
        payload = resp.json()
    except (requests.RequestException, ValueError) as exc:
        raise DeviceLoginError(f"could not request a device code: {exc}") from exc

    device_code = payload.get("device_code")
    user_code = payload.get("user_code")
    verify_url = _validate_verification_url(payload.get("verification_uri_complete", ""), allowed_hosts)
    interval = max(2.0, float(payload.get("interval", 5)))
    expires_in = float(payload.get("expires_in", 600))
    if not isinstance(device_code, str) or not isinstance(user_code, str):
        raise DeviceLoginError("server response is missing device credentials")

    stdout("")
    stdout(f"  Open:  {verify_url}")
    stdout(f"  Code:  {user_code}")
    stdout("")
    stdout("  Approve in your browser to finish. Waiting...")
    if open_browser is not None:
        try:
            open_browser(verify_url)
        except Exception:
            pass  # browser open is best-effort; the URL is printed

    deadline = time.monotonic() + min(timeout_total, expires_in) - poll_grace
    while time.monotonic() < deadline:
        sleep(interval)
        try:
            poll = requests.post(
                f"{base}/api/device/token",
                json={"device_code": device_code},
                headers={"X-Requested-With": "XMLHttpRequest"},
                timeout=10,
            )
        except requests.RequestException:
            continue  # transient network failure: keep polling until deadline
        if poll.status_code == 200:
            data = poll.json()
            creds = {
                "api_key": data.get("api_key", ""),
                "secret": data.get("secret", ""),
                "tenant_id": data.get("tenant_id", ""),
                "url": base,
            }
            if not all(creds[k] for k in ("api_key", "secret", "tenant_id")):
                raise DeviceLoginError("server granted an incomplete credential set")
            return creds
        try:
            err = poll.json().get("error", "")
        except ValueError:
            err = ""
        if err == "authorization_pending":
            continue
        if err == "access_denied":
            raise DeviceLoginError("login denied in the browser")
        if err in ("expired_token", "invalid_grant"):
            raise DeviceLoginError("device code expired or consumed — restart raven login")
        if err == "key_cap_reached":
            raise DeviceLoginError("active API key cap reached — revoke one in the console")
        # unknown error: keep polling until deadline (forward compatible)
    raise DeviceLoginError("timed out waiting for browser approval")
