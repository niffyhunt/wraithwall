#!/usr/bin/env python3
"""
URL Detonation Sandbox — runs inside isolated Docker container.
Accepts a URL, opens it in headless Chromium via Playwright, and
captures behavioral telemetry. Outputs structured JSON report to stdout.

Safety:
  - Read-only interaction by default (scroll/wait/navigate — no autofill)
  - Fresh browser context per run (no cookies, no localStorage carried)
  - SHA-256 hash of report for tamper evidence
  - Downloads: SHA-256 then discard by default (never persist payloads)
  - Schema version for forward-compat

Usage:
    python3 detonate.py "https://example.com"
"""

import base64
import hashlib
import json
import os
import sys
import time
import traceback
from typing import Optional
from urllib.parse import urlparse

SCHEMA_VERSION = "1.0.0"
TIMEOUT_MS = int(os.environ.get("DETONATE_TIMEOUT_MS", "30000"))
SCREENSHOT_INTERVAL = int(os.environ.get("SCREENSHOT_INTERVAL_S", "2"))
SANDBOX_NETWORK = os.environ.get("SANDBOX_NETWORK", "")

INTERNAL_DOMAINS_RE = None
try:
    import re
    INTERNAL_DOMAINS_RE = re.compile(
        r"localhost|127\.|0\.0\.0\.0|10\.|172\.(1[6-9]|2[0-9]|3[01])\.|"
        r"192\.168\.|169\.254\.|::1|metadata\.internal|"
        r"compute\.amazonaws\.com|169\.254\.169\.254", re.I
    )
except Exception:
    pass


def _flag_internal_redirect(url: str, report: dict) -> None:
    """Defense-in-depth visibility: the egress proxy BLOCKS internal targets,
    but a page that *tries* to redirect/fetch one is itself a threat signal.
    Records the attempt so the report shows hostile intent even though the
    network layer refused it."""
    if INTERNAL_DOMAINS_RE is None:
        return
    try:
        host = urlparse(url).hostname or ""
        if host and INTERNAL_DOMAINS_RE.search(host):
            report["threat_signals"]["internal_target_attempts"].append(url[:300])
    except Exception:
        pass


def detonate(target_url: str) -> dict:
    from playwright.sync_api import sync_playwright, Error as PWError

    report = {
        "_schema_version": SCHEMA_VERSION,
        "url": target_url,
        "final_url": "",
        "redirect_chain": [],
        "screenshots": [],
        "network": [],
        "dom_snapshot": "",
        "console_logs": [],
        "timing": {"load_time_ms": 0, "total_runtime_ms": 0},
        "threat_signals": {
            "suspicious_redirects": [],
            "js_anomalies": [],
            "download_attempts": [],
            "cross_tld_redirects": [],
            "internal_target_attempts": [],
            "punycode_domains": [],
            "js_obfuscation_density": 0,
            "meta_refresh_chains": [],
            "window_open_floods": 0,
        },
        "download_hashes": [],
        "error": None,
        "_report_hash": "",
    }

    t_start = time.time()

    with sync_playwright() as pw:
        browser = pw.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
                "--disable-setuid-sandbox",
                "--disable-web-security",
                # T2 egress integrity (research-sandbox): WebRTC ICE/STUN rides
                # UDP and bypasses HTTP proxies entirely — a detonated page
                # could beacon out with a literal-IP STUN candidate. With
                # WebRTC off, the enforcing proxy is the only way out.
                "--disable-features=VizDisplayCompositor,WebRTC",
                "--disable-blink-features=AutomationControlled",
            ],
        )

        context_kwargs = dict(
            viewport={"width": 1280, "height": 900},
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/125.0.0.0 Safari/537.36"
            ),
            ignore_https_errors=True,
            bypass_csp=True,
            no_viewport=False,
            locale="en-US",
            timezone_id="UTC",
        )
        proxy_server = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY")
        if proxy_server:
            context_kwargs["proxy"] = {"server": proxy_server}
        context = browser.new_context(**context_kwargs)

        page = context.new_page()

        # ── Network capture ──
        def on_request(req):
            report["network"].append({
                "url": req.url,
                "method": req.method,
                "status": None,
                "resource_type": req.resource_type,
            })

        def on_response(resp):
            status = resp.status
            url = resp.url
            _flag_internal_redirect(url, report)
            for entry in reversed(report["network"]):
                if entry["url"] == url and entry["status"] is None:
                    entry["status"] = status
                    break
            if 300 <= status < 400:
                location = resp.headers.get("location", "")
                report["redirect_chain"].append(f"{status} → {url} → {location}")
                _check_cross_tld_redirect(url, location, report)

        page.on("request", on_request)
        page.on("response", on_response)

        # ── Console capture ──
        def on_console(msg):
            entry = {"type": msg.type, "text": msg.text}
            report["console_logs"].append(entry)
            _check_js_anomaly(entry, report)

        page.on("console", on_console)

        # ── Dialog suppression (prevent alert/prompt/confirm from hanging) ──
        page.on("dialog", lambda d: d.dismiss())

        # ── Download detection ──
        def on_download(download):
            record = {
                "url": download.url,
                "suggested_filename": download.suggested_filename,
            }
            try:
                content = download.create_read_stream().read()
                sha256 = hashlib.sha256(content).hexdigest()
                record["sha256"] = sha256
                report["download_hashes"].append(sha256)
            except Exception:
                record["sha256"] = ""
            report["threat_signals"]["download_attempts"].append(record)

        page.on("download", on_download)

        # ── Navigate ──
        t_nav_start = time.time()
        try:
            page.goto(target_url, wait_until="domcontentloaded", timeout=TIMEOUT_MS)
        except PWError as e:
            t_nav_end = time.time()
            report["timing"]["load_time_ms"] = int((t_nav_end - t_nav_start) * 1000)
            report["error"] = str(e)
            report["final_url"] = page.url
            report["redirect_chain"] = _deduplicate_redirects(report["redirect_chain"])
            try:
                page.wait_for_load_state("networkidle", timeout=5000)
            except Exception:
                pass
            try:
                report["dom_snapshot"] = page.content()[:50000]
            except Exception as e2:
                report["dom_snapshot"] = f"<error: {e2}>"
            report["timing"]["total_runtime_ms"] = int((time.time() - t_start) * 1000)
            report["_report_hash"] = _hash_report(report)
            browser.close()
            return report

        t_nav_end = time.time()
        report["timing"]["load_time_ms"] = int((t_nav_end - t_nav_start) * 1000)
        report["final_url"] = page.url
        report["redirect_chain"] = _deduplicate_redirects(report["redirect_chain"])

        # ── Read-only interaction (scroll only — no autofill, no submit) ──
        try:
            page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
            page.wait_for_timeout(1000)
            page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            page.wait_for_timeout(1000)
        except Exception:
            pass

        # ── Screenshot after scroll ──
        try:
            screenshot_b64 = page.screenshot(type="png", full_page=True)
            report["screenshots"].append(base64.b64encode(screenshot_b64).decode())
        except Exception:
            pass

        # ── Wait for network idle ──
        try:
            page.wait_for_load_state("networkidle", timeout=10000)
        except Exception:
            pass

        # ── DOM capture ──
        try:
            report["dom_snapshot"] = page.content()[:50000]
        except Exception:
            pass

        # ── Post-load threat signal analysis ──
        try:
            _analyze_js_obfuscation(page, report)
            _check_punycode(report)
            _check_meta_refresh(page, report)
            _check_window_open_flood(page, report)
        except Exception:
            pass

        # ── Screenshot at idle ──
        try:
            screenshot2_b64 = page.screenshot(type="png", full_page=True)
            report["screenshots"].append(base64.b64encode(screenshot2_b64).decode())
        except Exception:
            pass

        browser.close()

    report["timing"]["total_runtime_ms"] = int((time.time() - t_start) * 1000)
    report["_report_hash"] = _hash_report(report)
    return report


# ── Threat Signal Detectors ────────────────────────────────────────────


def _check_cross_tld_redirect(from_url: str, to_location: str, report: dict):
    try:
        from_tld = urlparse(from_url).hostname or ""
        to_host = urlparse(to_location).hostname or ""
        if not from_tld or not to_host:
            return
        from_parts = from_tld.split(".")
        to_parts = to_host.split(".")
        from_tld_label = ".".join(from_parts[-2:]) if len(from_parts) >= 2 else from_tld
        to_tld_label = ".".join(to_parts[-2:]) if len(to_parts) >= 2 else to_host
        if from_tld_label != to_tld_label and from_tld_label and to_tld_label:
            report["threat_signals"]["cross_tld_redirects"].append(
                f"{from_tld} → {to_host}"
            )
    except Exception:
        pass


def _check_js_anomaly(entry: dict, report: dict):
    text = entry.get("text", "").lower()
    if entry.get("type") == "error":
        report["threat_signals"]["js_anomalies"].append(f"[JS ERROR] {entry.get('text', '')}")
    suspicious_patterns = [
        "eval(", "document.write", "window.open",
        "webdriver", "debugger", "phantom", "selenium",
    ]
    for pat in suspicious_patterns:
        if pat in text:
            report["threat_signals"]["js_anomalies"].append(
                f"[SUSPICIOUS: {pat}] {entry.get('text', '')}"
            )


def _analyze_js_obfuscation(page, report: dict):
    try:
        density = page.evaluate("""() => {
            const scripts = document.querySelectorAll('script:not([src])');
            let total = 0, obfuscated = 0;
            scripts.forEach(s => {
                const t = (s.textContent || '').length;
                total += t;
                if (t > 100) {
                    const lower = s.textContent.toLowerCase();
                    const evals = (lower.match(/eval/g) || []).length;
                    const fromChar = (lower.match(/fromcharcode/g) || []).length;
                    const atob = (lower.match(/\\batob\\b/g) || []).length;
                    const hex = (lower.match(/\\\\x[0-9a-f]{2}/g) || []).length;
                    const num = (lower.match(/\\\\u[0-9a-f]{4}/g) || []).length;
                    if (evals + fromChar + atob + hex + num > 5) obfuscated += t;
                }
            });
            return total > 0 ? (obfuscated / total) : 0;
        }""")
        report["threat_signals"]["js_obfuscation_density"] = round(density, 4)
    except Exception:
        pass


def _check_punycode(report: dict):
    for entry in report.get("network", []):
        try:
            url = entry.get("url", "")
            hostname = urlparse(url).hostname or ""
            if hostname.startswith("xn--"):
                if hostname not in report["threat_signals"].get("punycode_domains", []):
                    report["threat_signals"]["punycode_domains"].append(hostname)
        except Exception:
            pass


def _check_meta_refresh(page, report: dict):
    try:
        refreshes = page.evaluate("""() => {
            const metas = document.querySelectorAll('meta[http-equiv="refresh"]');
            return Array.from(metas).map(m => m.getAttribute('content') || '');
        }""")
        if refreshes and len(refreshes) > 0:
            report["threat_signals"]["meta_refresh_chains"] = refreshes
    except Exception:
        pass


def _check_window_open_flood(page, report: dict):
    try:
        count = page.evaluate("""() => {
            const before = window._detonate_win_count || 0;
            window._detonate_win_count = (before || 0) + 1;
            return window._detonate_win_count;
        }""")
        report["threat_signals"]["window_open_floods"] = count
    except Exception:
        pass


def _deduplicate_redirects(chain: list) -> list:
    seen = set()
    result = []
    for r in chain:
        if r not in seen:
            seen.add(r)
            result.append(r)
    return result


def _hash_report(report: dict) -> str:
    serialized = json.dumps(report, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


# ── Entrypoint ─────────────────────────────────────────────────────────


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No URL provided", "_schema_version": SCHEMA_VERSION}))
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        report = detonate(url)
        print(json.dumps(report))
    except Exception as e:
        print(
            json.dumps(
                {
                    "url": url,
                    "error": str(e),
                    "traceback": traceback.format_exc(),
                    "_schema_version": SCHEMA_VERSION,
                }
            )
        )
        sys.exit(1)
