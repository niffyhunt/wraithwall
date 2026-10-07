"""Sandbox-contract test matrix for the published ``wraithwall`` package.

Every sandbox-mode scenario runs in a subprocess so the import-time flag read
is genuine — the flag cannot be flipped after import, which is exactly what
makes it a boundary rather than a preference. Default-mode invariance is
asserted against the committed golden surface
(``tests/golden/default_mode_surface.txt``).

Matrix coverage:
  §4.1  default-mode regression (flag absent / disabled / malformed)
  §4.2  flag parsing table (strict allowlist, '1' only)
  §4.3  no background engine starts at boot (zero ambient authority)
  §4.4  no interactive terminal endpoint is exposed
  §4.5  alert-transport stubbing (intent recorded, zero network I/O)
  §4.6  failure-safe restart (no capability persists across restart)
  §4.7  rate limiter is self-contained even with ambient Redis configured
  §0.5  the startup log line (observability of the gate itself)
"""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GOLDEN_PATH = REPO_ROOT / "tests" / "golden" / "default_mode_surface.txt"
OUT_PATH = "/tmp/wraithwall_sbx_test_out.json"

CANONICAL_ENV = {
    "TESTING": "1",
    "FLASK_ENV": "development",
    "SECRET_KEY": "test-secret",
    "DATABASE_URL": "sqlite:///:memory:",
    # No ambient Redis and no ambient provider keys: the surface under test
    # must not depend on whatever a given machine put in .env.
    "REDIS_URL": "",
    "PYTHONPATH": str(REPO_ROOT / "src"),
}


def _run_import(extra_env: dict, script: str):
    """Import wraithwall in a fresh subprocess with the given env and run script.

    The subprocess environment is CANONICAL_ENV plus extra_env ONLY (plus the
    unavoidable OS process variables) — never the pytest process env, so the
    import-time configuration matches the golden capture exactly.
    """
    env = {k: v for k, v in CANONICAL_ENV.items()}
    env.update(extra_env)
    return subprocess.run(
        [sys.executable, "-c", script],
        cwd=REPO_ROOT, env=env, capture_output=True, text=True, timeout=300,
    )


def _load_golden() -> dict:
    txt = GOLDEN_PATH.read_text()
    return json.loads(txt[txt.index("{"):])


def _read_out() -> dict:
    return json.loads(Path(OUT_PATH).read_text())


def _surface_script() -> str:
    """Subprocess body that writes the live surface to OUT_PATH."""
    return (
        "import json, threading\n"
        "from wraithwall import create_app, sandbox_mode\n"
        "app = create_app({'TESTING': True})\n"
        "limiter = next(iter(app.extensions['limiter']))\n"
        "surface = {\n"
        "    'routes': sorted(str(r) for r in app.url_map.iter_rules()),\n"
        "    'blueprints': sorted(app.blueprints),\n"
        "    'threads': sorted(t.name for t in threading.enumerate()),\n"
        "    'sandbox_mode': sandbox_mode.SANDBOX_MODE,\n"
        "    'flag_malformed': sandbox_mode.FLAG_MALFORMED,\n"
        "    'ext_sandbox_mode': app.extensions['wraithwall']['sandbox_mode'],\n"
        "    'limiter_storage': str(limiter._storage_uri),\n"
        "}\n"
        f"open({OUT_PATH!r}, 'w').write(json.dumps(surface))\n"
    )


def _golden_compare(surface: dict) -> None:
    golden = _load_golden()
    assert sorted(golden["routes"]) == surface["routes"]
    assert sorted(golden["blueprints"]) == surface["blueprints"]
    assert sorted(golden["threads_started_at_boots"]) == surface["threads"]


# --------------------------------------------------------------------------
# §4.2 flag parsing — table-driven, on the real module function
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("1", True),
    ("", False),
    ("0", False),
    ("true", False),
    ("TRUE", False),
    ("True", False),
    ("yes", False),
    ("on", False),
    (" 1", False),
    ("1 ", False),
    ("2", False),
    ("01", False),
    ("1.0", False),
    ("\t1", False),
    ("garbage", False),
    ("1\x00", False),
])
def test_flag_parsing_table(raw, expected):
    from wraithwall.sandbox_mode import parse_sandbox_flag
    assert parse_sandbox_flag(raw) is expected


def test_flag_parse_none_is_disabled():
    from wraithwall.sandbox_mode import parse_sandbox_flag
    assert parse_sandbox_flag(None) is False


def test_flag_env_name_is_stable():
    """The env var name is the sandbox contract; renaming it silently disables
    every gate, so it is pinned like a public API."""
    from wraithwall.sandbox_mode import SANDBOX_FLAG_ENV
    assert SANDBOX_FLAG_ENV == "WRAITHWALL_SANDBOX"


# --------------------------------------------------------------------------
# §4.1 default-mode regression — flag absent / disabled / malformed
# --------------------------------------------------------------------------

def test_default_mode_flag_absent_matches_golden():
    proc = _run_import({}, _surface_script())
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = _read_out()
    _golden_compare(out)
    assert out["sandbox_mode"] is False
    assert out["flag_malformed"] is False
    assert out["ext_sandbox_mode"] is False


def test_default_mode_flag_disabled_matches_default():
    proc = _run_import({"WRAITHWALL_SANDBOX": "0"}, _surface_script())
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = _read_out()
    _golden_compare(out)
    assert out["sandbox_mode"] is False
    assert out["flag_malformed"] is False


def test_default_mode_flag_malformed_still_default():
    for bad in ("true", "TRUE", "yes", " 1", "garbage"):
        proc = _run_import({"WRAITHWALL_SANDBOX": bad}, _surface_script())
        assert proc.returncode == 0, proc.stderr[-2000:]
        out = _read_out()
        _golden_compare(out)
        assert out["sandbox_mode"] is False, bad
        # a botched enable must be *visible*, not silently ignored
        assert out["flag_malformed"] is True, bad


# --------------------------------------------------------------------------
# §4.3 no background engine starts at boot
# --------------------------------------------------------------------------

def test_sandbox_and_default_mode_start_no_background_threads():
    """Zero ambient authority: booting the app starts no worker of its own.

    The published package registers no scheduler and starts no engine thread;
    engines are opt-in (start_cowrie_watcher / start_propagation_network).
    A thread appearing here means a blueprint grew a boot side effect.
    """
    for env in ({}, {"WRAITHWALL_SANDBOX": "1"}):
        proc = _run_import(env, _surface_script())
        assert proc.returncode == 0, proc.stderr[-2000:]
        out = _read_out()
        assert out["threads"] == ["MainThread"], out["threads"]


# --------------------------------------------------------------------------
# §4.4 no interactive terminal endpoint
# --------------------------------------------------------------------------

def test_no_interactive_terminal_endpoint_in_either_mode():
    """The package exposes no PTY/shell route, in default or sandbox mode.

    terminal_bp ships in the source tree for the private monolith's use but is
    deliberately not registered by create_app(): an OSS install has no
    interactive terminal, sandboxed or not.
    """
    for env in ({}, {"WRAITHWALL_SANDBOX": "1"}):
        proc = _run_import(env, _surface_script())
        assert proc.returncode == 0, proc.stderr[-2000:]
        out = _read_out()
        assert not [r for r in out["routes"] if "terminal" in r], out["routes"]
        assert "terminal" not in out["blueprints"]


def test_sandbox_mode_route_surface_is_identical_to_default():
    """The flag changes posture, never the API surface."""
    proc_default = _run_import({}, _surface_script())
    assert proc_default.returncode == 0, proc_default.stderr[-2000:]
    default_surface = _read_out()
    proc_sandbox = _run_import({"WRAITHWALL_SANDBOX": "1"}, _surface_script())
    assert proc_sandbox.returncode == 0, proc_sandbox.stderr[-2000:]
    sandbox_surface = _read_out()
    assert default_surface["routes"] == sandbox_surface["routes"]
    assert default_surface["blueprints"] == sandbox_surface["blueprints"]


# --------------------------------------------------------------------------
# §4.5 alert-transport stubbing — intent recorded, zero network I/O
# --------------------------------------------------------------------------

def test_sandbox_mode_transport_stubs_no_io():
    proc = _run_import({"WRAITHWALL_SANDBOX": "1"}, (
        "import json, logging, socket, urllib.request\n"
        "logging.basicConfig(level=logging.INFO)\n"
        "from wraithwall.shared import send_telegram_alert_bg, send_discord_alert_bg\n"
        "class _Forbidden(Exception):\n"
        "    pass\n"
        "def _no_network(*a, **k):\n"
        "    raise _Forbidden('NETWORK I/O ATTEMPTED IN SANDBOX MODE')\n"
        "socket.socket.connect = _no_network\n"
        "socket.create_connection = _no_network\n"
        "urllib.request.urlopen = _no_network\n"
        "results = {}\n"
        "results['telegram_bg'] = send_telegram_alert_bg('test message')\n"
        "results['discord_bg'] = send_discord_alert_bg({'content': 'test'})\n"
        f"open({OUT_PATH!r}, 'w').write(json.dumps(results))\n"
    ))
    assert proc.returncode == 0, proc.stderr[-3000:]
    results = _read_out()
    assert results["telegram_bg"] is None
    assert results["discord_bg"] is None


def test_sandbox_mode_stub_intent_is_logged():
    proc = _run_import({"WRAITHWALL_SANDBOX": "1"}, (
        "import logging\n"
        "logging.basicConfig(level=logging.INFO)\n"
        "from wraithwall.shared import send_telegram_alert_bg\n"
        "send_telegram_alert_bg('proof of intent recording')\n"
        "print('PROBE_DONE')\n"
    ))
    assert proc.returncode == 0, proc.stderr[-2000:]
    combined = proc.stdout + proc.stderr
    assert "[SANDBOX-STUB]" in combined
    assert "proof of intent recording" in combined
    assert "PROBE_DONE" in combined


def test_sandbox_mode_env_key_guards_bypassed_leak_marker():
    """With ambient provider keys set, the stubs still short-circuit first."""
    proc = _run_import(
        {"WRAITHWALL_SANDBOX": "1", "TELEGRAM_BOT_TOKEN": "12345:fake",
         "TELEGRAM_CHAT_ID": "42", "DISCORD_WEBHOOK_URL": "https://example.invalid/webhook"},
        (
        "import json, logging, urllib.request\n"
        "logging.basicConfig(level=logging.INFO)\n"
        "from wraithwall.shared import send_telegram_alert_bg, send_discord_alert_bg\n"
        "class _Forbidden(Exception):\n"
        "    pass\n"
        "def _no_network(*a, **k):\n"
        "    raise _Forbidden('NETWORK I/O ATTEMPTED WITH KEYS PRESENT')\n"
        "urllib.request.urlopen = _no_network\n"
        "results = {}\n"
        "results['telegram_bg'] = send_telegram_alert_bg('leak probe')\n"
        "results['discord_bg'] = send_discord_alert_bg({'content': 'leak probe'})\n"
        f"open({OUT_PATH!r}, 'w').write(json.dumps(results))\n"
        ))
    assert proc.returncode == 0, proc.stderr[-3000:]
    results = _read_out()
    assert results["telegram_bg"] is None
    assert results["discord_bg"] is None
    assert "[SANDBOX-STUB]" in (proc.stdout + proc.stderr)


# --------------------------------------------------------------------------
# §4.6 failure-safe: no capability persists across a restart boundary
# --------------------------------------------------------------------------

def test_no_capability_persists_across_restart():
    proc = _run_import({"WRAITHWALL_SANDBOX": "1"}, (
        "from wraithwall import create_app, sandbox_mode\n"
        "assert sandbox_mode.SANDBOX_MODE is True\n"
        "app = create_app({'TESTING': True})\n"
        "assert app.extensions['wraithwall']['sandbox_mode'] is True\n"
        "print('SANDBOX_STATE_CONFIRMED')\n"
    ))
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "SANDBOX_STATE_CONFIRMED" in proc.stdout

    # Fresh process, flag absent: identical to a clean default start
    proc2 = _run_import({}, (
        "from wraithwall import create_app, sandbox_mode\n"
        "assert sandbox_mode.SANDBOX_MODE is False\n"
        "assert sandbox_mode.FLAG_MALFORMED is False\n"
        "app = create_app({'TESTING': True})\n"
        "assert app.extensions['wraithwall']['sandbox_mode'] is False\n"
        "print('DEFAULT_STATE_CONFIRMED')\n"
    ))
    assert proc2.returncode == 0, proc2.stderr[-2000:]
    assert "DEFAULT_STATE_CONFIRMED" in proc2.stdout


# --------------------------------------------------------------------------
# §4.7 hunt regression: limiter must be self-contained in sandbox mode
# --------------------------------------------------------------------------

def test_sandbox_mode_limiter_is_memory_backed_even_with_ambient_redis():
    """With ambient REDIS_URL present (host .env leakage), the sandbox process
    must not use it for rate limiting: a host Redis that rejects auth otherwise
    turns every limited route into a 500. Zero ambient authority => in-memory
    storage, while the data-plane Redis (cowrie:log) still attaches."""
    proc = _run_import(
        {"WRAITHWALL_SANDBOX": "1",
         # Closed port => instant ECONNREFUSED; proves ambient REDIS_URL cannot
         # leak into the sandbox limiter.
         "REDIS_URL": "redis://127.0.0.1:1/0"},
        _surface_script(),
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = _read_out()
    assert out["limiter_storage"] == "memory://", out["limiter_storage"]
    print("LIMITER_MEMORY_OK")


def test_default_mode_limiter_uses_redis_when_configured():
    proc = _run_import({"REDIS_URL": "redis://127.0.0.1:1/0"}, _surface_script())
    assert proc.returncode == 0, proc.stderr[-2000:]
    out = _read_out()
    assert out["limiter_storage"] == "redis://127.0.0.1:1/0", out["limiter_storage"]


# --------------------------------------------------------------------------
# §0.5 startup log line — observability of the gate itself
# --------------------------------------------------------------------------

@pytest.mark.parametrize("flag_value,expect_fragment", [
    (None, "SANDBOX FLAG: disabled |"),
    ("0", "SANDBOX FLAG: disabled |"),
    ("garbage", "SANDBOX FLAG: disabled (malformed value="),
    ("1", "SANDBOX FLAG: enabled |"),
])
def test_startup_log_line(flag_value, expect_fragment):
    env = {"WRAITHWALL_SANDBOX": flag_value} if flag_value is not None else {}
    proc = _run_import(env, (
        "import logging\n"
        "logging.basicConfig(level=logging.INFO)\n"
        "from wraithwall import create_app\n"
        "create_app({'TESTING': True})\n"
        "print('IMPORT_DONE')\n"
    ))
    assert proc.returncode == 0, proc.stderr[-2000:]
    combined = proc.stdout + proc.stderr
    assert expect_fragment in combined
    assert "commit=" in combined
    assert "version=" in combined


# --------------------------------------------------------------------------
# Golden oracle integrity
# --------------------------------------------------------------------------

def test_golden_oracle_exists_and_parses():
    assert GOLDEN_PATH.exists(), "golden surface missing — regenerate it"
    golden = _load_golden()
    assert len(golden["routes"]) > 50
    assert len(golden["blueprints"]) > 5
    assert "/api/health" in golden["routes"]
    assert "/api/v1/cowrie/ship" in golden["routes"]
    # no interactive terminal anywhere in the shipped surface
    assert not [r for r in golden["routes"] if "terminal" in r]
    # boot starts nothing but the main thread
    assert golden["threads_started_at_boots"] == ["MainThread"]