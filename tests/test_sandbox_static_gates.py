"""Static sandbox gate tests (Phase 3) — G1–G6, G7-static, G9, H10.

Two halves:

* the **real** `compose.sandbox.yml` must pass every gate (otherwise the shipped
  sandbox is not shippable), and
* a **mutation matrix** proves each gate actually fails closed: one weakened or
  banned option at a time, asserting the refusal and the specific gate that
  caught it. A gate that cannot fail is not a gate.

These are pure-Python: no daemon, no containers, no disk cost. The live
counterparts (boot, `docker inspect`, egress canary) live in
`tests/test_sandbox_live.py` and are opt-in.
"""
from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from sandbox_kit import assets, compose, gates_static, images
from sandbox_kit.gates import GateFailure

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_COMPOSE = REPO_ROOT / "compose.sandbox.yml"


# ── fixtures / helpers ─────────────────────────────────────────────────────

@pytest.fixture()
def doc() -> dict:
    return yaml.safe_load(REAL_COMPOSE.read_text())


def _refuse(tmp_path: Path, doc: dict, raw: str | None = None) -> GateFailure:
    path = tmp_path / "compose.sandbox.yml"
    path.write_text(raw if raw is not None else yaml.safe_dump(doc))
    with pytest.raises(GateFailure) as excinfo:
        gates_static.inspect_compose(path)
    return excinfo.value


def _gate_of(failure: GateFailure) -> str:
    for line in failure.message.splitlines():
        if line.strip().startswith("[") and line.strip().endswith("]"):
            return line.strip().strip("[]")
    return "?"


# ── the shipped file must pass ─────────────────────────────────────────────

def test_real_compose_passes_all_static_gates():
    summary = gates_static.inspect_compose(REAL_COMPOSE)
    assert summary["services"] == ["sb-app", "sb-busybox", "sb-busybox-t",
                                    "sb-detonate", "sb-egress",
                                    "sb-policy-selftest", "sb-redis",
                                    "sb-research-canary", "sb-seed", "sb-uplink"]
    assert summary["gate_count"] == 11


def test_real_compose_publishes_nothing_and_is_internal():
    """The two properties the whole egress claim rests on.

    Phase 5: the OPTIONAL uplink service (compose profile `uplink`, off by
    default) is the single sanctioned exception — loopback-host publish only,
    on the masquerade-disabled uplink network, enforced by the G6/G7 gates
    above. Anything else publishing anything is a failure.
    """
    doc = yaml.safe_load(REAL_COMPOSE.read_text())
    for name, svc in doc["services"].items():
        if svc.get("profiles"):
            continue  # optional profile services are gated by G6/G7, not here
        assert not svc.get("ports"), f"{name} publishes a port"
    for net, spec in doc["networks"].items():
        if net == "ww-uplink-net":
            assert spec.get("internal") is not True
            opts = spec.get("driver_opts") or {}
            assert opts.get(
                "com.docker.network.bridge.enable_ip_masquerade") == "false"
            continue
        if net == "ww-egress-net":
            # Phase 11: the research plane is the second (and only other)
            # non-internal network — enforced shape, see the T2 gate tests.
            assert spec.get("internal") is not True
            continue
        assert spec.get("internal") is True, f"{net} is not internal"


# ── the canary must be the same script everywhere, and must be real ───────

def test_compose_canary_matches_the_python_constant():
    """Single source of truth: no drift between the compose file and the tests."""
    doc = yaml.safe_load(REAL_COMPOSE.read_text())
    embedded = doc["services"]["sb-busybox"]["command"][2]
    assert compose.normalize_canary(embedded) == compose.normalize_canary(compose.CANARY_SCRIPT)


def test_canary_script_contains_no_shell_variables():
    """Regression guard for a real bug.

    Compose interpolates `$name` inside the command string. A `$fail` flag was
    silently replaced with an empty string, so the canary compared `"" = "1"`
    and passed unconditionally. Keeping the script variable-free stops that
    from ever coming back.
    """
    assert "$" not in compose.CANARY_SCRIPT


def test_canary_script_checks_both_routing_and_dns():
    script = compose.CANARY_SCRIPT
    assert "wget" in script and "1.1.1.1" in script
    assert "nslookup" in script
    assert "EGRESS_PROBE_FAILED" in script and "exit 1" in script
    assert "EGRESS_DENY_OK" in script


# ── G1 privileged / capabilities ───────────────────────────────────────────

def test_g1_privileged_container_refused(tmp_path, doc):
    doc["services"]["sb-app"]["privileged"] = True
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G1 privileged/cap_add"
    assert "privileged" in f.message


def test_g1_cap_add_refused(tmp_path, doc):
    doc["services"]["sb-app"]["cap_add"] = ["NET_ADMIN"]
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G1 privileged/cap_add"


# ── G2 docker socket ───────────────────────────────────────────────────────

def test_g2_docker_socket_refused(tmp_path, doc):
    doc["services"]["sb-app"]["volumes"].append("/var/run/docker.sock:/var/run/docker.sock")
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G2 docker socket"


# ── G3 host filesystem ─────────────────────────────────────────────────────

@pytest.mark.parametrize("mount", [
    "/etc:/etc",
    "~/.ssh:/root/.ssh:ro",
    "./secrets:/app/secrets",
    "/home/operator/ww-src:/repo",
])
def test_g3_host_bind_mounts_refused(tmp_path, doc, mount):
    doc["services"]["sb-app"]["volumes"].append(mount)
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G3 host bind mounts"


def test_g3_named_volume_is_allowed(tmp_path, doc):
    doc["services"]["sb-app"]["volumes"].append("ww_sb_extra:/extra")
    doc["volumes"]["ww_sb_extra"] = None
    # No refusal: a named volume is the supported storage form.
    assert gates_static.inspect_compose(
        _write_tmp(tmp_path, doc))["gate_count"] == 11


def _write_tmp(tmp_path: Path, doc: dict) -> Path:
    path = tmp_path / "compose.sandbox.yml"
    path.write_text(yaml.safe_dump(doc))
    return path


# ── G4 non-root ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("user", ["0:0", "root", "999:999", None])
def test_g4_non_root_enforced(tmp_path, doc, user):
    if user is None:
        doc["services"]["sb-app"].pop("user", None)
    else:
        doc["services"]["sb-app"]["user"] = user
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G4 non-root"


# ── G5 bounded resources ───────────────────────────────────────────────────

@pytest.mark.parametrize("key", ["mem_limit", "cpus", "pids_limit"])
def test_g5_missing_limit_refused(tmp_path, doc, key):
    doc["services"]["sb-app"].pop(key)
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G5 bounded resources"


def test_g5_missing_log_rotation_refused(tmp_path, doc):
    doc["services"]["sb-app"]["logging"] = {"driver": "json-file"}
    f = _refuse(tmp_path, doc)
    assert "log rotation" in f.message


def test_g5_oversized_tmpfs_refused(tmp_path, doc):
    doc["services"]["sb-app"]["tmpfs"] = ["/tmp:size=2G"]
    f = _refuse(tmp_path, doc)
    assert "256 MB cap" in f.message


def test_g5_unsized_tmpfs_refused(tmp_path, doc):
    doc["services"]["sb-app"]["tmpfs"] = ["/tmp"]
    f = _refuse(tmp_path, doc)
    assert "no explicit size cap" in f.message


# ── G6 port binding ────────────────────────────────────────────────────────

@pytest.mark.parametrize("port", ["0.0.0.0:8000:8000", "8000:8000", ":::8000:8000"])
def test_g6_non_loopback_publish_refused(tmp_path, doc, port):
    doc["services"]["sb-app"]["ports"] = [port]
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G6 restricted binding"


def test_g6_loopback_publish_is_allowed(tmp_path, doc):
    doc["services"]["sb-app"]["ports"] = ["127.0.0.1:8100:8000"]
    assert gates_static.inspect_compose(_write_tmp(tmp_path, doc))["gate_count"] == 11


def test_g6_host_network_refused(tmp_path, doc):
    doc["services"]["sb-app"]["network_mode"] = "host"
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G6 restricted binding"


# ── G7 internal networks ───────────────────────────────────────────────────

def test_g7_non_internal_network_refused(tmp_path, doc):
    doc["networks"]["ww-app-net"]["internal"] = False
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G7 internal networks"


def test_g7_missing_internal_key_refused(tmp_path, doc):
    doc["networks"]["ww-telemetry-net"].pop("internal")
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "G7 internal networks"


# ── restart / read-only ────────────────────────────────────────────────────

def test_restart_policy_must_be_no(tmp_path, doc):
    doc["services"]["sb-redis"]["restart"] = "unless-stopped"
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "restart/read-only"


def test_read_only_rootfs_required(tmp_path, doc):
    doc["services"]["sb-redis"].pop("read_only")
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "restart/read-only"


# ── H10 image pinning ──────────────────────────────────────────────────────

@pytest.mark.parametrize("image", ["redis:7-alpine", "redis:latest", "busybox"])
def test_h10_unpinned_image_refused(tmp_path, doc, image):
    doc["services"]["sb-redis"]["image"] = image
    f = _refuse(tmp_path, doc)
    assert _gate_of(f) == "H10 image pinning"


def test_h10_locally_built_tags_are_allowed(tmp_path, doc):
    doc["services"]["sb-app"]["image"] = images.APP_IMAGE
    doc["services"]["sb-seed"]["image"] = images.SEED_IMAGE
    assert gates_static.inspect_compose(_write_tmp(tmp_path, doc))["gate_count"] == 11


# ── G9 secrets ─────────────────────────────────────────────────────────────

def test_g9_env_file_refused(tmp_path, doc):
    doc["services"]["sb-app"]["env_file"] = ".env"
    f = _refuse(tmp_path, doc)
    assert f.code == "E204"
    assert "env_file is banned" in f.message


@pytest.mark.parametrize("secret", [
    "AKIAIOSFODNN7EXAMPLE",
    "sk-abcdefghijklmnopqrstuvwxyz012345",
    "xoxb-1234567890-abcdefghijkl",
    'DATABASE_URL: "postgresql://user:hunter2@db:5432/x"',
    "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
    "123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",
])
def test_g9_secret_shapes_refused(tmp_path, doc, secret):
    f = _refuse(tmp_path, doc, raw=REAL_COMPOSE.read_text() + f"\n# {secret}\n")
    assert f.code == "E204"


def test_g9_credential_env_vars_must_be_absent(tmp_path, doc):
    """A real bug: empty is not absent.

    Pinning every provider key to "" looked tidy but made libraries treat them
    as configured — boto3 raised `Invalid endpoint` for an empty R2_ENDPOINT_URL
    at import and the app exited 3.
    """
    doc["services"]["sb-app"]["environment"]["R2_ENDPOINT_URL"] = ""
    f = _refuse(tmp_path, doc)
    assert f.code == "E204"
    assert "must be absent" in f.message


def test_g9_no_provider_keys_in_the_shipped_compose():
    doc = yaml.safe_load(REAL_COMPOSE.read_text())
    env = doc["services"]["sb-app"]["environment"] or {}
    for key in env:
        if key == "SECRET_KEY":
            continue
        assert not gates_static._CREDENTIAL_KEY.search(key), (
            f"{key} should not be listed in the sandbox environment"
        )


def test_g9_placeholder_secret_key_is_allowed():
    """The shipped file carries a placeholder SECRET_KEY on purpose."""
    text = REAL_COMPOSE.read_text()
    assert "SECRET_KEY" in text
    assert "PLACEHOLDER" in text
    assert gates_static.inspect_compose(REAL_COMPOSE)["gate_count"] == 11


# ── fail-closed on malformed input ─────────────────────────────────────────

def test_missing_compose_file_refused(tmp_path):
    with pytest.raises(GateFailure) as ei:
        gates_static.inspect_compose(tmp_path / "nope.yml")
    assert "not found" in ei.value.message


def test_unparseable_compose_refused(tmp_path):
    path = tmp_path / "compose.sandbox.yml"
    path.write_text("services:\n  - this is not\n   a mapping: [\n")
    with pytest.raises(GateFailure) as ei:
        gates_static.inspect_compose(path)
    assert ei.value.code == "E205"


def test_compose_without_services_refused(tmp_path):
    path = tmp_path / "compose.sandbox.yml"
    path.write_text("version: '3'\n")
    with pytest.raises(GateFailure):
        gates_static.inspect_compose(path)


# ── build-context allowlist ────────────────────────────────────────────────

def test_build_context_allowlist_excludes_sensitive_paths():
    resolved = images.allowed_paths(REPO_ROOT)
    assert "requirements.txt" in resolved
    # The OSS slice ships one package under src/; templates live inside it, so
    # there is no separate top-level templates/ or static/ tree to carry.
    assert "src" in resolved
    assert "sandbox_kit" in resolved
    assert "detonate_sandbox" in resolved
    assert resolved == sorted(resolved)
    for forbidden in (".env", "venv", ".git", "node_modules", "tests", "docs"):
        assert not any(p == forbidden or p.startswith(forbidden + "/") for p in resolved), \
            f"{forbidden} must never be in a sandbox build context"


def test_build_context_allowlist_has_no_duplicates():
    resolved = images.allowed_paths(REPO_ROOT)
    assert len(resolved) == len(set(resolved))


@pytest.mark.parametrize("pkg", ["src", "sandbox_kit", "detonate_sandbox"])
def test_build_context_includes_every_sandbox_build_input(pkg):
    """Regression guard.

    Each of these is read by one of the four sandbox Dockerfiles. Leaving one
    out of the context produces a build failure, or — for `src` — an image whose
    gunicorn exits 3 the moment it loads the app.
    """
    assert pkg in images.allowed_paths(REPO_ROOT), (
        f"{pkg} is a sandbox build input but is not in the build context"
    )
    pkg_dir = REPO_ROOT / pkg
    assert pkg_dir.is_dir(), f"{pkg} should be a directory"
    assert any(pkg_dir.rglob("*.py")), f"{pkg} contains no python"


def test_dockerfile_copies_the_whole_context():
    """The Dockerfile must not re-enumerate the allowlist (drift risk)."""
    text = (REPO_ROOT / images.DOCKERFILES[images.APP_IMAGE]).read_text()
    assert "COPY . ." in text
    assert "COPY requirements.txt ./" in text
    # No explicit per-package COPY lines, which is how the drift happened.
    for pkg in ("src", "sandbox_kit", "detonate_sandbox"):
        assert f"COPY {pkg} " not in text, f"{pkg} is COPYed explicitly — use the context"


def test_app_image_serves_the_oss_package():
    """The sandbox image must run the published package, not a monolith entry."""
    text = (REPO_ROOT / images.DOCKERFILES[images.APP_IMAGE]).read_text()
    assert 'CMD ["gunicorn", "wraithwall:create_app()"' in text
    assert "main:app" not in text
    assert "PYTHONPATH=/app/src" in text


# ── G13: both install layouts produce the same build context ────────────────

@pytest.fixture()
def installed_layout(tmp_path, monkeypatch):
    """Simulate a pip install: packages importable side by side, assets in
    `share/wraithwall/`, and no `src/` directory anywhere."""
    shared = tmp_path / "share" / "wraithwall"
    shared.mkdir(parents=True)
    (shared / "requirements.txt").write_text("# fixture\n")
    (shared / "compose.sandbox.yml").write_text("# fixture\n")
    (shared / "detonate_sandbox").symlink_to(REPO_ROOT / "detonate_sandbox",
                                             target_is_directory=True)
    sp = tmp_path / "site-packages"
    sp.mkdir()
    (sp / "wraithwall").symlink_to(REPO_ROOT / "src" / "wraithwall",
                                   target_is_directory=True)
    (sp / "sandbox_kit").symlink_to(REPO_ROOT / "sandbox_kit",
                                   target_is_directory=True)
    monkeypatch.setattr(assets, "IS_CHECKOUT", False)
    monkeypatch.setattr(assets, "ASSET_ROOT", shared)
    monkeypatch.setattr(assets, "site_packages", lambda: sp)
    return shared


def _tree(root: Path) -> list:
    return sorted(
        str(p.relative_to(root))
        for p in root.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
        and not p.name.endswith(".pyc")
    )


def test_checkout_layout_stages_every_dockerfile_input(tmp_path):
    """Repo checkout: the allowlist alone is the whole context."""
    dest = compose.prepare_build_context(tmp_path / "ctx")
    for pkg in ("src", "sandbox_kit", "detonate_sandbox"):
        assert (dest / pkg).is_dir(), pkg
        assert not any((dest / pkg).rglob("__pycache__")), "caches must not ship"
    assert (dest / "requirements.txt").is_file()


def test_installed_layout_stages_the_same_tree(tmp_path, installed_layout):
    """A pip install has no `src/` directory — the launcher must synthesize it."""
    dest = compose.prepare_build_context(tmp_path / "ctx")
    for pkg in ("src", "sandbox_kit", "detonate_sandbox"):
        assert (dest / pkg).is_dir(), pkg
    assert (dest / "src" / "wraithwall" / "__init__.py").is_file()
    assert (dest / "sandbox_kit" / "cli.py").is_file()
    assert (dest / "detonate_sandbox" / "detonate.py").is_file()
    assert (dest / "requirements.txt").is_file()


def test_installed_layout_and_checkout_layout_agree(tmp_path, installed_layout):
    """The decisive one: both layouts stage an identical tree, so a pip install
    boots the same image a checkout does."""
    checkout = compose.prepare_build_context(tmp_path / "checkout")
    installed = compose.prepare_build_context(tmp_path / "installed")
    a, b = _tree(checkout), _tree(installed)
    assert a == b, sorted(set(a).symmetric_difference(b))


def test_asset_root_prefers_the_checkout(monkeypatch, tmp_path):
    """With both layouts present, the checkout wins — assets are editable."""
    monkeypatch.setattr(assets, "IS_CHECKOUT", True, raising=False)
    assert assets.asset_root() == REPO_ROOT
    assert assets.IS_CHECKOUT is True


def test_requirements_txt_mirrors_the_distribution_dependencies():
    """The sandbox image installs requirements.txt; a pip install resolves
    pyproject's list. If they diverge, the image and the wheel disagree about
    what the platform needs — and the divergence only shows up as an ImportError
    inside a container."""
    import tomllib

    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())
    declared = {
        dep.lower().replace(" ", "")
        for dep in data["project"]["dependencies"]
    }
    mirrored = {
        line.strip().lower().replace(" ", "")
        for line in (REPO_ROOT / "requirements.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }
    assert declared == mirrored, (
        f"only in pyproject: {sorted(declared - mirrored)}; "
        f"only in requirements.txt: {sorted(mirrored - declared)}"
    )


def test_every_registered_blueprint_import_is_satisfied():
    """create_app() registers blueprints at boot; a missing dependency there is
    a crash, not a degradation. Import each one directly so CI sees it."""
    import importlib

    for module in ("link_checker", "public_api", "gateway", "incident_response",
                   "architecture_viz", "live_events", "campaign_correlator",
                   "asn_intelligence", "bgp_monitor", "cowrie_intelligence",
                   "cowrie_ship", "canary_service", "fingerprint_corpus",
                   "sandbox", "dml_engine", "deception_event_bus"):
        importlib.import_module(f"wraithwall.{module}")


# ── G9 dynamic helper ──────────────────────────────────────────────────────

def test_env_allowlist_flags_unknown_credentials():
    findings = gates_static.verify_env_allowlist(
        {"PATH", "PYTHON_VERSION", "WRAITHWALL_SANDBOX", "SECRET_KEY", "SUPER_SECRET_TOKEN"}
    )
    assert any("SUPER_SECRET_TOKEN" in f for f in findings)
    assert not any("SECRET_KEY" in f for f in findings)  # explicitly allowlisted


def test_env_allowlist_accepts_image_level_env():
    findings = gates_static.verify_env_allowlist(
        {"PATH", "LANG", "HOME", "HOSTNAME", "GPG_KEY", "PYTHON_VERSION",
         "PYTHON_SHA256", "PIP_NO_CACHE_DIR", "WRAITHWALL_SANDBOX",
         "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE"}
    )
    assert findings == []
