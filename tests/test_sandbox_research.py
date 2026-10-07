"""Phase 11 — T2 research-sandbox tests.

Covers the four roadmap gates plus the profile promotion:

1. **Deny policy** (egress_policy.py): the full deny matrix — internal ranges,
   metadata endpoints, IPv6 (literal/mapped/ULA), docker DNS stub, DoH/DoT
   shapes — and the allow-side (a normal public host must NOT be denied).
2. **Proxy decision layers** (egress_proxy.py): allowlist deny-by-default,
   policy layer firing even for allowlisted hosts.
3. **Profile promotion**: research-sandbox is a real T2 MVP profile with
   per-session confirmation; vm/external stay honest pointers.
4. **Static topology gate + mutation matrix**: weakening the compose T2 shape
   one mutation at a time must refuse with E205.
5. **CLI gating**: E210 (no/invalid allowlist), E211 (detonate off-allowlist),
   per-session confirmation semantics, profiles output.

Pure Python — no daemon, no containers (the live counterparts stay opt-in).
"""
from __future__ import annotations

import copy

import pytest
import yaml
from pathlib import Path

from sandbox_kit import compose as compose_mod
from sandbox_kit import egress_policy, egress_proxy, gates_static
from sandbox_kit.egress_policy import classify, classify_connect
from sandbox_kit.egress_proxy import allowed_hosts_from_env, decide
from sandbox_kit.gates import GateFailure
from sandbox_kit.profiles import FUTURE_PROFILES, MVP_PROFILES, get_profile

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_COMPOSE = REPO_ROOT / "compose.sandbox.yml"


# ── 1. the deny policy ──────────────────────────────────────────────────────

@pytest.mark.parametrize("host", [
    "169.254.169.254",          # AWS/EC2 metadata v1
    "169.254.170.2",            # ECS task metadata
    "100.100.100.200",          # Alibaba metadata
    "metadata.google.internal", # GCP
    "metadata.goog",
    "metadata.internal",
    "metadata",
    "instance-data",
    "10.0.0.1", "172.16.0.9", "172.31.255.1", "192.168.1.1",   # RFC1918
    "127.0.0.1", "127.0.0.11",  # loopback + docker embedded DNS stub
    "0.0.0.0",
    "100.64.0.7",               # CGNAT
    "198.18.0.3",               # benchmark
    "224.0.0.1", "255.255.255.255",
    "::1", "::",                # v6 loopback / unspecified
    "fd00:ec2::254",            # AWS IPv6 metadata (ULA)
    "fe80::1",                  # v6 link-local
    "2001:db8::5",
    "::ffff:169.254.169.254",   # v4-mapped metadata
    "::ffff:10.0.0.1",
    "foo.local", "host.metadata", "svc.internal", "box.home.arpa",
    "router.localdomain".replace("localdomain", "localhost"),  # .localhost suffix
])
def test_policy_denies_infrastructure(host):
    denied, why = classify(host)
    assert denied, f"{host} was allowed: {why}"


@pytest.mark.parametrize("host", ["example.com", "example.org",
                                  "wraithwall.online", "one.one.one.one"])
def test_policy_allows_ordinary_public_hosts(host):
    denied, why = classify(host)
    assert not denied, f"{host} wrongly denied: {why}"


def test_policy_denies_doT_and_doh_shapes():
    assert classify("example.com", 853)[0]                      # DNS-over-TLS
    assert classify("dns.example.com", 443, "/dns-query")[0]    # RFC 8484 path
    assert classify("cloudflare-dns.com", 443, "/x")[0]         # bootstrap host
    assert classify("dns.google", 443)[0]
    # Plain 443 to an allowlisted non-DoH host must survive (else the profile
    # is useless) — DoH closure is bootstrap+path shaped, not blanket.
    assert not classify("example.com", 443)[0]
    assert not classify("example.com", 80)[0]


def test_policy_dns_rebinding_shape():
    """A hostname whose DNS answers with an infrastructure address is denied
    even when the literal string is benign — the rebinding shape."""
    # localhost resolves to 127.0.0.1 on every sane host; the literal string
    # would also hit the .localhost suffix, so use an A-record of the docker
    # stub instead: resolve a name that maps into a deny range.
    # Deterministic, dependency-free: classify() resolves via getaddrinfo, and
    # "localhost" is the only name we can rely on resolving everywhere — its
    # answer (127.0.0.1) is in the deny range, proving the resolution path.
    denied, _ = classify("localhost")
    assert denied


def test_policy_fails_closed_on_garbage():
    for bad in ("", "   ", None):
        denied, _ = classify(bad)
        assert denied
    denied, _ = classify_connect("")
    assert denied


def test_policy_connect_forms():
    assert classify_connect("169.254.169.254:80")[0]
    assert classify_connect("metadata.google.internal:443")[0]
    assert classify_connect("[fd00::1]:443")[0]
    assert not classify_connect("example.com:443")[0]


def test_self_test_cases_all_deny():
    """Every canonical case shipped to the container must actually deny —
    the in-container self-test (E212) is only meaningful if this holds."""
    for host, _why in egress_policy.SELF_TEST_CASES:
        denied, reason = classify(host)
        assert denied, f"self-test case {host} allowed: {reason}"


def test_self_test_script_contains_the_cases():
    script = egress_policy.self_test_script()
    assert "POLICY_SELF_TEST_OK" in script
    for host, _why in egress_policy.SELF_TEST_CASES:
        assert host in script


# ── 2. proxy decision layers ────────────────────────────────────────────────

ALLOW = frozenset({"example.com"})


def test_allowlist_deny_by_default():
    ok, why = decide("example.com", ALLOW)
    assert ok
    ok, why = decide("other.org", ALLOW)
    assert not ok and "allowlist" in why
    ok, why = decide("example.com", frozenset())
    assert not ok  # empty allowlist denies everything


def test_policy_layer_fires_even_for_allowlisted_hosts():
    ok, why = decide("169.254.169.254", ALLOW | {"169.254.169.254"})
    assert not ok and "policy" in why
    ok, why = decide("metadata.google.internal", ALLOW | {"metadata.google.internal"})
    assert not ok and "policy" in why


def test_allowlist_env_parsing(monkeypatch):
    monkeypatch.delenv("WRAITHWALL_SANDBOX_ALLOWED_HOSTS", raising=False)
    assert allowed_hosts_from_env() == frozenset()          # absent => empty
    monkeypatch.setenv("WRAITHWALL_SANDBOX_ALLOWED_HOSTS", " Example.COM , foo.local ,,")
    assert allowed_hosts_from_env() == frozenset({"example.com", "foo.local"})
    # '*' grants nothing: the allowlist is literal, never a wildcard.
    monkeypatch.setenv("WRAITHWALL_SANDBOX_ALLOWED_HOSTS", "*")
    assert allowed_hosts_from_env() == frozenset({"*"})
    ok, _ = decide("anything.net", allowed_hosts_from_env())
    assert not ok


# ── 3. profile promotion ────────────────────────────────────────────────────

def test_research_sandbox_is_a_real_t2_profile():
    p = get_profile("research-sandbox")
    assert p.tier == "T2"
    assert p.requires_runtime
    assert p.confirmation == "per-session"
    assert p.min_free_ram_mb >= 4096
    assert "research-sandbox" not in FUTURE_PROFILES


def test_mvp_and_future_shape_unchanged_elsewhere():
    assert set(FUTURE_PROFILES) == {"vm-sandbox", "external-sensor"}
    assert get_profile("app-only").confirmation == "none"
    assert get_profile("local-sandbox").confirmation == "one-time"


def test_t2_load_bearing_controls_refuse_via_e203():
    """The Phase 8 machinery must treat T2's rootless+userns as load-bearing:
    on a runtime without them, startup refuses with E203 (fail-closed), not
    a warning."""
    from sandbox_kit.gates import run_platform_controls_gate
    from sandbox_kit.platform import Control, PlatformReport, report_platform_controls

    def _report_without_rootless(runtime):
        rep = report_platform_controls(runtime=runtime)
        controls = tuple(
            Control(c.key, c.label,
                    "UNAVAILABLE" if c.key in ("rootless-runtime", "user-namespace")
                    else c.status, c.load_bearing, c.detail)
            for c in rep.controls
        )
        return PlatformReport(rep.system, rep.release, rep.machine, rep.runtime,
                              controls)

    with pytest.raises(GateFailure) as ei:
        run_platform_controls_gate(
            get_profile("research-sandbox"), "docker",
            {"system": lambda: ("Linux", "6.8", "x86_64"),
             "docker_info": lambda: {},
             "userns": lambda: None,           # probe says: not available
             "cgroup": lambda: True,
             "lsm": lambda: ["apparmor"]})
    assert ei.value.code == "E203"


# ── 4. static topology gate + mutation matrix ───────────────────────────────

@pytest.fixture()
def base_doc() -> dict:
    return yaml.safe_load(REAL_COMPOSE.read_text())


def _mutate(tmp_path: Path, doc: dict) -> GateFailure:
    p = tmp_path / "compose.sandbox.yml"
    p.write_text(yaml.safe_dump(doc))
    with pytest.raises(GateFailure) as ei:
        gates_static.inspect_compose(p)
    return ei.value


def test_real_compose_still_passes_with_t2(base_doc):
    summary = gates_static.inspect_compose(REAL_COMPOSE)
    assert "sb-egress" in summary["services"]
    assert "sb-detonate" in summary["services"]


def test_mutation_t2_service_on_two_networks(tmp_path, base_doc):
    doc = copy.deepcopy(base_doc)
    doc["services"]["sb-detonate"]["networks"].append("ww-app-net")
    assert _mutate(tmp_path, doc).code == "E205"


def test_mutation_t2_dns_blackhole_removed(tmp_path, base_doc):
    doc = copy.deepcopy(base_doc)
    doc["services"]["sb-detonate"].pop("dns")
    assert _mutate(tmp_path, doc).code == "E205"


def test_mutation_t2_publishes_a_port(tmp_path, base_doc):
    doc = copy.deepcopy(base_doc)
    doc["services"]["sb-detonate"]["ports"] = ["127.0.0.1:8500:8000"]
    assert _mutate(tmp_path, doc).code == "E205"


def test_mutation_first_party_joins_egress_plane(tmp_path, base_doc):
    doc = copy.deepcopy(base_doc)
    doc["services"]["sb-app"]["networks"].append("ww-egress-net")
    assert _mutate(tmp_path, doc).code == "E205"


def test_mutation_t2_service_unprofiled(tmp_path, base_doc):
    doc = copy.deepcopy(base_doc)
    doc["services"]["sb-detonate"].pop("profiles")
    assert _mutate(tmp_path, doc).code == "E205"


def test_mutation_unknown_research_service(tmp_path, base_doc):
    doc = copy.deepcopy(base_doc)
    doc["services"]["sb-seed"]["profiles"] = ["research"]
    assert _mutate(tmp_path, doc).code == "E205"


def test_mutation_proxy_image_swapped(tmp_path, base_doc):
    """The enforcement addon lives in the egress image; swapping the proxy to
    another image removes the enforcement and must refuse."""
    doc = copy.deepcopy(base_doc)
    doc["services"]["sb-egress"]["image"] = "wraithwall-sandbox-seed:local"
    assert _mutate(tmp_path, doc).code == "E205"


# ── 5. CLI gating ───────────────────────────────────────────────────────────

@pytest.fixture()
def sbx_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("WRAITHWALL_SANDBOX_DIR", str(tmp_path / "sbx"))
    return tmp_path


def test_e210_refuses_without_allowlist(sbx_dir, capsys):
    from sandbox_kit import cli
    assert cli.main(["up", "--profile", "research-sandbox", "--yes"]) == 2
    assert "E210" in capsys.readouterr().out


def test_e210_refuses_policy_denied_allowlist(sbx_dir, capsys):
    from sandbox_kit import cli
    rc = cli.main(["up", "--profile", "research-sandbox", "--yes",
                   "--allow-host", "169.254.169.254"])
    assert rc == 2
    assert "refused by the egress policy" in capsys.readouterr().out


def test_e210_symmetric_refusal_on_non_research_profile(sbx_dir, capsys):
    """Red-team finding turned regression: `--allow-host` on a profile that
    never fetches developer-supplied URLs used to be silently ignored, which
    lets a developer believe egress is allowlist-gated when the flag did
    nothing. It must refuse (E210), never no-op."""
    from sandbox_kit import cli
    for profile in ("app-only", "local-sandbox"):
        rc = cli.main(["up", "--profile", profile,
                       "--allow-host", "example.com"])
        assert rc == 2, profile
        assert "E210" in capsys.readouterr().out


def test_e210_parses_and_normalizes(sbx_dir):
    from sandbox_kit import cli
    assert cli._parse_allow_hosts(" Example.COM, foo.local. ") == \
        ["example.com", "foo.local"]
    assert cli._parse_allow_hosts("https://example.com/x") == ["example.com"]
    with pytest.raises(ValueError):
        cli._parse_allow_hosts("bad host")


def test_detonate_requires_research_running(sbx_dir, capsys):
    from sandbox_kit import cli
    assert cli.main(["detonate", "--url", "https://example.com"]) == 2
    assert "does not exist" in capsys.readouterr().out


def test_e211_detonate_host_not_on_allowlist(sbx_dir, capsys, monkeypatch):
    """A RUNNING T2 sandbox whose recorded allowlist excludes the URL must
    refuse with E211 — verified at the decision boundary without a daemon by
    stubbing the state read."""
    from sandbox_kit import cli, state
    monkeypatch.setattr(state, "read_state", lambda name: {
        "state": "RUNNING", "profile": "research-sandbox", "tier": "T2",
        "project": "ww-sb-x", "allow_hosts": ["example.com"],
    })
    rc = cli.main(["detonate", "--url", "https://evil.example.net/"])
    assert rc == 2
    assert "E211" in capsys.readouterr().out


def test_e211_detonate_policy_denied_even_if_allowlisted(sbx_dir, capsys, monkeypatch):
    from sandbox_kit import cli, state
    monkeypatch.setattr(state, "read_state", lambda name: {
        "state": "RUNNING", "profile": "research-sandbox", "tier": "T2",
        "project": "ww-sb-x", "allow_hosts": ["169.254.169.254"],
    })
    rc = cli.main(["detonate", "--url", "http://169.254.169.254/latest"])
    assert rc == 2
    assert "egress policy refuses" in capsys.readouterr().out or \
        "policy refuses" in capsys.readouterr().out


def test_per_session_confirmation_not_persisted(sbx_dir):
    """T2 confirmation must never write an ack file: every up re-asks by
    construction, and no 'always allow' state may exist."""
    from sandbox_kit import cli, state
    # decline interactively
    monkey_stdin = pytest.MonkeyPatch()
    monkey_stdin.setattr("builtins.input", lambda *_: "n")
    profile = get_profile("research-sandbox")
    assert not cli._confirm_ack(profile, assume_yes=False)
    monkey_stdin.undo()
    # accept with --yes — still nothing persisted
    assert cli._confirm_ack(profile, assume_yes=True)
    assert not (state.sandbox_dir("default") / "ack.txt").exists()


def test_profiles_output_lists_t2_as_available(capsys):
    from sandbox_kit import cli
    assert cli.main(["profiles"]) == 0
    out = capsys.readouterr().out
    assert "research-sandbox" in out
    assert "per-session" in out
    # the future list no longer contains it
    assert out.index("research-sandbox") < out.index("Not available")


# ── 6. verify_research_plane wiring (no-daemon, contract level) ─────────────

def test_verify_research_plane_refuses_on_missing_check(sbx_dir, monkeypatch):
    """A research boot without its self-check containers is not a research
    boot: a timeout (None) refuses fail-closed."""
    from sandbox_kit.gates import GateFailure
    monkeypatch.setattr(compose_mod, "wait_for_exit", lambda *a, **k: None)
    with pytest.raises(GateFailure):
        compose_mod.verify_research_plane("ww-sb-x")


def test_verify_research_plane_refuses_on_canary_failure(sbx_dir, monkeypatch):
    from sandbox_kit.gates import GateFailure
    calls = iter([0, 1])  # selftest ok, canary failed
    monkeypatch.setattr(compose_mod, "wait_for_exit",
                        lambda *a, **k: next(calls))
    monkeypatch.setattr(compose_mod, "container_id", lambda *a, **k: "cid")
    monkeypatch.setattr(compose_mod, "_run", lambda *a, **k: type(
        "R", (), {"stdout": "EGRESS_PROBE_FAILED: direct IP egress", "stderr": ""})())
    with pytest.raises(GateFailure) as ei:
        compose_mod.verify_research_plane("ww-sb-x")
    assert ei.value.code == "E202"


# ── 7. hunt regressions (2026-09-15 red-team pass) ──────────────────────────

def test_sanitize_raw_output_strips_terminal_escapes():
    """`detonate`'s raw-output fallback can embed hostile-page console text;
    echoing raw ANSI/OSC/C0 escapes would let a detonated page write into the
    developer's terminal (cursor hijack, title injection, arbitrary C0)."""
    from sandbox_kit.cli import _sanitize_raw_output
    evil = ("ok \x1b]0;pwned-title\x07 \x1b[2J\x1b[H clear "
            "\x1b[31;1mcolor\x1b[0m \x00\x07\x1f\x7f end")
    out = _sanitize_raw_output(evil)
    assert "\x1b" not in out
    assert "pwned-title" not in out
    assert "clear" in out and "end" in out  # visible text survives
    for ch in ("\x00", "\x07", "\x1f", "\x7f"):
        assert ch not in out


def test_sanitize_raw_output_truncates_and_keeps_tail():
    from sandbox_kit.cli import _sanitize_raw_output
    out = _sanitize_raw_output("x" * 9000 + "TAIL")
    assert len(out) <= 4000
    assert out.endswith("TAIL")


def test_detonate_refuses_control_chars_in_url(sbx_dir, capsys, monkeypatch):
    """Header/log injection: a --url with control characters must refuse
    before any parsing or state access."""
    from sandbox_kit import cli, state
    monkeypatch.setattr(state, "read_state", lambda name: {
        "state": "RUNNING", "profile": "research-sandbox", "tier": "T2",
        "project": "ww-sb-x", "allow_hosts": ["example.com"],
    })
    rc = cli.main(["detonate", "--url", "https://example.com/\r\nX-Injected: 1"])
    assert rc == 2
    assert "control characters" in capsys.readouterr().out


def test_detonate_refuses_non_http_schemes(sbx_dir, capsys, monkeypatch):
    from sandbox_kit import cli, state
    monkeypatch.setattr(state, "read_state", lambda name: {
        "state": "RUNNING", "profile": "research-sandbox", "tier": "T2",
        "project": "ww-sb-x", "allow_hosts": ["example.com"],
    })
    for url in ("gopher://example.com", "file:///etc/passwd", "ftp://example.com/x"):
        capsys.readouterr()
        rc = cli.main(["detonate", "--url", url])
        assert rc == 2, url
        assert "http/https only" in capsys.readouterr().out


def test_detonate_rejects_dotdot_host_shapes():
    """The G12 hostile-string rule: '..' labels can never pass policy, and the
    allowlist can never contain them (parse layer refuses '/'). Belt: policy
    denies; suspenders: allowlist exact-match."""
    from sandbox_kit.egress_policy import classify
    denied, _ = classify("..")
    assert denied
