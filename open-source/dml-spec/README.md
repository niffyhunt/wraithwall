# Deception Markup Language (DML)

**DML** is a small, versioned, HMAC-signable schema for declaring deception
assets — honeypots, canaries, and tripwires — as portable documents. Instead
of scattering trap logic across your codebase, you describe traps once, in one
file, and ship that file between systems with confidence that it has not been
tampered with in transit or at rest.

A **DML document** is a versioned set of **traps**. Each trap pairs a
**trigger** (what an attacker has to do to set it off) with a **response**
(how the trap reacts), plus metadata (severity, MITRE ATT&CK tactic, tags) and
alerting intent.

## Why versioned + signed deception config matters

Deception only works if attackers can't distinguish traps from real assets —
and operators can't afford to deploy traps they can't trust. Two properties
make a deception config trustworthy:

- **Versioned.** A document declares the DML spec version it targets, so
  consumers can reject documents they don't understand instead of
  misinterpreting them. Trap IDs are namespaced and must be unique, so two
  teams can merge configs without silent collisions.
- **Signed.** Trap definitions are exactly the kind of high-value config an
  attacker who gains a foothold would love to quietly edit — disabling the
  tripwire that would catch them, or pointing a "block" response at log-only.
  DML signs every trap **and** the document as a whole with HMAC-SHA256, so
  any edit — to a field, a trap, or the set of traps — is detectable as long
  as the signing key stays secret.

## Trigger types

## DML 0.3.0 — WraithMesh sensors

v0.3.0 adds a **`sensors`** section for declaring WraithMesh nodes inside the
same signed document as your traps, plus an optional **`mesh_policy`** for
TIE corroboration rules.

```yaml
dml_version: "0.3.0"
mesh_policy:
  tie_min_corroboration: 2
  forbid_raw_commands: true
  forbid_src_ip: true
sensors:
  - id: cowrie-east-1
    name: Cowrie observer
    sensor_class: cowrie
    cowrie_log_path: /var/log/cowrie/cowrie.json
    aggregator_url: http://127.0.0.1:8787
```

Export a WraithMesh `mesh.json` from a signed document:

```bash
DML_KEY=... WRAITHMESH_KEY=... dml sign examples/example_mesh.yaml -o signed_mesh.yaml
DML_KEY=... WRAITHMESH_KEY=... dml export-mesh signed_mesh.yaml cowrie-east-1 -o mesh.json
```

New trigger types: `cowrie_session`, `canary_beacon`, `equivalence_match`.  
New response types: `mesh_uplink`, `corroborate_alert`.  
Sensor classes: `cowrie`, `canary`, `gateway`, `fingerprint`.

Documents declaring `dml_version: "0.2.0"` remain valid (traps-only).

## Trigger types

The trigger types — the kind of attacker activity that fires a trap:

| Trigger type     | Fires when…                                              | Key fields                       |
| ---------------- | -------------------------------------------------------- | -------------------------------- |
| `http_request`   | a request hits a planted path/method                     | `path` (required), `method`      |
| `dns_resolution` | a planted hostname is resolved                           | `hostname` (required)            |
| `api_key_use`    | a planted API key (by prefix) is used                    | `api_key_prefix`                 |
| `file_access`    | a canary file is opened                                  | `path`                           |
| `login_attempt`  | a login is attempted against a decoy credential          | `match_regex`                    |
| `data_access`    | a canary database record is read                         | `record_id`                      |
| `timing_probe`   | response-timing probing is detected                      | `timing_target_ms` (required)    |
| `canary_email`   | mail arrives at a canary address                         | `email` (required)               |
| `jwt_use`        | a planted/forged JWT is presented                        | `match_regex`                    |
| `cowrie_session` | a Cowrie session matches a known equivalence key         | `equivalence_key` (required)     |
| `canary_beacon`  | a supply-chain canary token fires                        | `package_name` (required)        |
| `equivalence_match` | any sensor sees a campaign equivalence key            | `equivalence_key` (required)     |

## Response types

The eight response types — how a trap reacts once triggered:

| Response type      | Effect                                                       | Key fields                       |
| ------------------ | ----------------------------------------------------------- | -------------------------------- |
| `fake_data`        | serve fabricated data to the attacker                       | `fake_data_template`, `http_status` |
| `redirect_sandbox` | divert the session into a sandbox/decoy environment         | `redirect_url`, `sandbox_reason` |
| `delay_response`   | tarpit — stall the response                                 | `delay_ms` (required)            |
| `mirror_engage`    | engage the attacker (e.g. LLM-driven mirroring)             | `llm_prompt_override`, `llm_model` |
| `block_ip`         | block the source                                            | —                                |
| `log_only`         | record the event, no visible reaction                       | —                                |
| `alert_only`       | fire an alert, no visible reaction                          | —                                |
| `honeypot_auth`    | accept the credential into a honeypot auth flow             | `http_status`                    |
| `mesh_uplink`      | emit a signed observation to the TIE aggregator               | `aggregator_url` (required)      |
| `corroborate_alert`| request corroboration / high-priority TIE alert             | `aggregator_url`                 |

Severity levels: `critical`, `high`, `medium`, `low`, `info`.
MITRE tactics: the standard ATT&CK enterprise tactic set (e.g.
`credential_access`, `discovery`, `exfiltration`).

## Install

```bash
pip install .               # from a checkout
# runtime dependency: PyYAML>=6
```

## Quickstart

```python
from dml import DMLValidator, DMLSigner, load, dumps

doc = load("examples/example_traps.yaml")

# 1. Validate against the spec.
errors = DMLValidator().validate_document(doc)
assert not errors, errors

# 2. Sign (the key is supplied by you, never hardcoded in the library).
signer = DMLSigner.from_env("DML_KEY")     # or DMLSigner("my-secret")
signed = signer.sign_document(doc)

# 3. Verify — detects any tampering with traps or the document.
ok, errors = signer.verify_document(signed)
assert ok

print(dumps(signed, fmt="yaml"))
```

Build a document from your own records (no ORM/framework coupling):

```python
from dml import DMLTrap, DMLTrigger, build_document

traps = [
    DMLTrap(id="secret-path", name="Hidden endpoint",
            trigger=DMLTrigger(type="http_request", path="/internal/.env")),
]
doc = build_document(traps, platform="my-app", namespace="prod")
```

Run the full round-trip example:

```bash
DML_KEY=test-key-123 python examples/quickstart.py
```

## CLI

The signing key is read from an environment variable (default `DML_KEY`) — it
is **never** passed as a command-line literal, so it can't leak into shell
history or process listings.

```bash
python -m dml validate examples/example_traps.yaml
python -m dml sign     examples/example_traps.yaml --key-env DML_KEY -o signed.yaml
python -m dml verify   signed.yaml --key-env DML_KEY
python -m dml schema
```

Example output:

```text
$ python -m dml validate examples/example_traps.yaml
OK: valid DML document (5 traps)

$ DML_KEY=test-key-123 python -m dml sign examples/example_traps.yaml --key-env DML_KEY -o signed.yaml
OK: signed document written to signed.yaml

$ DML_KEY=test-key-123 python -m dml verify signed.yaml --key-env DML_KEY
OK: document signature valid

$ DML_KEY=wrong python -m dml verify signed.yaml --key-env DML_KEY
FAILED: verification failed:
   - Document signature mismatch — document may be tampered
```

## The signing model

DML signs at **two levels** with **HMAC-SHA256**:

- **Per-trap.** Each trap carries a `signature` field — an HMAC over the
  trap's contents with the `signature` field itself excluded. This lets a
  consumer attribute tampering to a specific trap.
- **Whole-document.** The document carries a `document_signature` — an HMAC
  over the document identity fields (`dml_version`, `platform`, `namespace`)
  plus every trap with its per-trap signature stripped. This binds the set of
  traps together: adding, removing, or editing any trap (even with a forged
  per-trap signature) invalidates the document signature.

**Canonicalization.** Before signing, the relevant object is serialized
deterministically as compact JSON with sorted keys:

```python
canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"))
signature = hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()[:32]
```

Verification recomputes the canonical form and compares signatures in
constant time.

**Key handling.** The HMAC key is supplied by the **caller** — via the
`DMLSigner(key)` constructor or `DMLSigner.from_env("DML_KEY")`. The library
contains no default, fallback, or hardcoded key; a missing key raises rather
than signing with a guessable value. Keep the key secret: anyone who has it
can forge valid signatures.

## Limitations

- **HMAC-SHA256, not asymmetric.** Signatures use HMAC-SHA256 (symmetric key),
  not public-key cryptography. Anyone who holds the signing key can forge
  signatures. Key distribution and rotation are outside DML's scope — treat the
  key as a shared secret scoped to a deployment environment.
- **No encryption.** DML signs documents but does not encrypt them. Trap
  definitions are visible to anyone who can read the file. If your trap
  definitions themselves are sensitive (e.g., they reveal internal network
  paths), sign and then encrypt at the transport or storage layer.
- **Canonicalization is JSON-only.** The deterministic serialisation used for
  signing is compact JSON with sorted keys. Documents stored in YAML are
  converted to JSON before signing, so the on-disk format and the signed
  representation differ. This is transparent to the library but matters if you
  verify signatures outside Python.
- **No automatic key rotation.** DML has no built-in key lifecycle. Rotating
  the key requires re-signing every document — plan your key rotation process
  separately.
- **The spec is not a runtime.** DML describes and signs traps; it does not
  deploy, manage, or enforce them. Integration with sensors, aggregators, and
  response systems is the responsibility of the platform consuming the DML
  document (e.g., WraithWall).

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 niffy_hunt.

---

Part of the WraithWall project — https://wraithwall.online · by niffy_hunt.
