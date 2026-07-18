# Canary Kit

**Canary Kit detects software supply-chain compromise: it plants uniquely-derived
canary tokens in a package and raises a high-signal alert the moment one "fires" —
i.e. when the planted code beacons home from an environment you don't control
(a leaked build, a typosquat install, an attacker unpacking your release).**

A canary token is worthless to the attacker but invaluable to you: legitimate
internal use is silent, so any beacon you receive is, by construction, suspicious.

This is the standalone, MIT-licensed extraction of the supply-chain canary core
from the [WraithWall](https://wraithwall.online) security platform. It has **no
Flask, web framework, or network dependency** in its core — just the minting,
registration, and trigger-detection logic.

## Install

```bash
pip install .
# optional extras:
pip install ".[redis]"   # inject your own redis client
pip install ".[test]"    # pytest
```

Requires Python >= 3.10. The core has **zero third-party dependencies**.

## Quickstart

```python
from canary_kit import CanaryRegistry, InMemoryStore

registry = CanaryRegistry(store=InMemoryStore())

# Mint + register a canary for a package you're about to ship.
record = registry.register("acme-internal-utils", "1.4.2", owner="sec-team")
print(record.token)            # e.g. 9f1c... (24 hex chars)

# Later: a beacon arrives carrying a token. Did it match one we issued?
hit = registry.detect(record.token, ip_address="198.51.100.23", env_hash="a1b2")
print(hit.matched)             # True  -> the canary fired
print(hit.record.fire_count)   # 1

# A forged / unknown token never matches.
miss = registry.detect("deadbeefdeadbeefdeadbeef")
print(miss.matched, miss.reason)   # False unknown token
```

Run the full demo:

```bash
python examples/quickstart.py
```

## Public API

```python
# Minting & derivations (stdlib only)
mint_token(package_name: str, version: str, *, salt: str | None = None) -> str
derive_token(package_name: str, version: str, salt: str) -> str  # deterministic
encode_watermark(token: str) -> str          # zero-width watermark of token[:8]
decode_watermark(text: str) -> str | None    # recover token[:8] from text

# Metadata model
class CanaryToken:                            # dataclass
    token, package_name, version, token_type, created_at,
    fired, fire_count, last_fired, fire_ips, fire_environments, extra
    .to_dict() -> dict
    CanaryToken.from_dict(dict) -> CanaryToken

# Token types
TOKEN_TYPE_RUNTIME, TOKEN_TYPE_DNS, TOKEN_TYPE_WATERMARK, TOKEN_TYPES

# Registration + detection
class CanaryRegistry(store: CanaryStore | None = None)
    .register(package_name, version, *, token_type=..., salt=None,
              token=None, **extra) -> CanaryToken
    .get(token) -> CanaryToken | None
    .list_tokens() -> list[str]
    .all_records() -> list[CanaryToken]
    .detect(token, *, ip_address="", env_hash="unknown",
            version="unknown") -> BeaconResult   # alias: report_beacon

class BeaconResult:                           # dataclass
    matched: bool; token: str; record: CanaryToken | None; reason: str

# Pluggable storage (Redis is optional and never auto-connects)
class CanaryStore(Protocol):   put/get/all/tokens
class InMemoryStore(...)        # default, thread-safe
class RedisStore(client, *, prefix="canary_kit:", ttl_seconds=...)  # inject client
```

## CLI usage

```bash
# Mint + register a token (persisted to a JSON registry file)
$ python -m canary_kit mint acme-internal-utils 1.4.2 --type runtime
{
  "token": "9f1c2a...",
  "package_name": "acme-internal-utils",
  "version": "1.4.2",
  "token_type": "runtime",
  "fired": false,
  ...
}

# List issued tokens
$ python -m canary_kit list
9f1c2a...  acme-internal-utils@1.4.2  [runtime]  armed x0

# Simulate / record a beacon hit
$ python -m canary_kit beacon 9f1c2a... --ip 198.51.100.23 --env a1b2
MATCH: canary fired for token 9f1c2a...

# Unknown token -> exit code 1
$ python -m canary_kit beacon deadbeef...
NO MATCH: unknown token (token='deadbeef...')
```

Use `--registry PATH` to choose the JSON registry file (default
`.canary_kit_registry.json` in the working directory). The installed console
script `canary-kit` is equivalent to `python -m canary_kit`.

## How detection works

1. **Mint** — a token is `sha256(f"{package}:{version}:{salt}")[:24]`. With no
   explicit salt, a random `secrets.token_hex(8)` salt makes each token unique;
   pass a salt to derive a token reproducibly.
2. **Plant & register** — you embed that token in your package (as runtime
   beacon code, a DNS hostname in metadata, or a zero-width docstring watermark)
   and call `registry.register(...)` to record its metadata in the store.
3. **Beacon** — when the planted artifact runs/installs outside your control, it
   phones home carrying the token (plus an environment fingerprint and version).
4. **Detect** — `registry.detect(token, ...)` looks the token up in the store.
   A hit means the canary *fired*: the record is marked `fired`, counters and
   source IPs/environments accumulate, and you get a `BeaconResult(matched=True)`.
   An unknown/forged token returns `matched=False` and changes nothing.

Because issued tokens are random and never used in legitimate traffic, a match
is an inherently high-signal indicator of a leaked or tampered package.

## Limitations

- **Token entropy.** The minted token is 24 hex characters (96 bits) from SHA-256.
  This is sufficient for anyone who cannot brute-force the token space, but a
  token leaked in source control or a CI log is game-over — rotate the salt and
  re-mint.
- **No network dependency.** Canary Kit does not listen, poll, or ship data
  anywhere. Beacon detection is a registry lookup you call from your own
  telemetry pipeline — you must build the ingestion path.
- **Deterministic derivation.** Passing an explicit `salt` makes the token
  reproducible, which is useful for testing but means anyone who knows the
  inputs can precompute the token. Use the random-salt default for production.
- **Zero-width watermarking.** `encode_watermark` / `decode_watermark` embeds
  the first 8 hex characters of a token as zero-width Unicode characters
  (U+200B, U+200C, U+200D, U+FEFF). This survives copy-paste but not
  re-encoding (e.g., minification, OCR, or charset conversion that strips
  zero-width codepoints).
- **Storage choice is yours.** The library ships with an `InMemoryStore` and a
  `RedisStore` adapter, but you can provide any store implementing the
  `CanaryStore` protocol. There is no built-in persistence to disk or cloud.

## Development

```bash
git clone https://github.com/niffyhunt/wraithwall-toolkit
cd wraithwall-toolkit/canary-kit
pip install -e ".[test]"
pytest
```

Contributions are welcome. The core is deliberately dependency-free; any
proposed addition that introduces a runtime dependency should justify it.

## License

MIT — see [LICENSE](LICENSE). Copyright (c) 2026 niffy_hunt.

---

Part of the WraithWall project — https://wraithwall.online · by niffy_hunt
