"""End-to-end Canary Kit demo: mint, register, then detect a beacon.

Run with:  python examples/quickstart.py
"""

from __future__ import annotations

from canary_kit import (
    CanaryRegistry,
    InMemoryStore,
    TOKEN_TYPE_RUNTIME,
    decode_watermark,
    encode_watermark,
    mint_token,
)


def main() -> None:
    # 1. Stand up a registry over the default in-memory store.
    registry = CanaryRegistry(store=InMemoryStore())

    # 2. Mint + register a canary token for a package we are publishing.
    record = registry.register(
        "acme-internal-utils",
        "1.4.2",
        token_type=TOKEN_TYPE_RUNTIME,
        owner="platform-security",
    )
    print(f"Minted canary token: {record.token}")
    print(f"  package : {record.package_name}@{record.version}")
    print(f"  type    : {record.token_type}")
    print(f"  armed   : fired={record.fired}")

    # 3. Show the deterministic zero-width watermark for this token.
    wm = encode_watermark(record.token)
    print(f"  watermark prefix recovered: {decode_watermark('hi' + wm + 'there')}")

    # 4. An attacker imports the package outside our network -> beacon fires.
    print("\n-- beacon arrives from a token we issued --")
    hit = registry.detect(
        record.token,
        ip_address="198.51.100.23",
        env_hash="a1b2c3d4e5f6",
        version="1.4.2",
    )
    print(f"matched : {hit.matched}")
    print(f"fired   : {hit.record.fired}, count={hit.record.fire_count}")
    print(f"ips     : {hit.record.fire_ips}")

    # 5. A beacon carrying an unknown/forged token does NOT match.
    print("\n-- beacon arrives with an unknown token --")
    forged = mint_token("not-ours", "9.9.9")
    miss = registry.detect(forged, ip_address="203.0.113.7")
    print(f"matched : {miss.matched}  reason: {miss.reason}")

    print("\nDone. The fired token is your high-signal supply-chain alert.")


if __name__ == "__main__":
    main()
