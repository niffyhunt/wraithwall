"""Command-line interface for Canary Kit.

Run with ``python -m canary_kit ...`` or the installed ``canary-kit`` script.

Subcommands:
    mint    Mint + register a canary token for a package/version.
    list    List issued tokens (and their fired state).
    beacon  Record/simulate a beacon hit and report whether it matched.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .filestore import FileStore
from .registry import CanaryRegistry
from .tokens import TOKEN_TYPES, TOKEN_TYPE_RUNTIME

DEFAULT_REGISTRY = ".canary_kit_registry.json"


def _registry(args: argparse.Namespace) -> CanaryRegistry:
    return CanaryRegistry(store=FileStore(args.registry))


def cmd_mint(args: argparse.Namespace) -> int:
    reg = _registry(args)
    record = reg.register(
        args.package,
        args.version,
        token_type=args.type,
        salt=args.salt,
    )
    print(json.dumps(record.to_dict(), indent=2))
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    reg = _registry(args)
    records = reg.all_records()
    if not records:
        print("(no tokens registered)")
        return 0
    for r in records:
        flag = "FIRED" if r.fired else "armed"
        print(f"{r.token}  {r.package_name}@{r.version}  [{r.token_type}]  {flag} x{r.fire_count}")
    return 0


def cmd_beacon(args: argparse.Namespace) -> int:
    reg = _registry(args)
    result = reg.detect(
        args.token,
        ip_address=args.ip,
        env_hash=args.env,
        version=args.beacon_version,
    )
    if result.matched:
        print(f"MATCH: canary fired for token {result.token}")
        if result.record:
            print(json.dumps(result.record.to_dict(), indent=2))
        return 0
    print(f"NO MATCH: {result.reason} (token={result.token!r})")
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="canary-kit", description="Supply-chain canary token kit.")
    p.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY,
        type=Path,
        help=f"JSON registry file (default: {DEFAULT_REGISTRY})",
    )
    sub = p.add_subparsers(dest="command", required=True)

    m = sub.add_parser("mint", help="Mint + register a canary token")
    m.add_argument("package", help="Package name")
    m.add_argument("version", help="Package version")
    m.add_argument("--type", choices=TOKEN_TYPES, default=TOKEN_TYPE_RUNTIME, help="Token type")
    m.add_argument("--salt", default=None, help="Explicit salt for deterministic minting")
    m.set_defaults(func=cmd_mint)

    ls = sub.add_parser("list", help="List issued tokens")
    ls.set_defaults(func=cmd_list)

    b = sub.add_parser("beacon", help="Record/simulate a beacon hit")
    b.add_argument("token", help="Token reported by the beacon")
    b.add_argument("--ip", default="", help="Source IP of the beacon")
    b.add_argument("--env", default="unknown", help="Environment fingerprint hash")
    b.add_argument("--beacon-version", default="unknown", help="Version reported by the beacon")
    b.set_defaults(func=cmd_beacon)

    return p


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
