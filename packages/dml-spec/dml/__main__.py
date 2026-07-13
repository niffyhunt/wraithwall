"""Command-line interface for DML.

Subcommands:

    python -m dml validate <doc.yaml>
    python -m dml sign     <doc.yaml> --key-env DML_KEY [-o signed.yaml]
    python -m dml verify   <signed.yaml> --key-env DML_KEY
    python -m dml schema

The signing key is read from the named environment variable (``DML_KEY`` by
default). The key is never accepted as a command-line literal, so it cannot
leak into shell history or process listings.
"""

from __future__ import annotations

import argparse
import json
import sys

from .io import dump, dumps, load
from .signing import DEFAULT_KEY_ENV, DMLSigner
from .spec import (
    DML_VERSION,
    MITRE_TACTICS,
    RESPONSE_TYPES,
    SEVERITY_LEVELS,
    TRIGGER_TYPES,
)
from .validator import DMLValidator


def _cmd_validate(args: argparse.Namespace) -> int:
    doc = load(args.document)
    errors = DMLValidator().validate_document(doc)
    if not errors:
        print(f"OK: valid DML document ({len(doc.get('traps', []))} traps)")
        return 0
    print(f"INVALID: {len(errors)} error(s):", file=sys.stderr)
    for e in errors:
        print(f"   - {e}", file=sys.stderr)
    return 1


def _cmd_sign(args: argparse.Namespace) -> int:
    doc = load(args.document)
    signer = DMLSigner.from_env(args.key_env)
    signed = signer.sign_document(doc)
    if args.output:
        dump(signed, args.output)
        print(f"OK: signed document written to {args.output}")
    else:
        fmt = "json" if args.document.lower().endswith(".json") else "yaml"
        sys.stdout.write(dumps(signed, fmt=fmt))
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    doc = load(args.document)
    signer = DMLSigner.from_env(args.key_env)
    ok, errors = signer.verify_document(doc)
    if ok:
        print("OK: document signature valid")
        return 0
    print("FAILED: verification failed:", file=sys.stderr)
    for e in errors:
        print(f"   - {e}", file=sys.stderr)
    return 1


def _cmd_schema(_args: argparse.Namespace) -> int:
    print(
        json.dumps(
            {
                "dml_version": DML_VERSION,
                "trigger_types": sorted(TRIGGER_TYPES),
                "response_types": sorted(RESPONSE_TYPES),
                "severity_levels": sorted(SEVERITY_LEVELS),
                "mitre_tactics": sorted(MITRE_TACTICS),
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the argparse parser for the ``dml`` CLI."""
    parser = argparse.ArgumentParser(
        prog="dml",
        description="Validate, sign and verify Deception Markup Language documents.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_val = sub.add_parser("validate", help="validate a DML document")
    p_val.add_argument("document", help="path to a DML document (.yaml/.yml/.json)")
    p_val.set_defaults(func=_cmd_validate)

    p_sign = sub.add_parser("sign", help="sign a DML document (per-trap + whole-doc)")
    p_sign.add_argument("document", help="path to a DML document")
    p_sign.add_argument(
        "--key-env",
        default=DEFAULT_KEY_ENV,
        help=f"env var holding the HMAC key (default: {DEFAULT_KEY_ENV})",
    )
    p_sign.add_argument(
        "-o", "--output", help="write signed document here instead of stdout"
    )
    p_sign.set_defaults(func=_cmd_sign)

    p_ver = sub.add_parser("verify", help="verify a signed DML document")
    p_ver.add_argument("document", help="path to a signed DML document")
    p_ver.add_argument(
        "--key-env",
        default=DEFAULT_KEY_ENV,
        help=f"env var holding the HMAC key (default: {DEFAULT_KEY_ENV})",
    )
    p_ver.set_defaults(func=_cmd_verify)

    p_schema = sub.add_parser("schema", help="print the DML spec enums as JSON")
    p_schema.set_defaults(func=_cmd_schema)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns a process exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as e:
        print(f"File not found: {e.filename}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
