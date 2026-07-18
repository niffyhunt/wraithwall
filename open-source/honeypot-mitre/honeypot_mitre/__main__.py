"""Command-line interface.

Usage::

    python -m honeypot_mitre path/to/cowrie.json
    cat cowrie.json | python -m honeypot_mitre -
    python -m honeypot_mitre              # reads stdin when no file given

Reads Cowrie JSON event logs (one JSON object per line), reconstructs sessions,
and emits one JSON intelligence record per session.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .parsing import parse_lines, parse_sessions
from .pipeline import analyze_session


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeypot-mitre",
        description="Map raw Cowrie honeypot logs to MITRE ATT&CK + a threat score "
                    "+ a replay dedup key. Emits one JSON record per session.",
    )
    parser.add_argument(
        "logfile",
        nargs="?",
        default="-",
        help="Path to a Cowrie JSON log, or '-' for stdin (default: stdin).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print each JSON record (default: one compact object per line).",
    )
    parser.add_argument(
        "--min-score",
        type=int,
        default=0,
        help="Only emit sessions whose deterministic score is >= this value.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code.
    """
    args = _build_parser().parse_args(argv)

    if args.logfile == "-":
        sessions = parse_lines(sys.stdin)
    else:
        sessions = parse_sessions(args.logfile)

    indent = 2 if args.pretty else None
    for session in sessions:
        record = analyze_session(session)
        if record["score"] < args.min_score:
            continue
        sys.stdout.write(json.dumps(record, indent=indent) + "\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
