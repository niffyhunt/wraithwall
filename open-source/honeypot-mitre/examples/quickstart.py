"""Quickstart for honeypot-mitre.

Parses the bundled synthetic Cowrie log, prints a one-line intelligence summary
per session, and demonstrates the order-independent dedup key.

Run::

    python examples/quickstart.py
"""

from __future__ import annotations

import os

from honeypot_mitre import (
    analyze_session,
    classify_actor,
    dedup_key,
    map_techniques,
    parse_sessions,
    score_session,
)

SAMPLE = os.path.join(os.path.dirname(__file__), "sample_cowrie.json")


def main() -> None:
    sessions = parse_sessions(SAMPLE)
    print(f"Parsed {len(sessions)} session(s) from {os.path.basename(SAMPLE)}\n")

    for session in sessions:
        record = analyze_session(session)
        print(f"session {record['session_id']}  src={record['src_ip']}")
        print(f"  commands ({len(record['commands'])}): {record['commands']}")
        print(f"  dominant stage: {record['dominant_stage']}  progression: {record['progression']}")
        print(f"  techniques: {record['techniques']}")
        print(f"  score: {record['score']}/100  actor: {record['actor_label']}")
        if record["campaign_indicators"]:
            print(f"  campaign indicators: {record['campaign_indicators']}")
        print(f"  dedup_key: {record['dedup_key']}\n")

    # Building blocks can also be called directly.
    cmds_a = ["uname -a", "whoami", "cat /etc/shadow"]
    cmds_b = ["cat /etc/shadow", "uname -a", "whoami"]  # same set, different order
    print("Direct API:")
    print(f"  map_techniques -> {map_techniques(cmds_a)['techniques_used']}")
    print(f"  score_session  -> {score_session(cmds_a)}")
    print(f"  classify_actor -> {classify_actor(cmds_a, duration=120)['actor_label']}")
    print(f"  dedup stable across order: {dedup_key(cmds_a) == dedup_key(cmds_b)}")


if __name__ == "__main__":
    main()
