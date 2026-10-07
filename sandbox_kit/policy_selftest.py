#!/usr/bin/env python3
"""Egress-container policy self-check (T2 dynamic gate, Phase 11).

Runs as part of every research-sandbox start: the egress container must
classify every canonical deny case as DENIED before the plane is trusted.
Pure computation — no network, no DNS — so it is deterministic and cheap.
Fail-closed: any surprise is exit 1 and the launcher tears the plane down
(E212 path).

Installed in the egress image at /egress/policy_selftest.py. The container's
compose healthcheck-style self-test runs `python /egress/policy_selftest.py`.
"""
import sys

sys.path.insert(0, "/egress")

from egress_policy import SELF_TEST_CASES, classify  # sys.path insert above; not a lint code


def main() -> int:
    failures = []
    for host, why in SELF_TEST_CASES:
        denied, reason = classify(host)
        if not denied:
            failures.append(f"{host} ({why}) was ALLOWED: {reason}")
    if failures:
        print("POLICY_SELF_TEST_FAILED:")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"POLICY_SELF_TEST_OK: {len(SELF_TEST_CASES)} deny cases classified correctly")
    return 0


if __name__ == "__main__":
    sys.exit(main())
