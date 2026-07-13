"""Standalone check: package imports and runs with anthropic unavailable.

Run with: python3 tests/_no_anthropic_check.py
Simulates anthropic being uninstalled by inserting a finder that hides it.
"""
import importlib.abc
import importlib.machinery
import os
import sys


class _HideAnthropic(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path, target=None):
        if fullname == "anthropic" or fullname.startswith("anthropic."):
            raise ImportError("anthropic hidden for test")
        return None


sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.meta_path.insert(0, _HideAnthropic())
for mod in [m for m in sys.modules if m == "anthropic" or m.startswith("anthropic.")]:
    del sys.modules[mod]

import honeypot_mitre as h  # noqa: E402

api = ["parse_sessions", "score_session", "map_techniques",
       "classify_actor", "dedup_key", "Analyzer", "analyze_session"]
assert all(hasattr(h, n) for n in api), "missing public API"

sessions = h.parse_sessions("examples/sample_cowrie.json")
assert len(sessions) == 3
rec = h.analyze_session(sessions[0])
print("OK import-without-anthropic; version", h.__version__,
      "| sample0 score", rec["score"], "actor", rec["actor_label"])
print("public API:", ", ".join(api))
