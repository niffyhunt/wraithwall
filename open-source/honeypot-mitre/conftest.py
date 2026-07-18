"""Pytest bootstrap: make the package importable when running from a source
checkout without a local install (``pip install .`` is the supported
path; this is only a convenience for in-tree test runs)."""

import os
import sys

sys.path.insert(0, os.path.dirname(__file__))
