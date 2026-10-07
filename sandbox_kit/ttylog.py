"""Cowrie ttylog parsing — pure stdlib, deliberately free of web-stack imports.

The binary ttylog parser used to live in ``wraithwall.replay_tty``, a Flask
blueprint module. ``python -m sandbox_kit replay`` only needs the parser, but
importing it through the blueprint pulled in the whole Flask app chain
(``wraithwall/__init__`` imports flask), so replay died with
``ModuleNotFoundError: No module named 'flask'`` on any interpreter that has
the sandbox kit but not the web stack — including the CI platform matrix,
which installs only pytest and PyYAML.

Canonical location is here. ``wraithwall.replay_tty`` re-exports
``parse_ttylog``/``sanitize_for_terminal`` so existing importers keep working.

Format (authoritative): verified against cowrie 3.0.14
``src/cowrie/core/ttylog.py`` — ``TTYSTRUCT = "<iLiiLL"``, little-endian,
24-byte header followed by ``length`` payload bytes.
"""
from __future__ import annotations

import logging
import re
import struct
from typing import List, Tuple

logger = logging.getLogger(__name__)

SANITIZE_CSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
SANITIZE_OSC = re.compile(r"\x1b\][^\x07\x1b]*(\x07|\x1b\\)")
SANITIZE_DCS = re.compile(r"\x1bP[^\x1b]*\x1b\\")
SANITIZE_OTHER = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
SANITIZE_BELL = re.compile(r"\x07")


def parse_ttylog(file_path: str) -> List[Tuple[float, str]]:
    """Parse a Cowrie binary ttylog file (authoritative format).

    Verified against cowrie 3.0.14 src/cowrie/core/ttylog.py:
      TTYSTRUCT = "<iLiiLL"  ->  [op:i][tty:L][length:i][direction:i][sec:L][usec:L]
      little-endian, 24-byte header, followed by `length` payload bytes.
      op: 1=open 2=close 3=write 4=exec; direction: 1=input 2=output 3=interact.

    Only OP_WRITE frames with direction != 2 (i.e. attacker INPUT — the
    same rule cowrie's own input-hash uses) contribute replay frames.

    Returns:
        List of (timestamp_seconds, sanitized_text) tuples for input frames.
    """
    frames: List[Tuple[float, str]] = []
    hdr = struct.Struct("<iLiiLL")
    OP_WRITE, DIR_OUTPUT = 3, 2

    try:
        with open(file_path, "rb") as f:
            while True:
                header = f.read(hdr.size)
                if len(header) < hdr.size:
                    break
                op, _tty, length, direction, sec, usec = hdr.unpack(header)
                if length < 0 or length > 1024 * 1024:
                    break
                data = f.read(length)
                if len(data) < length:
                    break
                if op == OP_WRITE and direction != DIR_OUTPUT and length:
                    text = sanitize_for_terminal(data)
                    if text:
                        frames.append((sec + usec / 1_000_000.0, text))
    except FileNotFoundError:
        logger.debug(f"TTY log not found: {file_path}")
    except Exception as e:
        logger.error(f"TTY parse error for {file_path}: {e}")

    return frames


def sanitize_for_terminal(data: bytes) -> str:
    """Strip terminal escape sequences and non-printable characters.

    Preserves: printable ASCII, newlines, carriage returns, tabs.
    Removes: CSI sequences, OSC sequences, DCS sequences, null bytes,
             bell characters, and other control characters.
    """
    text = data.decode("utf-8", errors="replace")

    text = SANITIZE_OSC.sub("", text)
    text = SANITIZE_DCS.sub("", text)
    text = SANITIZE_CSI.sub("", text)
    text = SANITIZE_BELL.sub("", text)
    text = SANITIZE_OTHER.sub("", text)

    return text
