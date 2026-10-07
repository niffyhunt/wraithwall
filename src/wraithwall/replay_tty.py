"""
REPLAY — Cowrie TTY session playback.

Parses Cowrie's binary ttylog format (little-endian 24-byte frame header plus
raw terminal bytes), sanitizes escape sequences, and serves through an
admin-gated endpoint for xterm.js rendering.

TTY logs are read from the shared Docker volume mounted on the honeypot
host and shipped through the existing cowrie:log → consumer pipeline.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from flask import Blueprint, Response, jsonify, request, render_template_string

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "")
TTYLOG_BASE_PATH = os.environ.get(
    "TTYLOG_BASE_PATH", "/var/log/cowrie/tty"
)

# Parser lives in sandbox_kit (pure stdlib) so `python -m sandbox_kit replay`
# works without the web stack; re-exported here so existing
# `from wraithwall.replay_tty import parse_ttylog` callers keep working.
from sandbox_kit.ttylog import (  # noqa: F401
    SANITIZE_BELL,
    SANITIZE_CSI,
    SANITIZE_DCS,
    SANITIZE_OSC,
    SANITIZE_OTHER,
    parse_ttylog,
    sanitize_for_terminal,
)

replay_bp = Blueprint("replay", __name__)

def _get_redis():
    if not REDIS_URL:
        return None
    try:
        import redis as redis_lib
        return redis_lib.from_url(REDIS_URL, socket_connect_timeout=3,
                                  socket_timeout=5, decode_responses=True)
    except Exception:
        return None

def _require_admin():
    """Fail-closed admin gate for TTY replay.

    The published package ships no account system, so the check is bound by
    the host application (``wraithwall.host_auth.bind(is_logged_in=...,
    is_admin=...)``). With nothing bound, TTY replay is refused rather than
    served to anonymous callers.
    """
    from wraithwall import host_auth

    if not {"is_logged_in", "is_admin"}.issubset(host_auth.bound()):
        return jsonify({"error": "Admin authentication required"}), 403
    if not host_auth.is_logged_in() or not host_auth.is_admin():
        return jsonify({"error": "Admin authentication required"}), 403
    return None

def _require_logged_in():
    """Softer check for playbook-linked TTY replays (analysts with playbook perms can view their incident TTYs)."""
    from wraithwall import host_auth

    if "is_logged_in" not in host_auth.bound():
        return jsonify({"error": "Login required"}), 401
    if not host_auth.is_logged_in():
        return jsonify({"error": "Login required"}), 401
    return None


def generate_playback_html(session_id: str, frames: list) -> str:
    """Generate a sandboxed playback page with xterm.js.

    ``frames`` is injected with Jinja's ``tojson`` filter, which escapes
    ``<``, ``>``, ``&`` and ``'`` so hostile terminal output captured from a
    honeypot session cannot break out of the script tag.
    """
    return render_template_string("""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TTY Replay — {{ session_id }}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/xterm@5.3.0/css/xterm.css">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { background: #0a0a0a; color: #c0c0c0; font-family: monospace; }
#terminal { width: 100%; height: 100vh; padding: 8px; }
.replay-bar {
    display: flex; align-items: center; gap: 12px; padding: 6px 12px;
    background: #1a1a1a; border-bottom: 1px solid #333; font-size: 12px;
}
.replay-bar span { color: #888; }
.replay-bar .session { color: #c41a1a; font-weight: bold; }
#speed { width: 80px; }
</style>
</head>
<body>
<div class="replay-bar">
    <span class="session">SESSION: {{ session_id }}</span>
    <span>Speed:</span>
    <input type="range" id="speed" min="0.5" max="5" step="0.5" value="1">
    <span id="speed-label">1x</span>
    <span id="progress">0 / {{ frame_count }}</span>
</div>
<div id="terminal"></div>
<script src="https://cdn.jsdelivr.net/npm/xterm@5.3.0/lib/xterm.js"></script>
<script>
(function() {
    var frames = {{ frames | tojson }};
    var term = new Terminal({
        cols: 120, rows: 40,
        cursorBlink: false, disableStdin: true,
        fontSize: 13, fontFamily: "'Courier New', monospace",
        theme: { background: '#0a0a0a', foreground: '#c0c0c0' },
    });
    term.open(document.getElementById('terminal'));

    var idx = 0, speed = 1;
    var speedEl = document.getElementById('speed');
    var speedLabel = document.getElementById('speed-label');
    var progressEl = document.getElementById('progress');

    speedEl.addEventListener('input', function() {
        speed = parseFloat(this.value);
        speedLabel.textContent = speed + 'x';
    });

    function playNext() {
        if (idx >= frames.length) { term.write('\\r\\n--- END OF REPLAY ---\\r\\n'); return; }
        var frame = frames[idx];
        term.write(frame[1]);
        progressEl.textContent = (idx + 1) + ' / ' + frames.length;
        idx++;
        if (idx < frames.length) {
            var delay = (frames[idx][0] - frame[0]) * 1000 / speed;
            delay = Math.max(delay, 10);
            setTimeout(playNext, delay);
        }
    }

    if (frames.length > 0) { playNext(); }
    else { term.write('No TTY data for this session.\\r\\n'); }
})();
</script>
</body>
</html>""", session_id=session_id, frames=frames,
   frame_count=len(frames))

@replay_bp.route("/api/cowrie/session/<session_id>/tty", methods=["GET"])
def get_tty_replay(session_id: str):
    """Return TTY playback data as JSON (API) or HTML page depending on Accept header."""
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    r = _get_redis()
    tty_path = None

    if r:
        try:
            tty_path = r.get(f"cowrie_tty_path:{session_id}")
        except Exception:
            pass

    if not tty_path:
        tty_path = os.path.join(TTYLOG_BASE_PATH, session_id)

    frames = parse_ttylog(tty_path)

    accept = request.headers.get("Accept", "")
    if "text/html" in accept:
        return generate_playback_html(session_id, frames)

    return jsonify({
        "ok": True,
        "session_id": session_id,
        "frame_count": len(frames),
        "duration_seconds": round(
            frames[-1][0] - frames[0][0], 1
        ) if frames else 0,
        "frames": [
            {"timestamp": round(ts, 3), "text": txt}
            for ts, txt in frames
        ],
    })

@replay_bp.route("/api/cowrie/session/<session_id>/tty/play", methods=["GET"])
def play_tty_replay(session_id: str):
    """Serve the interactive HTML playback page.
    For playbook hot-links we allow any logged-in user (they only see sessions linked in their playbooks).
    """
    auth_err = _require_logged_in()
    if auth_err:
        return auth_err

    r = _get_redis()
    tty_path = None

    if r:
        try:
            tty_path = r.get(f"cowrie_tty_path:{session_id}")
        except Exception:
            pass

    if not tty_path:
        tty_path = os.path.join(TTYLOG_BASE_PATH, session_id)

    frames = parse_ttylog(tty_path)
    return generate_playback_html(session_id, frames)
