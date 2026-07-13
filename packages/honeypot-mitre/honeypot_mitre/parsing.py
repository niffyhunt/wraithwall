"""Cowrie log parsing.

Reads `cowrie` honeypot JSON event logs (one JSON object per line) and
reconstructs per-session state: the ordered command sequence, login attempts,
file downloads, source IP, and session duration.

This replaces the original long-running, queue-backed log watcher with a simple
batch reader over an iterable of lines (a file handle, ``sys.stdin``, a list of
strings, ...). There is no threading, no Redis, and no network access.

Relevant Cowrie event ids:

* ``cowrie.session.connect``        — opens a session, carries ``src_ip``/``src_port``
* ``cowrie.login.success`` / ``.failed`` — login attempt with ``username``/``password``
* ``cowrie.command.input``          — a single command line in ``input``
* ``cowrie.session.file_download``  — a downloaded file (``url``/``outfile``)
* ``cowrie.session.closed``         — closes the session, carries ``duration``
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class Session:
    """A reconstructed Cowrie session.

    Attributes:
        session_id: Cowrie session identifier.
        src_ip: Source IP address of the connecting client.
        src_port: Source port, if reported.
        connected_at: ISO timestamp from the connect event.
        closed_at: ISO timestamp from the close event.
        sensor: Cowrie sensor name, if reported.
        duration: Session duration in seconds (from the close event).
        commands: Ordered list of command lines the attacker issued.
        downloads: List of ``{"url", "outfile", "timestamp"}`` dicts.
        login_attempts: List of ``{"username", "password", "success", "timestamp"}``.
    """

    session_id: str
    src_ip: str = ''
    src_port: int = 0
    connected_at: str = ''
    closed_at: str = ''
    sensor: str = ''
    duration: float = 0.0
    commands: List[str] = field(default_factory=list)
    downloads: List[Dict[str, Any]] = field(default_factory=list)
    login_attempts: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Return a plain ``dict`` representation of the session."""
        return {
            'session_id': self.session_id,
            'src_ip': self.src_ip,
            'src_port': self.src_port,
            'connected_at': self.connected_at,
            'closed_at': self.closed_at,
            'sensor': self.sensor,
            'duration': self.duration,
            'commands': list(self.commands),
            'downloads': list(self.downloads),
            'login_attempts': list(self.login_attempts),
        }


def _coerce_float(value: Any) -> float:
    """Best-effort coercion of an arbitrary value to ``float`` (``0.0`` on failure)."""
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def parse_events(events: Iterable[Dict[str, Any]]) -> List[Session]:
    """Reconstruct sessions from an iterable of already-decoded Cowrie events.

    Events are grouped by their ``session`` field. Events without a session id
    are ignored. Sessions are returned in first-seen order. A session can be
    reconstructed even if its connect or close event is missing.

    Args:
        events: Iterable of decoded Cowrie event dicts.

    Returns:
        List of :class:`Session` objects in first-seen order.
    """
    sessions: Dict[str, Session] = {}
    order: List[str] = []

    def _get(sid: str) -> Session:
        if sid not in sessions:
            sessions[sid] = Session(session_id=sid)
            order.append(sid)
        return sessions[sid]

    for event in events:
        if not isinstance(event, dict):
            continue
        sid = event.get('session', '')
        if not sid:
            continue

        eventid = event.get('eventid', '')
        session = _get(sid)

        if eventid == 'cowrie.session.connect':
            session.src_ip = event.get('src_ip', '') or session.src_ip
            session.src_port = event.get('src_port', 0) or session.src_port
            session.connected_at = event.get('timestamp', '') or session.connected_at
            session.sensor = event.get('sensor', '') or session.sensor

        elif eventid in ('cowrie.login.success', 'cowrie.login.failed'):
            session.login_attempts.append({
                'username': event.get('username', ''),
                'password': event.get('password', ''),
                'success': eventid == 'cowrie.login.success',
                'timestamp': event.get('timestamp', ''),
            })

        elif eventid == 'cowrie.command.input':
            command = (event.get('input', '') or '').strip()
            if command:
                session.commands.append(command)
            if not session.src_ip:
                session.src_ip = event.get('src_ip', '') or session.src_ip

        elif eventid == 'cowrie.session.file_download':
            session.downloads.append({
                'url': event.get('url', ''),
                'outfile': event.get('outfile', ''),
                'timestamp': event.get('timestamp', ''),
            })

        elif eventid == 'cowrie.session.closed':
            session.duration = _coerce_float(event.get('duration', 0))
            session.closed_at = event.get('timestamp', '') or session.closed_at

        # Carry src_ip forward from any event that reports it.
        if not session.src_ip and event.get('src_ip'):
            session.src_ip = event['src_ip']

    return [sessions[sid] for sid in order]


def parse_lines(lines: Iterable[str]) -> List[Session]:
    """Reconstruct sessions from an iterable of raw JSON-lines text.

    Each non-empty line is parsed as one JSON object; malformed lines are
    silently skipped (honeypot logs routinely contain partial/garbled lines).

    Args:
        lines: Iterable of text lines (e.g. an open file handle or ``sys.stdin``).

    Returns:
        List of :class:`Session` objects in first-seen order.
    """
    def _decoded() -> Iterable[Dict[str, Any]]:
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue

    return parse_events(_decoded())


def parse_sessions(source: Any) -> List[Session]:
    """Parse Cowrie sessions from a file path, file handle, or line iterable.

    Args:
        source: A filesystem path (``str`` / ``os.PathLike``) to a Cowrie JSON
            log, or any iterable of text lines (open file, ``sys.stdin``, list).

    Returns:
        List of :class:`Session` objects in first-seen order.
    """
    import os

    if isinstance(source, (str, os.PathLike)):
        with open(source, 'r', encoding='utf-8', errors='replace') as handle:
            return parse_lines(handle)
    return parse_lines(source)
