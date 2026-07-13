"""
WraithWall Terminal — WebSocket PTY gateway

Provides a browser-based terminal via xterm.js + flask-sock WebSocket.
PTY is spawned per-connection, cleaned up on disconnect.
Session-auth gated; idle timeout kills stale sessions.
"""

import os
import pty
import select
import termios
import struct
import fcntl
import signal
import logging
import threading
import time
import json

from flask import Blueprint, request, jsonify, session

logger = logging.getLogger(__name__)

terminal_bp = Blueprint('terminal', __name__, url_prefix='/api/terminal')

TERMINAL_SHELL = os.environ.get('TERMINAL_SHELL', '/bin/bash')
TERMINAL_IDLE_TIMEOUT = int(os.environ.get('TERMINAL_IDLE_TIMEOUT', '900'))

@terminal_bp.route('/token', methods=['POST'])
def get_token():
    """Generate a short-lived JWT for WebSocket auth."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'ok': False, 'error': 'Unauthorized'}), 401

    from jose import jwt as jose_jwt
    from datetime import datetime, timedelta

    token = jose_jwt.encode({
        'sub': str(user_id),
        'type': 'terminal',
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=3600),  # 1 hour session
    }, os.environ.get('SECRET_KEY', ''), algorithm='HS256')

    return jsonify({'ok': True, 'token': token})

@terminal_bp.route('/config')
def get_config():
    return jsonify({
        'ok': True,
        'idle_timeout': TERMINAL_IDLE_TIMEOUT,
        'shell': TERMINAL_SHELL,
    })

def _set_winsize(fd, cols, rows):
    """Set terminal window size on the PTY."""
    try:
        winsize = struct.pack('HHHH', rows, cols, 0, 0)
        fcntl.ioctl(fd, termios.TIOCSWINSZ, winsize)
    except Exception as e:
        logger.warning(f"TIOCSWINSZ failed: {e}")

def _spawn_pty(shell, cols=80, rows=24):
    """Fork a PTY with the given shell. Returns (pid, fd)."""
    pid, fd = pty.fork()
    if pid == 0:
        child_env = os.environ.copy()
        child_env['TERM'] = 'xterm-256color'
        os.execve(shell, [shell], child_env)
    _set_winsize(fd, cols, rows)
    # Put the master side in raw mode so keystrokes (including arrows, ctrl, etc) pass through cleanly to the child shell
    try:
        attrs = termios.tcgetattr(fd)
        attrs[3] = attrs[3] & ~termios.ICANON & ~termios.ECHO & ~termios.ISIG
        attrs[0] = attrs[0] & ~termios.ICRNL & ~termios.IXON
        attrs[1] = attrs[1] & ~termios.OPOST
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
    except Exception as e:
        logger.warning(f"Failed to set raw mode on PTY: {e}")
    return pid, fd

def handle_terminal_ws(ws):
    """
    flask-sock WebSocket handler for the terminal PTY.
    Registered in main.py via Sock().
    Supports either Flask session cookie or short-lived ?token= JWT (preferred for WS stability).
    """
    user_id = None

    # Prefer explicit token (avoids session/cookie issues on WS upgrade behind proxy)
    token = request.args.get('token')
    if token:
        try:
            from jose import jwt as jose_jwt
            claims = jose_jwt.decode(token, os.environ.get('SECRET_KEY', ''), algorithms=['HS256'])
            if claims.get('type') == 'terminal' and claims.get('sub'):
                user_id = claims['sub']
            else:
                ws.close(4001, 'Invalid token')
                return
        except Exception as e:
            logger.warning(f"Terminal token decode failed: {e}")
            ws.close(4001, 'Token validation failed')
            return
    else:
        # Fallback to session (for direct same-origin cases)
        user_id = session.get('user_id')
        if not user_id:
            ws.close(4001, 'Unauthorized')
            return

    pid = None
    fd = None
    stopped = threading.Event()

    try:
        pid, fd = _spawn_pty(TERMINAL_SHELL, 80, 24)
        last_activity = time.time()

        def pty_reader():
            nonlocal last_activity
            buf = b''
            try:
                while not stopped.is_set():
                    r, _, _ = select.select([fd], [], [], 0.5)
                    if r:
                        try:
                            data = os.read(fd, 65536)
                        except OSError:
                            break
                        if not data:
                            break
                        buf += data
                        while b'\n' in buf or len(buf) >= 4096:
                            idx = buf.find(b'\n')
                            if idx == -1 and len(buf) >= 4096:
                                idx = len(buf) - 1
                            chunk = buf[:idx + 1] if idx >= 0 else buf
                            buf = buf[idx + 1:] if idx >= 0 else b''
                            try:
                                ws.send(chunk)
                            except Exception:
                                stopped.set()
                                return
                        last_activity = time.time()
                    if stopped.is_set():
                        break
            except Exception:
                pass
            finally:
                ws.close()

        reader = threading.Thread(target=pty_reader, daemon=True)
        reader.start()

        while not stopped.is_set():
            try:
                msg = ws.receive(timeout=1.0)
            except Exception:
                continue
            if msg is None:
                break
            if isinstance(msg, str) and msg.startswith('{'):
                try:
                    cmd = json.loads(msg)
                    if cmd.get('type') == 'resize':
                        _set_winsize(fd, int(cmd.get('cols', 80)), int(cmd.get('rows', 24)))
                    elif cmd.get('type') == 'ping':
                        pass
                except json.JSONDecodeError:
                    pass
                continue

            data = msg.encode() if isinstance(msg, str) else msg
            try:
                os.write(fd, data)
                last_activity = time.time()
            except OSError:
                break

            if time.time() - last_activity > TERMINAL_IDLE_TIMEOUT:
                logger.info(f"Terminal {user_id}: idle timeout ({TERMINAL_IDLE_TIMEOUT}s)")
                break

    except Exception as e:
        logger.error(f"Terminal error (user={user_id}): {e}")
    finally:
        stopped.set()
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        if pid is not None:
            try:
                os.kill(pid, signal.SIGHUP)
                os.waitpid(pid, 0)
            except OSError:
                pass
