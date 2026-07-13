import os
import re
import sys
import json
import time
import ast
import hashlib
import secrets
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any, Set

import requests
import redis as redis_lib
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────

CANARY_BEACON_URL = os.environ.get('CANARY_BEACON_URL', '')
CANARY_DNS_DOMAIN = os.environ.get('CANARY_DNS_DOMAIN', '')
REDIS_URL = os.environ.get('REDIS_URL', '')
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')

TOKEN_REGISTRY_FILE = Path(".canary_tokens.json")

# Zero-width characters for watermark encoding
ZW_ZERO = '\u200b'
ZW_ONE = '\u200c'
ZW_SEP = '\u200d'

# ────────────────────────────────────────────────────────────
# RUNTIME CANARY TEMPLATE
# ────────────────────────────────────────────────────────────

RUNTIME_CANARY_TEMPLATE = '''
# Supply ‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍chain integrity verification
import threading as _sc_t, hashlib as _sc_h, os as _sc_o
def _sc_v():
    try:
        import platform as _p, socket as _s
        _env = _sc_h.sha256(f"{{_p.system()}}:{{_p.machine()}}:{{_s.gethostname()[:4]}}".encode()).hexdigest()[:12]
        import urllib.request as _ur
        _ur.urlopen(f"https://{beacon_domain}/api/supply-chain/beacon?t={token}&e={{_env}}&v={version}", timeout=2)
    except Exception:
        pass
_sc_t.Thread(target=_sc_v, daemon=True).start()
del _sc_t, _sc_h, _sc_o
'''

# ────────────────────────────────────────────────────────────
# TOKEN REGISTRY
# ────────────────────────────────────────────────────────────

def _get_redis():
    if not REDIS_URL:
        return None
    try:
        return redis_lib.from_url(
            REDIS_URL,
            socket_connect_timeout=3,
            socket_keepalive=True,
            decode_responses=True,
            max_connections=5
        )
    except Exception:
        return None

def _rate_limited(ip: str, bucket: str = "sc_beacon", limit: int = 10, window: int = 60) -> bool:
    """Per-IP rate limit (default 10 hits / 60s) via Redis incr+expire.

    Fails closed (returns True) on Redis error so unauthenticated hits cannot
    flood downstream log writes when Redis is unavailable.
    """
    r = _get_redis()
    if not r:
        return False
    try:
        key = f"rl:{bucket}:{ip or 'unknown'}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, window)
        return int(count) > limit
    except Exception:
        return True

def load_registry() -> Dict:
    r = _get_redis()
    if r:
        tokens = {}
        cursor = 0
        while True:
            cursor, keys = r.scan(cursor, match='supply_chain_canary:*', count=100)
            for key in keys:
                data = r.get(key)
                if data:
                    token_id = key.replace('supply_chain_canary:', '')
                    tokens[token_id] = json.loads(data)
            if cursor == 0:
                break
        if tokens:
            return {"tokens": tokens}

    if TOKEN_REGISTRY_FILE.exists():
        return json.loads(TOKEN_REGISTRY_FILE.read_text())
    return {"tokens": {}}

def save_registry(reg: Dict):
    TOKEN_REGISTRY_FILE.write_text(json.dumps(reg, indent=2))

def register_token(token: str, metadata: Dict) -> str:
    reg = load_registry()
    reg["tokens"][token] = {
        **metadata,
        "created_at": datetime.utcnow().isoformat(),
        "fired": False,
        "fire_count": 0,
        "fire_ips": [],
        "fire_environments": []
    }
    save_registry(reg)

    r = _get_redis()
    if r:
        r.setex(
            f"supply_chain_canary:{token}",
            86400 * 365,
            json.dumps(reg["tokens"][token])
        )
        r.zadd('canaries:active', {token: time.time()})

        # Also store in credential lure format for cross-module visibility
        r.setex(
            f"lure:sc_{token[:12]}",
            86400 * 365,
            json.dumps({
                "lure_id": f"sc_{token[:12]}",
                "platform": "supply_chain",
                "token": token,
                "planted_at": metadata.get("planted_at"),
                "triggered": False,
                "trigger_count": 0,
                "trigger_ips": [],
                "package_name": metadata.get("package_name"),
                "version": metadata.get("version"),
            })
        )
        r.zadd('lures:active', {f"sc_{token[:12]}": time.time()})

    return token

def generate_token(package_name: str, version: str) -> str:
    seed = f"{package_name}:{version}:{secrets.token_hex(8)}"
    return hashlib.sha256(seed.encode()).hexdigest()[:24]

# ────────────────────────────────────────────────────────────
# INJECTION STRATEGY 1 — RUNTIME PING CANARY
# ────────────────────────────────────────────────────────────

def inject_runtime_canary(package_dir: Path, token: str, version: str,
                          beacon_domain: str) -> bool:
    init_file = package_dir / "__init__.py"
    if not init_file.exists():
        for init in package_dir.rglob("__init__.py"):
            init_file = init
            break

    if not init_file.exists():
        logger.warning(f"No __init__.py in {package_dir}")
        return False

    original = init_file.read_text()
    if "_sc_v" in original:
        logger.info(f"Runtime canary already in {init_file}")
        return True

    canary_code = RUNTIME_CANARY_TEMPLATE.format(
        beacon_domain=beacon_domain,
        token=token,
        version=version
    )

    lines = original.split('\n')
    insert_at = 0
    for i, line in enumerate(lines):
        stripped = line.strip()
        if (stripped.startswith('import ') or stripped.startswith('from ') or
                not stripped or stripped.startswith('#')):
            insert_at = i + 1
        else:
            insert_at = i
            break

    if insert_at == 0:
        insert_at = len(lines)

    lines.insert(insert_at, canary_code)
    init_file.write_text('\n'.join(lines))
    logger.info(f"Runtime canary injected: {init_file}")
    return True

# ────────────────────────────────────────────────────────────
# INJECTION STRATEGY 2 — DNS CANARY IN METADATA
# ────────────────────────────────────────────────────────────

def inject_dns_canary_metadata(package_dir: Path, token: str, dns_domain: str) -> bool:
    canary_hostname = f"{token[:12]}.{dns_domain}"
    canary_url = f"https://{canary_hostname}/security"

    metadata_files = [
        ("pyproject.toml", None),
        ("setup.cfg", None),
        ("setup.py", None),
        ("package.json", None),
        ("composer.json", None),
    ]

    for meta_filename, _ in metadata_files:
        meta_file = package_dir / meta_filename
        if not meta_file.exists():
            continue

        content = meta_file.read_text()
        if canary_hostname in content:
            return True

        injected = False

        if meta_filename == "pyproject.toml":
            if "[project.urls]" in content:
                content = content.replace(
                    "[project.urls]",
                    f'[project.urls]\nSecurity = "{canary_url}"'
                )
            else:
                content += f'\n[project.urls]\nSecurity = "{canary_url}"\n'
            injected = True

        elif meta_filename == "setup.cfg":
            if "[metadata]" in content:
                content = content.replace(
                    "[metadata]",
                    f'[metadata]\nsecurity = {canary_url}'
                )
            else:
                content += f'\n[metadata]\nsecurity = {canary_url}\n'
            injected = True

        elif meta_filename == "setup.py":
            if "project_urls" in content:
                content = re.sub(
                    r'(project_urls\s*=\s*\{)',
                    f'\\1\n        "Security": "{canary_url}",',
                    content
                )
            else:
                content = content.replace(
                    'setup(',
                    f'setup(\n    project_urls={{"Security": "{canary_url}"}},'
                )
            injected = True

        elif meta_filename == "package.json":
            pkg = json.loads(content)
            if "repository" not in pkg:
                pkg["repository"] = {"type": "git", "url": f"git+{canary_url}"}
            elif "funding" not in pkg:
                pkg["funding"] = {"url": canary_url}
            else:
                pkg["contributors"] = [{"name": "Security Team", "url": canary_url}]
            content = json.dumps(pkg, indent=2)
            injected = True

        elif meta_filename == "composer.json":
            pkg = json.loads(content)
            if "support" not in pkg:
                pkg["support"] = {"security": canary_url}
            else:
                pkg["support"]["security"] = canary_url
            content = json.dumps(pkg, indent=2)
            injected = True

        if injected:
            meta_file.write_text(content)
            logger.info(f"DNS canary in {meta_filename}: {canary_hostname}")
            return True

    # Fallback
    fallback = package_dir / ".canary"
    fallback.write_text(f"Security: {canary_url}\n")
    logger.info(f"DNS canary fallback: {fallback}")
    return True

# ────────────────────────────────────────────────────────────
# INJECTION STRATEGY 3 — ZERO-WIDTH WATERMARK
# ────────────────────────────────────────────────────────────

def _encode_watermark(token: str) -> str:
    bits = bin(int(token[:8], 16))[2:].zfill(32)
    return ZW_SEP + ''.join(ZW_ONE if b == '1' else ZW_ZERO for b in bits) + ZW_SEP

def _decode_watermark(text: str) -> Optional[str]:
    if ZW_SEP not in text:
        return None
    try:
        parts = text.split(ZW_SEP)
        for part in parts:
            if len(part) == 32 and all(c in (ZW_ZERO, ZW_ONE) for c in part):
                bits = ''.join('1' if c == ZW_ONE else '0' for c in part)
                return hex(int(bits, 2))[2:].zfill(8)
    except Exception:
        pass
    return None

def inject_watermark(package_dir: Path, token: str, max_per_file: int = 3) -> int:
    watermark = _encode_watermark(token)
    count = 0

    for py_file in package_dir.rglob("*.py"):
        try:
            content = py_file.read_text(encoding='utf-8')
            if any(s in str(py_file) for s in ['test_', '_test', 'migration', '__pycache__']):
                continue
            if ZW_SEP in content:
                continue

            modified = False
            added = 0
            try:
                tree = ast.parse(content)
            except SyntaxError:
                continue

            for node in ast.walk(tree):
                if added >= max_per_file:
                    break
                if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
                    if (node.body and isinstance(node.body[0], ast.Expr) and
                            isinstance(node.body[0].value, ast.Constant) and
                            isinstance(node.body[0].value.value, str)):
                        old_doc = node.body[0].value.value
                        words = old_doc.split()
                        if words:
                            first_end = len(words[0])
                            new_doc = old_doc[:first_end] + watermark + old_doc[first_end:]
                            content = content.replace(old_doc, new_doc, 1)
                            modified = True
                            added += 1

            # Fallback: inject into a long string constant
            if not modified:
                for node in ast.walk(tree):
                    if isinstance(node, ast.Assign):
                        for target in node.targets:
                            if (isinstance(target, ast.Name) and
                                    isinstance(node.value, ast.Constant) and
                                    isinstance(node.value.value, str) and
                                    len(node.value.value) > 50):
                                old_str = node.value.value
                                new_str = old_str[:10] + watermark + old_str[10:]
                                content = content.replace(old_str, new_str, 1)
                                modified = True
                                added += 1
                                break
                    if modified:
                        break

            if modified:
                py_file.write_text(content, encoding='utf-8')
                count += 1
        except Exception:
            continue

    logger.info(f"Watermark injected in {count} files")
    return count

# ────────────────────────────────────────────────────────────
# SCANNER
# ────────────────────────────────────────────────────────────

def scan_package(package_dir: Path) -> Dict:
    results = {
        "runtime_canary": False,
        "dns_canaries": [],
        "watermarks": [],
        "files_scanned": 0
    }

    for py_file in package_dir.rglob("*.py"):
        results["files_scanned"] += 1
        try:
            content = py_file.read_text(encoding='utf-8')
            if "_sc_v" in content:
                results["runtime_canary"] = True
            wm = _decode_watermark(content)
            if wm:
                results["watermarks"].append({"file": str(py_file), "token_prefix": wm})
        except Exception:
            pass

    for meta_file in ['pyproject.toml', 'setup.py', 'setup.cfg', 'package.json']:
        f = package_dir / meta_file
        if f.exists():
            content = f.read_text()
            domain = CANARY_DNS_DOMAIN or 'sc.example.com'
            matches = re.findall(r'[a-f0-9]{12}\.' + re.escape(domain), content)
            results["dns_canaries"].extend(matches)

    return results

# ────────────────────────────────────────────────────────────
# BEACON HANDLER
# ────────────────────────────────────────────────────────────

def report_beacon(token: str, env_hash: str, version: str, ip_address: str):
    r = _get_redis()
    if r:
        key = f"supply_chain_canary:{token}"
        existing = r.get(key)
        if existing:
            data = json.loads(existing)
            data["fired"] = True
            data["fire_count"] = data.get("fire_count", 0) + 1
            data["last_fired"] = datetime.utcnow().isoformat()
            data.setdefault("fire_ips", []).append(ip_address)
            data.setdefault("fire_environments", []).append({
                "env_hash": env_hash,
                "version": version,
                "ip": ip_address,
                "timestamp": datetime.utcnow().isoformat()
            })
            r.setex(key, 86400 * 365, json.dumps(data))
            r.zadd('canaries:triggered', {token: time.time()})

            # Update credential lure format
            lure_key = f"lure:sc_{token[:12]}"
            lure_raw = r.get(lure_key)
            if lure_raw:
                lure = json.loads(lure_raw)
                lure["triggered"] = True
                lure["trigger_count"] = lure.get("trigger_count", 0) + 1
                lure.setdefault("trigger_ips", []).append(ip_address)
                r.setex(lure_key, 86400 * 365, json.dumps(lure))

    # Telegram alert
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={
                    "chat_id": TELEGRAM_CHAT_ID,
                    "text": (
                        f"📦 <b>SUPPLY CHAIN CANARY FIRED</b>\n"
                        f"<b>Token:</b> <code>{token[:16]}</code>\n"
                        f"<b>IP:</b> <code>{ip_address}</code>\n"
                        f"<b>Env:</b> <code>{env_hash}</code>\n"
                        f"<b>Version:</b> {version}"
                    ),
                    "parse_mode": "HTML"
                },
                timeout=5
            )
        except Exception as e:
            logger.error(f"Supply chain canary Telegram alert failed: {e}")

# ────────────────────────────────────────────────────────────
# FLASK BLUEPRINT
# ────────────────────────────────────────────────────────────

supply_chain_bp = Blueprint('supply_chain_canary', __name__)

@supply_chain_bp.route('/api/supply-chain/beacon', methods=['GET'])
def receive_beacon():
    token = request.args.get('t', '')
    env_hash = request.args.get('e', 'unknown')
    version = request.args.get('v', 'unknown')
    ip_address = request.headers.get('X-Forwarded-For', request.remote_addr or '')
    ip_address = ip_address.split(',')[0].strip()

    if not token:
        return jsonify({"ok": False, "error": "Missing token"}), 400

    if _rate_limited(ip_address):
        return jsonify({"ok": False, "error": "Rate limit exceeded"}), 429

    report_beacon(token, env_hash, version, ip_address)
    return jsonify({"ok": True, "message": "Beacon received"}), 200

@supply_chain_bp.route('/api/supply-chain/canaries', methods=['GET'])
def list_canaries():
    try:

        if not is_logged_in() or not is_admin():
            return jsonify({"error": "Admin required"}), 403
    except ImportError:
        pass

    reg = load_registry()
    return jsonify({
        "ok": True,
        "count": len(reg.get("tokens", {})),
        "canaries": list(reg.get("tokens", {}).keys())[:50]
    })

@supply_chain_bp.route('/api/supply-chain/canary/<token>', methods=['GET'])
def get_canary(token):
    try:

        if not is_logged_in() or not is_admin():
            return jsonify({"error": "Admin required"}), 403
    except ImportError:
        pass

    r = _get_redis()
    if r:
        data = r.get(f"supply_chain_canary:{token}")
        if data:
            return jsonify({"ok": True, "canary": json.loads(data)})

    reg = load_registry()
    if token in reg.get("tokens", {}):
        return jsonify({"ok": True, "canary": reg["tokens"][token]})

    return jsonify({"error": "Token not found"}), 404

@supply_chain_bp.route('/api/supply-chain/scan', methods=['POST'])
def scan_endpoint():
    try:

        if not is_logged_in() or not is_admin():
            return jsonify({"error": "Admin required"}), 403
    except ImportError:
        pass

    data = request.get_json(silent=True) or {}
    path = data.get('path', '')
    if not path:
        return jsonify({"error": "path required"}), 400

    pkg_dir = Path(path)
    if not pkg_dir.exists():
        return jsonify({"error": "Path not found"}), 404

    results = scan_package(pkg_dir)
    return jsonify({"ok": True, "results": results})

# ────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────

def cli():
    if len(sys.argv) < 2:
        print("Usage: supply_chain_canary.py [scan|inject] <path>")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'scan':
        path = sys.argv[2] if len(sys.argv) > 2 else '.'
        results = scan_package(Path(path))
        print(json.dumps(results, indent=2))

    elif cmd == 'inject':
        path = sys.argv[2] if len(sys.argv) > 2 else '.'
        pkg = Path(path)
        token = generate_token(pkg.name, "1.0.0")
        inject_runtime_canary(pkg, token, "1.0.0", CANARY_DNS_DOMAIN or 'sc.example.com')
        inject_dns_canary_metadata(pkg, token, CANARY_DNS_DOMAIN or 'sc.example.com')
        inject_watermark(pkg, token)
        print(f"Token: {token}")

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == '__main__':
    cli()
