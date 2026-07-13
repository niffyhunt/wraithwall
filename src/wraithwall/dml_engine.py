import os
import re
import sys
import json
import time
import hmac
import hashlib
import secrets
import logging
import threading
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field, asdict

import yaml
import redis as redis_lib
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────

REDIS_URL = os.environ.get('REDIS_URL', '')
CRED_PROP_SECRET = os.environ.get('CRED_PROP_SECRET', '')
DML_VERSION = "0.2.0"

# Valid enums
TRIGGER_TYPES = {
    "http_request", "dns_resolution", "api_key_use", "file_access",
    "login_attempt", "data_access", "timing_probe", "canary_email", "jwt_use",
}

RESPONSE_TYPES = {
    "fake_data", "redirect_sandbox", "delay_response", "mirror_engage",
    "block_ip", "log_only", "alert_only", "honeypot_auth",
}

SEVERITY_LEVELS = {"critical", "high", "medium", "low", "info"}

MITRE_TACTICS = {
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "exfiltration", "command_and_control", "impact", "reconnaissance",
}

# ────────────────────────────────────────────────────────────
# DML DATA STRUCTURES
# ────────────────────────────────────────────────────────────

@dataclass
class DMLAlert:
    channels: list = field(default_factory=lambda: ["discord", "telegram"])
    include_ip: bool = True
    include_ua: bool = True
    include_headers: bool = False
    include_body_hash: bool = True
    throttle_seconds: int = 0

@dataclass
class DMLResponse:
    type: str = "log_only"
    delay_ms: Optional[int] = None
    fake_data_template: Optional[str] = None
    llm_prompt_override: Optional[str] = None
    llm_model: Optional[str] = None
    sandbox_reason: Optional[str] = None
    redirect_url: Optional[str] = None
    http_status: int = 200
    content_type: str = "application/json"

@dataclass
class DMLTrigger:
    type: str = "http_request"
    path: Optional[str] = None
    method: Optional[str] = None
    hostname: Optional[str] = None
    api_key_prefix: Optional[str] = None
    email: Optional[str] = None
    record_id: Optional[int] = None
    timing_target_ms: Optional[int] = None
    match_regex: Optional[str] = None

@dataclass
class DMLTrap:
    id: str
    name: str
    version: str = "0.2.0"
    namespace: str = "default"
    enabled: bool = True
    severity: str = "high"
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    description: str = ""
    tags: list = field(default_factory=list)
    trigger: DMLTrigger = field(default_factory=DMLTrigger)
    response: DMLResponse = field(default_factory=DMLResponse)
    alert: DMLAlert = field(default_factory=DMLAlert)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    author: str = ""
    plant_in: list = field(default_factory=list)
    signature: Optional[str] = None

    @property
    def fully_qualified_id(self) -> str:
        return f"{self.namespace}:{self.id}"

@dataclass
class DMLDocument:
    dml_version: str = DML_VERSION
    platform: str = ""
    namespace: str = ""
    description: str = ""
    author: str = ""
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    traps: list = field(default_factory=list)
    document_signature: Optional[str] = None

# ────────────────────────────────────────────────────────────
# DML VALIDATOR
# ────────────────────────────────────────────────────────────

class DMLValidationError(Exception):
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"DML validation error at '{field}': {message}")

class DMLValidator:
    """Validates‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ DML documents and individual traps."""

    def validate_document(self, doc: dict) -> list:
        errors = []
        if doc.get('dml_version') != DML_VERSION:
            errors.append(f"dml_version must be '{DML_VERSION}', got '{doc.get('dml_version')}'")
        if not doc.get('traps'):
            errors.append("Document must contain at least one trap")
        ids_seen = set()
        for i, trap in enumerate(doc.get('traps', [])):
            trap_errors = self.validate_trap(trap)
            for e in trap_errors:
                errors.append(f"traps[{i}].{e}")
            ns = trap.get('namespace', 'default')
            tid = trap.get('id', '')
            fqid = f"{ns}:{tid}"
            if fqid in ids_seen:
                errors.append(f"traps[{i}]: duplicate fully-qualified ID '{fqid}'")
            ids_seen.add(fqid)
        return errors

    def validate_trap(self, trap: dict) -> list:
        errors = []
        if not trap.get('id'):
            errors.append("id is required")
        elif not re.match(r'^[a-z0-9][a-z0-9\-]{1,48}[a-z0-9]$', trap['id']):
            errors.append("id must be lowercase alphanumeric with hyphens (3-50 chars)")
        if not trap.get('name'):
            errors.append("name is required")
        if trap.get('severity') and trap['severity'] not in SEVERITY_LEVELS:
            errors.append(f"severity must be one of: {SEVERITY_LEVELS}")
        if trap.get('mitre_tactic') and trap['mitre_tactic'] not in MITRE_TACTICS:
            errors.append(f"mitre_tactic must be one of: {MITRE_TACTICS}")

        trigger = trap.get('trigger', {})
        trigger_type = trigger.get('type')
        if not trigger_type:
            errors.append("trigger.type is required")
        elif trigger_type not in TRIGGER_TYPES:
            errors.append(f"trigger.type must be one of: {TRIGGER_TYPES}")
        else:
            if trigger_type == 'http_request' and not trigger.get('path'):
                errors.append("trigger.path required for http_request trigger")
            if trigger_type == 'dns_resolution' and not trigger.get('hostname'):
                errors.append("trigger.hostname required for dns_resolution trigger")
            if trigger_type == 'timing_probe' and not trigger.get('timing_target_ms'):
                errors.append("trigger.timing_target_ms required for timing_probe trigger")
            if trigger_type == 'canary_email' and not trigger.get('email'):
                errors.append("trigger.email required for canary_email trigger")

        response = trap.get('response', {})
        resp_type = response.get('type')
        if resp_type and resp_type not in RESPONSE_TYPES:
            errors.append(f"response.type must be one of: {RESPONSE_TYPES}")
        if resp_type == 'delay_response' and not response.get('delay_ms'):
            errors.append("response.delay_ms required for delay_response type")

        return errors

    def is_valid(self, doc: dict) -> bool:
        return len(self.validate_document(doc)) == 0

# ────────────────────────────────────────────────────────────
# DML SIGNER
# ────────────────────────────────────────────────────────────

class DMLSigner:
    """HMAC‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ signing for DML document tamper detection."""

    def __init__(self):
        self.secret = CRED_PROP_SECRET or secrets.token_hex(32)

    def sign_document(self, doc: dict) -> dict:
        signed = dict(doc)
        for trap in signed.get('traps', []):
            trap_copy = {k: v for k, v in trap.items() if k != 'signature'}
            trap['signature'] = self._sign_dict(trap_copy)

        doc_copy = {
            'dml_version': signed.get('dml_version'),
            'platform': signed.get('platform'),
            'namespace': signed.get('namespace'),
            'traps': [{k: v for k, v in t.items() if k != 'signature'} for t in signed.get('traps', [])]
        }
        signed['document_signature'] = self._sign_dict(doc_copy)
        return signed

    def verify_document(self, doc: dict) -> tuple:
        errors = []
        if 'document_signature' not in doc:
            errors.append("Missing document_signature")
            return False, errors

        doc_copy = {
            'dml_version': doc.get('dml_version'),
            'platform': doc.get('platform'),
            'namespace': doc.get('namespace'),
            'traps': [{k: v for k, v in t.items() if k != 'signature'} for t in doc.get('traps', [])]
        }
        if doc['document_signature'] != self._sign_dict(doc_copy):
            errors.append("Document signature mismatch — document may be tampered")
            return False, errors

        for i, trap in enumerate(doc.get('traps', [])):
            if 'signature' not in trap:
                errors.append(f"traps[{i}]: Missing signature")
                continue
            trap_copy = {k: v for k, v in trap.items() if k != 'signature'}
            if trap['signature'] != self._sign_dict(trap_copy):
                errors.append(f"traps[{i}]: Signature mismatch for '{trap.get('id', 'unknown')}'")

        return len(errors) == 0, errors

    def _sign_dict(self, d: dict) -> str:
        canonical = json.dumps(d, sort_keys=True, separators=(',', ':'))
        return hmac.new(self.secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()[:32]

# ────────────────────────────────────────────────────────────
# DML GENERATOR
# ────────────────────────────────────────────────────────────

class DMLGenerator:
    """Convert‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ EZMCyber DB objects to DML format."""

    def from_honey_token(self, token) -> dict:
        trigger_type = "http_request"
        path = None
        hostname = None

        tv = token.token_value
        if token.token_type == 'url':
            trigger_type = "http_request"
            path = tv
        elif token.token_type == 'api_key':
            trigger_type = "api_key_use"
        elif token.token_type == 'dns':
            trigger_type = "dns_resolution"
            hostname = tv
        elif token.token_type in ('reverse_canary', 'predictive_canary'):
            trigger_type = "http_request"
            path = tv

        resp_map = {
            'serve_fake_data': 'fake_data', 'delay_response': 'delay_response',
            'block_ip': 'block_ip', 'log_only': 'log_only',
        }

        return {
            "id": f"token-{token.id}",
            "name": token.description or f"Honey Token {token.id}",
            "version": DML_VERSION,
            "enabled": token.is_active,
            "severity": token.severity or "high",
            "description": token.description or "",
            "tags": [token.token_type],
            "trigger": {
                "type": trigger_type, "path": path, "hostname": hostname,
                "method": "ANY" if trigger_type == "http_request" else None,
            },
            "response": {
                "type": resp_map.get(token.response_action, 'log_only'),
                "http_status": 200 if token.response_action == 'serve_fake_data' else 403,
            },
            "alert": {"channels": ["discord", "telegram"], "include_ip": True, "include_ua": True},
            "created_at": token.created_at.isoformat() if hasattr(token, 'created_at') else datetime.utcnow().isoformat(),
        }

    def from_canary_record(self, canary) -> dict:
        trigger_map = {
            'fake_user': ('data_access', None),
            'quantum_user': ('data_access', None),
            'fake_api_key': ('api_key_use', None),
            'fake_session': ('http_request', '/api/sessions'),
            'reverse_canary': ('http_request', canary.description),
            'predictive_canary': ('http_request', None),
        }
        trigger_type, path = trigger_map.get(canary.canary_type, ('data_access', None))

        return {
            "id": f"canary-{canary.id}",
            "name": f"{canary.canary_type.replace('_', ' ').title()} #{canary.record_id}",
            "version": DML_VERSION,
            "enabled": canary.is_active,
            "severity": "critical" if 'quantum' in canary.canary_type else "high",
            "description": canary.description or "",
            "tags": ["canary", canary.table_name, canary.canary_type],
            "trigger": {"type": trigger_type, "path": path, "record_id": canary.record_id, "method": "ANY"},
            "response": {"type": "redirect_sandbox", "http_status": 200},
            "alert": {"channels": ["discord", "telegram"], "include_ip": True, "include_ua": True, "include_headers": True},
            "created_at": canary.created_at.isoformat() if hasattr(canary, 'created_at') else datetime.utcnow().isoformat(),
        }

    def export_platform_dml(self, honey_tokens: list, canary_records: list) -> dict:
        traps = []
        for token in honey_tokens:
            traps.append(self.from_honey_token(token))
        for canary in canary_records:
            traps.append(self.from_canary_record(canary))
        return {
            "dml_version": DML_VERSION,
            "platform": "ezmcyber",
            "namespace": "production",
            "description": "EZMCyber deception trap configuration",
            "author": "EZMCyber Platform",
            "created_at": datetime.utcnow().isoformat(),
            "traps": traps
        }

# ────────────────────────────────────────────────────────────
# DML DEPLOYER
# ────────────────────────────────────────────────────────────

class DMLDeployer:
    """Read DML documents and deploy traps to EZMCyber."""

    def __init__(self, app_context=None):
        self.app = app_context
        self.validator = DMLValidator()
        self._redis = self._get_redis()

    def _get_redis(self):
        if not REDIS_URL:
            return None
        try:
            return redis_lib.from_url(REDIS_URL, socket_connect_timeout=3,
                                      decode_responses=True, max_connections=5)
        except Exception:
            return None

    def deploy_document(self, doc: dict) -> dict:
        errors = self.validator.validate_document(doc)
        if errors:
            return {"ok": False, "errors": errors}

        report = {"ok": True, "deployed": [], "skipped": [], "failed": []}
        for trap in doc.get('traps', []):
            if not trap.get('enabled', True):
                report["skipped"].append({"id": trap['id'], "reason": "disabled"})
                continue
            try:
                result = self._deploy_trap(trap)
                if result["ok"]:
                    report["deployed"].append({"id": trap['id'], "type": result["type"]})
                    self._record_deployment(trap)
                else:
                    report["failed"].append({"id": trap['id'], "error": result["error"]})
            except Exception as e:
                report["failed"].append({"id": trap['id'], "error": str(e)})
        return report

    def _deploy_trap(self, trap: dict) -> dict:
        trigger = trap.get('trigger', {})
        response = trap.get('response', {})
        trigger_type = trigger.get('type')

        try:

            if trigger_type == 'http_request':
                path = trigger.get('path')
                if not path:
                    return {"ok": False, "error": "path required"}

                existing = HoneyToken.query.filter_by(token_value=path).first()
                if existing:
                    return {"ok": False, "error": f"Trap for path {path} already exists"}

                resp_action = {
                    'fake_data': 'serve_fake_data', 'redirect_sandbox': 'serve_fake_data',
                    'delay_response': 'delay_response', 'block_ip': 'block_ip',
                    'log_only': 'log_only',
                }.get(response.get('type', 'log_only'), 'log_only')

                token = HoneyToken(
                    token_type='dml_trap', token_value=path,
                    description=f"[DML:{trap['id']}] {trap.get('name', '')}",
                    severity=trap.get('severity', 'high'),
                    response_action=resp_action, is_active=True
                )
                db.session.add(token)
                db.session.flush()

                canary = CanaryRecord(
                    table_name='dml_trap', record_id=token.id,
                    canary_type='dml_imported',
                    description=f"DML trap: {trap['id']}"
                )
                db.session.add(canary)
                db.session.commit()

                write_immutable_log({
                    'event': 'dml_trap_deployed',
                    'trap_id': trap['id'],
                    'trigger_type': trigger_type,
                    'path': path
                })
                return {"ok": True, "type": "honey_token", "token_id": token.id}

            else:
                write_immutable_log({
                    'event': 'dml_trap_registered',
                    'trap_id': trap['id'],
                    'trigger_type': trigger_type,
                    'note': 'Manual deployment required for non-HTTP triggers'
                })
                return {"ok": True, "type": "registered", "note": "manual deployment required"}

        except ImportError:
            return {"ok": False, "error": "Not running inside EZMCyber app context"}

    def _record_deployment(self, trap: dict):
        if not self._redis:
            return
        fqid = f"{trap.get('namespace', 'default')}:{trap.get('id')}"
        self._redis.hset(f"dml_trap:{fqid}", mapping={
            "id": trap.get('id'),
            "name": trap.get('name', ''),
            "trigger_type": trap.get('trigger', {}).get('type', ''),
            "response_type": trap.get('response', {}).get('type', ''),
            "severity": trap.get('severity', ''),
            "deployed_at": datetime.utcnow().isoformat(),
            "trigger_count": 0,
            "last_triggered": "",
            "unique_ips": 0
        })
        self._redis.zadd('dml_traps:by_deployment', {fqid: time.time()})
        self._redis.sadd('deployed_traps:all', fqid)

    def record_trigger(self, trap_id: str, namespace: str = "default",
                       ip: str = "", tool: str = ""):
        if not self._redis:
            return
        fqid = f"{namespace}:{trap_id}"
        self._redis.hincrby(f"dml_trap:{fqid}", "trigger_count", 1)
        self._redis.hset(f"dml_trap:{fqid}", "last_triggered", datetime.utcnow().isoformat())
        if ip:
            self._redis.pfadd(f"dml_trap:{fqid}:ips", ip)
            self._redis.hset(f"dml_trap:{fqid}", "unique_ips",
                            self._redis.pfcount(f"dml_trap:{fqid}:ips"))
        if tool:
            self._redis.zincrby(f"dml_trap:{fqid}:tools", 1, tool)
        self._redis.zincrby('dml_traps:by_effectiveness', 1, fqid)

    def get_effectiveness_report(self) -> dict:
        if not self._redis:
            return {"ok": False, "error": "Redis unavailable"}
        top = self._redis.zrevrange('dml_traps:by_effectiveness', 0, 19, withscores=True)
        report = []
        for fqid, count in top:
            data = self._redis.hgetall(f"dml_trap:{fqid}")
            if data:
                tools = self._redis.zrevrange(f"dml_trap:{fqid}:tools", 0, 4, withscores=True)
                report.append({
                    "trap_id": fqid,
                    "name": data.get("name", ""),
                    "total_triggers": int(count),
                    "unique_ips": int(data.get("unique_ips", 0)),
                    "last_triggered": data.get("last_triggered", ""),
                    "top_tools": [{"tool": t, "count": int(c)} for t, c in tools],
                })
        return {
            "ok": True,
            "total_deployed": self._redis.scard('deployed_traps:all'),
            "most_effective": report
        }

# ────────────────────────────────────────────────────────────
# FLASK ROUTE REGISTRATION
# ────────────────────────────────────────────────────────────

def register_dml_routes(app):
    """Register DML routes on a Flask app."""

    @app.route('/api/dml/validate', methods=['POST'])
    def dml_validate():
        doc = request.get_json(silent=True)
        if not doc:
            return jsonify({"ok": False, "error": "JSON body required"}), 400
        validator = DMLValidator()
        errors = validator.validate_document(doc)
        return jsonify({
            "ok": len(errors) == 0,
            "valid": len(errors) == 0,
            "errors": errors,
            "trap_count": len(doc.get('traps', [])),
            "dml_version": doc.get('dml_version')
        })

    @app.route('/api/dml/schema', methods=['GET'])
    def dml_schema():
        return jsonify({
            "dml_version": DML_VERSION,
            "trigger_types": list(TRIGGER_TYPES),
            "response_types": list(RESPONSE_TYPES),
            "severity_levels": list(SEVERITY_LEVELS),
            "mitre_tactics": list(MITRE_TACTICS),
            "spec_url": "https://github.com/niffyhunt/dml-spec",
        })

    @app.route('/api/dml/export', methods=['GET'])
    def dml_export():
        try:

            if not is_logged_in() or not is_admin():
                return jsonify({"error": "Admin required"}), 403
        except ImportError:
            pass

        tokens = HoneyToken.query.filter_by(is_active=True).all()
        canaries = CanaryRecord.query.filter_by(is_active=True).all()
        gen = DMLGenerator()
        doc = gen.export_platform_dml(tokens, canaries)
        return jsonify(doc)

    @app.route('/api/dml/import', methods=['POST'])
    def dml_import():
        try:

            if not is_logged_in() or not is_admin():
                return jsonify({"error": "Admin required"}), 403
        except ImportError:
            pass

        doc = request.get_json(silent=True)
        if not doc:
            return jsonify({"ok": False, "error": "JSON body required"}), 400

        deployer = DMLDeployer(flask_app if 'flask_app' in dir() else None)
        report = deployer.deploy_document(doc)
        return jsonify(report), 200 if report["ok"] else 400

    @app.route('/api/dml/sign', methods=['POST'])
    def dml_sign():
        try:

            if not is_logged_in() or not is_admin():
                return jsonify({"error": "Admin required"}), 403
        except ImportError:
            pass

        doc = request.get_json(silent=True)
        if not doc:
            return jsonify({"ok": False, "error": "JSON body required"}), 400

        signer = DMLSigner()
        signed = signer.sign_document(doc)
        return jsonify({"ok": True, "signed_document": signed})

    @app.route('/api/dml/verify', methods=['POST'])
    def dml_verify():
        doc = request.get_json(silent=True)
        if not doc:
            return jsonify({"ok": False, "error": "JSON body required"}), 400

        signer = DMLSigner()
        valid, errors = signer.verify_document(doc)
        return jsonify({"ok": True, "valid": valid, "errors": errors})

    @app.route('/api/dml/effectiveness', methods=['GET'])
    def dml_effectiveness():
        try:

            if not is_logged_in() or not is_admin():
                return jsonify({"error": "Admin required"}), 403
        except ImportError:
            pass

        deployer = DMLDeployer()
        report = deployer.get_effectiveness_report()
        return jsonify(report)

# ────────────────────────────────────────────────────────────
# CLI
# ────────────────────────────────────────────────────────────

def cli():
    if len(sys.argv) < 2:
        print("Usage: dml_engine.py [validate|sign|verify|schema] [file]")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == 'schema':
        print(json.dumps({
            "dml_version": DML_VERSION,
            "trigger_types": list(TRIGGER_TYPES),
            "response_types": list(RESPONSE_TYPES),
            "severity_levels": list(SEVERITY_LEVELS),
        }, indent=2))

    elif cmd in ('validate', 'sign', 'verify'):
        if len(sys.argv) < 3:
            print(f"Usage: dml_engine.py {cmd} <file.json|file.yaml>")
            sys.exit(1)

        filepath = sys.argv[2]
        try:
            with open(filepath) as f:
                if filepath.endswith(('.yaml', '.yml')):
                    doc = yaml.safe_load(f)
                else:
                    doc = json.load(f)
        except FileNotFoundError:
            print(f"File not found: {filepath}")
            sys.exit(1)
        except (json.JSONDecodeError, yaml.YAMLError) as e:
            print(f"Parse error: {e}")
            sys.exit(1)

        if cmd == 'validate':
            validator = DMLValidator()
            errors = validator.validate_document(doc)
            if not errors:
                print(f"✅ Valid DML document ({len(doc.get('traps', []))} traps)")
            else:
                print(f"❌ Invalid — {len(errors)} errors:")
                for e in errors:
                    print(f"   • {e}")
                sys.exit(1)

        elif cmd == 'sign':
            signer = DMLSigner()
            signed = signer.sign_document(doc)
            print(json.dumps(signed, indent=2))

        elif cmd == 'verify':
            signer = DMLSigner()
            valid, errors = signer.verify_document(doc)
            if valid:
                print("✅ Document signature valid")
            else:
                print(f"❌ Verification failed:")
                for e in errors:
                    print(f"   • {e}")
                sys.exit(1)

    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)

if __name__ == '__main__':
    cli()
