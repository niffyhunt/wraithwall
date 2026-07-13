import os
import re
import json
import time
import base64
import hashlib
import hmac
import secrets
import logging
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Set
from collections import Counter, defaultdict
from enum import Enum

import requests
import redis as redis_lib
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────

REDIS_URL = os.environ.get('REDIS_URL', '')
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')
GITLAB_TOKEN = os.environ.get('GITLAB_TOKEN', '')
PASTEBIN_API_KEY = os.environ.get('PASTEBIN_API_KEY', '')
HONEYPOT_SSH_IP = os.environ.get('HONEYPOT_SSH_IP', '')
HONEYPOT_SSH_PORT = int(os.environ.get('HONEYPOT_SSH_PORT', '22'))
CRED_PROP_SECRET = os.environ.get('CRED_PROP_SECRET', '')
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')

MAX_ACTIVE_LURES = int(os.environ.get('MAX_ACTIVE_LURES', '50'))
LURE_TRACKING_TTL = int(os.environ.get('LURE_TRACKING_TTL', '7776000'))
LURE_REFRESH_INTERVAL = int(os.environ.get('LURE_REFRESH_INTERVAL', '3600'))
LURE_WEEKLY_PASTEBIN_INTERVAL = int(os.environ.get('LURE_WEEKLY_PASTEBIN_INTERVAL', str(7 * 86400)))
ENABLE_WEEKLY_PASTEBIN = os.environ.get('ENABLE_WEEKLY_PASTEBIN', 'true').lower() == 'true'
AUTO_ROTATION = os.environ.get('ENABLE_AUTO_ROTATION', 'true').lower() == 'true'

if not CRED_PROP_SECRET:
    CRED_PROP_SECRET = base64.b64encode(secrets.token_bytes(32)).decode()
    logger.warning("CRED_PROP_SECRET not set — generated ephemeral key (lures will change on restart)")

# ────────────────────────────────────────────────────────────
# CREDENTIAL TYPES
# ────────────────────────────────────────────────────────────

class CredentialType(Enum):
    SSH_ACCESS = "ssh_access"
    AWS_IAM = "aws_iam"
    DATABASE = "database"
    API_KEY = "api_key"
    DOCKER_REGISTRY = "docker_registry"
    KUBERNETES = "kubernetes"

# Reserved test prefixes for legal compliance
AWS_TEST_PREFIX = "AKIA"
STRIPE_TEST_PREFIX = "sk_test_"

USERNAME_POOLS = {
    'admin': ['admin', 'root', 'superuser', 'administrator', 'sysadmin'],
    'service': ['deploy', 'jenkins', 'gitlab-runner', 'ansible', 'terraform'],
    'cloud': ['ec2-user', 'ubuntu', 'centos', 'debian', 'fedora'],
    'database': ['postgres', 'mysql', 'mongodb', 'redis', 'elasticsearch'],
}

# ────────────────────────────────────────────────────────────
# CREDENTIAL GENERATOR
# ────────────────────────────────────────────────────────────

class CredentialGenerator:
    """Cryptographically‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ secure, deterministic credential generation."""

    @classmethod
    def generate(cls, lure_id: str, types: List[CredentialType] = None) -> Dict[str, Any]:
        if types is None:
            types = [CredentialType.SSH_ACCESS, CredentialType.AWS_IAM,
                     CredentialType.DATABASE, CredentialType.API_KEY]

        seed = hashlib.pbkdf2_hmac(
            'sha256',
            CRED_PROP_SECRET.encode(),
            lure_id.encode(),
            100000,
            dklen=64
        )

        creds = {
            'lure_id': lure_id,
            'generated_at': datetime.utcnow().isoformat(),
            'honeypot_id': hashlib.sha256(f"honeypot-{lure_id}".encode()).hexdigest()[:12]
        }

        if CredentialType.SSH_ACCESS in types:
            creds['ssh_access'] = cls._ssh_credentials(lure_id, seed)
        if CredentialType.AWS_IAM in types:
            creds['aws_iam'] = cls._aws_credentials(lure_id, seed)
        if CredentialType.DATABASE in types:
            creds['database'] = cls._database_credentials(lure_id, seed)
        if CredentialType.API_KEY in types:
            creds['api_key'] = cls._api_credentials(lure_id, seed)
        if CredentialType.DOCKER_REGISTRY in types:
            creds['docker_registry'] = cls._docker_credentials(lure_id, seed)
        if CredentialType.KUBERNETES in types:
            creds['kubernetes'] = cls._k8s_credentials(lure_id, seed)

        return creds

    @classmethod
    def _ssh_credentials(cls, lure_id: str, seed: bytes) -> Dict:
        idx = int(hashlib.sha256(seed[:16] + b'ssh-username').hexdigest()[:8], 16)
        categories = list(USERNAME_POOLS.keys())
        cat = categories[idx % len(categories)]
        username = USERNAME_POOLS[cat][idx % len(USERNAME_POOLS[cat])]

        pw_bytes = hashlib.pbkdf2_hmac('sha256', seed[16:32] + b'ssh-pass', lure_id.encode(), 50000, dklen=24)
        password = base64.b64encode(pw_bytes).decode()[:20].replace('/', 'x')

        return {
            'host': HONEYPOT_SSH_IP or '127.0.0.1',
            'port': HONEYPOT_SSH_PORT,
            'username': username,
            'password': password,
            'connection_string': f"ssh {username}@{HONEYPOT_SSH_IP or '127.0.0.1'} -p {HONEYPOT_SSH_PORT}"
        }

    @classmethod
    def _aws_credentials(cls, lure_id: str, seed: bytes) -> Dict:
        key_bytes = hashlib.sha256(seed[:32] + b'aws-key').digest()[:16]
        access_key = AWS_TEST_PREFIX + base64.b32encode(key_bytes).decode()[:16]
        secret = base64.b64encode(
            hashlib.pbkdf2_hmac('sha256', seed[32:] + b'aws-secret', lure_id.encode(), 50000, dklen=40)
        ).decode()[:40]
        return {
            'access_key_id': access_key,
            'secret_access_key': secret,
            'region': 'us-east-1',
            'is_test_key': True
        }

    @classmethod
    def _database_credentials(cls, lure_id: str, seed: bytes) -> Dict:
        db_pass = base64.b64encode(hashlib.sha256(seed + b'db-pass').digest()).decode()[:16]
        db_pass = db_pass.replace('/', 'x')
        host = HONEYPOT_SSH_IP or '127.0.0.1'
        return {
            'primary': f"postgresql://admin:{db_pass}@{host}:5432/production",
            'mysql': f"mysql://root:{db_pass}@{host}:3306/mysql",
            'mongodb': f"mongodb://admin:{db_pass}@{host}:27017/admin",
            'redis': f"redis://:{db_pass}@{host}:6379/0",
            'host': host,
            'password': db_pass
        }

    @classmethod
    def _api_credentials(cls, lure_id: str, seed: bytes) -> Dict:
        api_key = f"{STRIPE_TEST_PREFIX}{base64.b32encode(seed[:20]).decode()[:24].lower()}"
        secret = hashlib.sha256(seed + b'api-secret').hexdigest()[:32]
        return {
            'stripe_test_key': api_key,
            'api_key': hashlib.sha256(seed + b'api-key').hexdigest()[:32],
            'api_secret': secret,
            'endpoint': f"https://{HONEYPOT_SSH_IP or '127.0.0.1'}/api/v1"
        }

    @classmethod
    def _docker_credentials(cls, lure_id: str, seed: bytes) -> Dict:
        pw = base64.b64encode(hashlib.sha256(seed + b'docker').digest()).decode()[:16]
        host = HONEYPOT_SSH_IP or '127.0.0.1'
        return {
            'registry': f"{host}:5000",
            'username': 'admin',
            'password': pw,
            'auth': base64.b64encode(f'admin:{pw}'.encode()).decode()
        }

    @classmethod
    def _k8s_credentials(cls, lure_id: str, seed: bytes) -> Dict:
        host = HONEYPOT_SSH_IP or '127.0.0.1'
        return {
            'api_server': f"https://{host}:6443",
            'token': base64.b64encode(seed[:32]).decode(),
            'namespace': 'production'
        }

# ────────────────────────────────────────────────────────────
# FORMAT GENERATORS
# ────────────────────────────────────────────────────────────

class CredentialFormatter:
    """Formats‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ credentials for different output formats."""

    @staticmethod
    def as_env_file(creds: Dict) -> str:
        ssh = creds.get('ssh_access', {})
        aws = creds.get('aws_iam', {})
        db = creds.get('database', {})
        api = creds.get('api_key', {})

        return f"""# Production Environment Configuration
# Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

# SSH Access
SSH_HOST={ssh.get('host', '')}
SSH_PORT={ssh.get('port', 22)}
SSH_USER={ssh.get('username', '')}
SSH_PASS={ssh.get('password', '')}

# AWS Credentials
AWS_ACCESS_KEY_ID={aws.get('access_key_id', '')}
AWS_SECRET_ACCESS_KEY={aws.get('secret_access_key', '')}
AWS_DEFAULT_REGION={aws.get('region', 'us-east-1')}

# Database
DATABASE_URL={db.get('primary', '')}
REDIS_URL={db.get('redis', '')}

# API
API_KEY={api.get('api_key', '')}
API_SECRET={api.get('api_secret', '')}
STRIPE_SECRET_KEY={api.get('stripe_test_key', '')}
"""

    @staticmethod
    def as_config_json(creds: Dict) -> str:
        ssh = creds.get('ssh_access', {})
        aws = creds.get('aws_iam', {})
        db = creds.get('database', {})

        return json.dumps({
            "environment": "production",
            "infrastructure": {
                "ssh": {
                    "host": ssh.get('host'),
                    "user": ssh.get('username'),
                    "password": ssh.get('password')
                },
                "aws": {
                    "access_key": aws.get('access_key_id'),
                    "secret_key": aws.get('secret_access_key')
                },
                "databases": {
                    "postgresql": db.get('primary'),
                    "redis": db.get('redis')
                }
            }
        }, indent=2)

    @staticmethod
    def as_docker_compose(creds: Dict) -> str:
        ssh = creds.get('ssh_access', {})
        db = creds.get('database', {})
        return f"""version: '3.8'
services:
  app:
    environment:
      - SSH_HOST={ssh.get('host')}
      - SSH_USER={ssh.get('username')}
      - SSH_PASS={ssh.get('password')}
      - DATABASE_URL={db.get('primary')}
      - REDIS_URL={db.get('redis')}
"""

    @staticmethod
    def as_terraform(creds: Dict) -> str:
        ssh = creds.get('ssh_access', {})
        aws = creds.get('aws_iam', {})
        db = creds.get('database', {})
        return f"""variable "ssh_host" {{ default = "{ssh.get('host')}" }}
variable "ssh_user" {{ default = "{ssh.get('username')}" }}
variable "ssh_password" {{ default = "{ssh.get('password')}" sensitive = true }}
variable "aws_access_key" {{ default = "{aws.get('access_key_id')}" }}
variable "aws_secret_key" {{ default = "{aws.get('secret_access_key')}" sensitive = true }}
variable "database_password" {{ default = "{db.get('password')}" sensitive = true }}
"""

# ────────────────────────────────────────────────────────────
# MULTI-PLATFORM SEEDER
# ────────────────────────────────────────────────────────────

class PlatformSeeder:
    """Seeds‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ credentials across multiple platforms."""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'Mozilla/5.0 (compatible; HoneypotCredentialPropagation/2.0)'

    def seed_github_gist(self, creds: Dict, formatter: str = 'env') -> Optional[Dict]:
        if not GITHUB_TOKEN:
            return None

        formatters = {
            'env': CredentialFormatter.as_env_file,
            'json': CredentialFormatter.as_config_json,
            'docker': CredentialFormatter.as_docker_compose,
            'terraform': CredentialFormatter.as_terraform,
        }
        fmt = formatters.get(formatter, formatters['env'])
        content = fmt(creds)

        filenames = {
            'env': ['.env', '.env.production', 'config.env', 'prod.env'],
            'json': ['config.json', 'production.json', 'settings.json'],
            'docker': ['docker-compose.yml', 'docker-compose.prod.yml'],
            'terraform': ['terraform.tfvars', 'production.tfvars'],
        }
        filename = secrets.choice(filenames.get(formatter, filenames['env']))

        payload = {
            "description": secrets.choice([
                "Production configuration", "Deployment config",
                "Infrastructure settings", "Backup config"
            ]),
            "public": True,
            "files": {filename: {"content": content}}
        }

        try:
            self.session.headers['Authorization'] = f"token {GITHUB_TOKEN}"
            resp = self.session.post("https://api.github.com/gists", json=payload, timeout=15)
            if resp.status_code == 201:
                gist = resp.json()
                return {
                    'platform': 'github_gist',
                    'gist_id': gist['id'],
                    'url': gist['html_url'],
                    'filename': filename,
                    'formatter': formatter,
                }
            logger.error(f"GitHub gist creation failed: {resp.status_code}")
        except Exception as e:
            logger.error(f"GitHub seed error: {e}")
        return None

    def seed_gitlab_snippet(self, creds: Dict) -> Optional[Dict]:
        if not GITLAB_TOKEN:
            return None

        content = CredentialFormatter.as_env_file(creds)
        payload = {
            "title": f"Production config — {datetime.utcnow().strftime('%Y-%m-%d')}",
            "file_name": ".env.production",
            "content": content,
            "visibility": "public",
            "description": "Infrastructure configuration"
        }
        try:
            self.session.headers['PRIVATE-TOKEN'] = GITLAB_TOKEN
            resp = self.session.post("https://gitlab.com/api/v4/snippets", json=payload, timeout=15)
            if resp.status_code == 201:
                snippet = resp.json()
                return {
                    'platform': 'gitlab_snippet',
                    'snippet_id': str(snippet['id']),
                    'url': snippet['web_url']
                }
        except Exception as e:
            logger.error(f"GitLab seed error: {e}")
        return None

    def seed_paste(self, creds: Dict, service: str = 'dpaste') -> Optional[Dict]:
        content = CredentialFormatter.as_env_file(creds)
        if service == 'dpaste':
            try:
                resp = self.session.post(
                    "https://dpaste.com/api/v2/",
                    data={"content": content, "syntax": "text", "expiry_days": 30,
                          "title": f"config-{datetime.utcnow().strftime('%Y%m%d')}"},
                    timeout=15
                )
                if resp.status_code == 201:
                    return {'platform': 'dpaste', 'url': resp.text.strip()}
            except Exception as e:
                logger.error(f"DPaste seed error: {e}")
        elif service == 'hastebin':
            try:
                resp = self.session.post(
                    "https://hastebin.com/documents",
                    data=content,
                    headers={'Content-Type': 'text/plain'},
                    timeout=15
                )
                if resp.status_code == 200:
                    key = resp.json().get('key')
                    return {'platform': 'hastebin', 'paste_key': key, 'url': f"https://hastebin.com/{key}"}
            except Exception as e:
                logger.error(f"Hastebin seed error: {e}")
        elif service == 'pastebin':
            if not PASTEBIN_API_KEY:
                logger.warning("PASTEBIN_API_KEY not set — cannot seed Pastebin")
                return None
            try:
                resp = self.session.post(
                    "https://pastebin.com/api/api_post.php",
                    data={
                        "api_option": "paste",
                        "api_dev_key": PASTEBIN_API_KEY,
                        "api_paste_code": content,
                        "api_paste_private": "1",
                        "api_paste_name": f"config-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.env",
                        "api_paste_expire_date": "1M",
                        "api_paste_format": "text"
                    },
                    timeout=15
                )
                url = resp.text.strip()
                if url.startswith("https://pastebin.com/"):
                    return {'platform': 'pastebin', 'url': url}
                logger.error(f"Pastebin seed failed: {url}")
            except Exception as e:
                logger.error(f"Pastebin seed error: {e}")
        return None

    def delete_github_gist(self, gist_id: str) -> bool:
        if not GITHUB_TOKEN:
            return False
        try:
            self.session.headers['Authorization'] = f"token {GITHUB_TOKEN}"
            resp = self.session.delete(f"https://api.github.com/gists/{gist_id}", timeout=10)
            return resp.status_code == 204
        except Exception:
            return False

# ────────────────────────────────────────────────────────────
# PROPAGATION NETWORK
# ────────────────────────────────────────────────────────────

class CredentialPropagationNetwork:
    """Manages complete credential lure lifecycle."""

    def __init__(self):
        self.redis = self._connect_redis()
        self.generator = CredentialGenerator()
        self.formatter = CredentialFormatter()
        self.seeder = PlatformSeeder()
        self._rotation_thread = None
        self._running = False
        self.lock = threading.RLock()

        self.metrics = defaultdict(int)

    def _connect_redis(self):
        if not REDIS_URL:
            return None
        for attempt in range(3):
            try:
                r = redis_lib.from_url(
                    REDIS_URL,
                    socket_connect_timeout=5,
                    socket_keepalive=True,
                    retry_on_timeout=True,
                    decode_responses=True,
                    max_connections=10
                )
                r.ping()
                return r
            except Exception as e:
                logger.warning(f"Redis attempt {attempt + 1}: {e}")
                time.sleep(2)
        return None

    @staticmethod
    def lure_id_for_username(username: str, max_tries: int = 10000) -> Optional[str]:
        for _ in range(max_tries):
            lid = secrets.token_hex(16)
            creds = CredentialGenerator.generate(lid, [CredentialType.SSH_ACCESS])
            if creds.get('ssh_access', {}).get('username') == username:
                return lid
        return None

    def plant_lure(self, platforms: List[str] = None,
                   cred_types: List[CredentialType] = None,
                   lure_id: Optional[str] = None) -> Optional[Dict]:
        if platforms is None:
            platforms = ['github_gist']
        if cred_types is None:
            cred_types = list(CredentialType)

        lure_id = lure_id or secrets.token_hex(16)
        creds = self.generator.generate(lure_id, cred_types)

        planted = []
        for platform in platforms:
            if platform == 'github_gist':
                fmt = secrets.choice(['env', 'json', 'docker', 'terraform'])
                result = self.seeder.seed_github_gist(creds, fmt)
            elif platform == 'gitlab_snippet':
                result = self.seeder.seed_gitlab_snippet(creds)
            elif platform in ('dpaste', 'hastebin', 'pastebin'):
                result = self.seeder.seed_paste(creds, platform)
            else:
                continue
            if result:
                planted.append(result)

        if not planted:
            return None

        lure = {
            'lure_id': lure_id,
            'platforms': planted,
            'credentials': creds,
            'planted_at': datetime.utcnow().isoformat(),
            'triggered': False,
            'trigger_count': 0,
            'trigger_ips': [],
            'exposure_metrics': {
                'total_triggers': 0,
                'unique_ips': [],
                'trigger_types': {},
                'first_trigger': None,
                'last_trigger': None
            }
        }

        self._store_lure(lure)
        self.metrics['lures_planted'] += 1
        logger.info(f"Lure {lure_id} planted on {len(planted)} platforms")
        return lure

    def _store_lure(self, lure: Dict):
        if not self.redis:
            return
        lid = lure['lure_id']
        self.redis.setex(f"lure:{lid}", LURE_TRACKING_TTL, json.dumps(lure))
        self.redis.zadd('lures:active', {lid: time.time()})

        # Maintain max active lures
        count = self.redis.zcard('lures:active')
        if count > MAX_ACTIVE_LURES:
            remove = count - MAX_ACTIVE_LURES
            oldest = self.redis.zrange('lures:active', 0, remove - 1)
            for old_id in oldest:
                self.redis.delete(f"lure:{old_id}")
                self.redis.zrem('lures:active', old_id)

    def record_trigger(self, lure_id: str, trigger_data: Dict):
        """Record that a lure was triggered. Called by cowrie_intelligence."""
        if not self.redis:
            return

        with self.lock:
            raw = self.redis.get(f"lure:{lure_id}")
            if not raw:
                return

            lure = json.loads(raw)
            lure['triggered'] = True
            lure['trigger_count'] = lure.get('trigger_count', 0) + 1
            lure['last_trigger_at'] = datetime.utcnow().isoformat()

            if not lure.get('first_trigger_at'):
                lure['first_trigger_at'] = datetime.utcnow().isoformat()

            src_ip = trigger_data.get('ip', 'unknown')
            ips = lure.get('trigger_ips', [])
            if src_ip not in ips:
                ips.append(src_ip)
            lure['trigger_ips'] = ips[:100]

            metrics = lure.get('exposure_metrics', {})
            metrics['total_triggers'] = metrics.get('total_triggers', 0) + 1
            unique = set(metrics.get('unique_ips', []))
            unique.add(src_ip)
            metrics['unique_ips'] = list(unique)
            ttypes = metrics.get('trigger_types', {})
            ttype = trigger_data.get('type', 'unknown')
            ttypes[ttype] = ttypes.get(ttype, 0) + 1
            lure['exposure_metrics'] = metrics

            self.redis.setex(f"lure:{lure_id}", LURE_TRACKING_TTL, json.dumps(lure))
            self.redis.zadd('lures:triggered', {lure_id: time.time()})

            self.metrics['total_triggers'] += 1

            planted_at = datetime.fromisoformat(lure['planted_at'])
            exposure_hours = (datetime.utcnow() - planted_at).total_seconds() / 3600
            logger.warning(f"Lure {lure_id} triggered by {src_ip} — exposure: {exposure_hours:.1f}h")
            try:
                from deception_event_bus import publish_deception_event
                publish_deception_event(
                    'credential_propagation', 'C-06', 'credential_lure',
                    trigger_data.get('type', 'credential_use'), src_ip,
                    context={'lure_id': lure_id, 'platform': lure.get('platform')},
                    bait_layer=2,
                )
            except Exception:
                pass
            self._notify_trigger(lure, trigger_data, exposure_hours)

    def get_stats(self) -> Dict:
        if not self.redis:
            return {}
        active = self.redis.zcard('lures:active')
        triggered = self.redis.zcard('lures:triggered')
        return {
            'active_lures': active,
            'triggered_lures': triggered,
            'trigger_rate': (triggered / max(active, 1)) * 100,
            'total_planted': self.metrics['lures_planted'],
            'total_triggers': self.metrics['total_triggers']
        }

    def _notify_trigger(self, lure: Dict, trigger_data: Dict, exposure_hours: float):
        if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
            return
        platforms = [p.get('platform', '') for p in lure.get('platforms', [])]
        msg = (
            f"🎯 <b>CREDENTIAL LURE TRIGGERED</b>\n"
            f"<b>Lure:</b> <code>{lure['lure_id'][:16]}</code>\n"
            f"<b>Platforms:</b> {', '.join(platforms)}\n"
            f"<b>IP:</b> <code>{trigger_data.get('ip', 'unknown')}</code>\n"
            f"<b>Exposure:</b> {exposure_hours:.1f}h\n"
            f"<b>Total Triggers:</b> {lure['trigger_count']}"
        )
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"},
                timeout=5
            )
        except Exception as e:
            logger.error(f"Credential lure Telegram alert failed: {e}")

    def _maybe_weekly_pastebin(self):
        if not ENABLE_WEEKLY_PASTEBIN or not self.redis:
            return
        key = 'lures:last_weekly_pastebin'
        now = time.time()
        last = self.redis.get(key)
        if last and (now - float(last)) < LURE_WEEKLY_PASTEBIN_INTERVAL:
            return
        lure = self.plant_lure(platforms=['pastebin'])
        if lure:
            self.redis.set(key, str(now))
            logger.info(f"Weekly Pastebin lure planted: {lure['lure_id'][:16]}")

    def auto_rotate(self):
        while self._running:
            try:
                if self.redis:
                    self._maybe_weekly_pastebin()
                    active = self.redis.zcard('lures:active')
                    if active < MAX_ACTIVE_LURES * 0.8:
                        platforms = ['github_gist']
                        roll = secrets.randbelow(100)
                        if roll < 30:
                            platforms.append('hastebin')
                        if roll < 20:
                            platforms.append('pastebin')
                        if roll < 10:
                            platforms.append('dpaste')
                        self.plant_lure(platforms)
                time.sleep(LURE_REFRESH_INTERVAL)
            except Exception as e:
                logger.error(f"Auto-rotation error: {e}")
                time.sleep(60)

    def start(self):
        if self._running:
            return
        self._running = True
        if AUTO_ROTATION:
            self._rotation_thread = threading.Thread(target=self.auto_rotate, daemon=True)
            self._rotation_thread.start()
        logger.info("Credential propagation network started")

    def stop(self):
        self._running = False
        if self._rotation_thread:
            self._rotation_thread.join(timeout=5)

# ────────────────────────────────────────────────────────────
# COWRIE INTEGRATION
# ────────────────────────────────────────────────────────────

def check_cowrie_login_for_lure(username: str, password: str, src_ip: str):
    """Called by cowrie_intelligence on login events."""
    try:
        network = get_network()
        if not network.redis:
            return

        active = network.redis.zrange('lures:active', 0, -1)
        for lid in active:
            raw = network.redis.get(f"lure:{lid}")
            if not raw:
                continue
            lure = json.loads(raw)
            ssh = lure.get('credentials', {}).get('ssh_access', {})
            if ssh.get('username') == username and ssh.get('password') == password:
                network.record_trigger(lid, {
                    'type': 'ssh_login',
                    'ip': src_ip,
                    'username': username,
                    'timestamp': datetime.utcnow().isoformat()
                })
                return
    except Exception as e:
        logger.error(f"Lure check error: {e}")

# ────────────────────────────────────────────────────────────
# SINGLETON
# ────────────────────────────────────────────────────────────

_network: Optional[CredentialPropagationNetwork] = None
_network_lock = threading.Lock()

def get_network() -> CredentialPropagationNetwork:
    global _network
    if _network is None:
        with _network_lock:
            if _network is None:
                _network = CredentialPropagationNetwork()
    return _network

def start_propagation_network():
    get_network().start()

# ────────────────────────────────────────────────────────────
# FLASK BLUEPRINT
# ────────────────────────────────────────────────────────────

cred_prop_bp = Blueprint('cred_propagation', __name__)

def _require_admin():
    try:

        if not is_logged_in() or not is_admin():
            return jsonify({"error": "Admin authentication required"}), 403
    except ImportError:
        pass
    return None

@cred_prop_bp.route('/api/lures', methods=['GET'])
def list_lures():
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    network = get_network()
    if not network.redis:
        return jsonify({"error": "Redis unavailable"}), 503

    lure_ids = network.redis.zrange('lures:active', 0, -1, desc=True)
    lures = []
    for lid in lure_ids[:50]:
        raw = network.redis.get(f"lure:{lid}")
        if raw:
            lure = json.loads(raw)
            lure.pop('credentials', None)
            lures.append(lure)

    return jsonify({"ok": True, "count": len(lures), "lures": lures})

@cred_prop_bp.route('/api/lures/plant', methods=['POST'])
def plant_lure():
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    data = request.get_json(silent=True) or {}
    platforms = data.get('platforms', ['github_gist'])
    network = get_network()
    lure_id = None
    target_user = data.get('target_username')
    if target_user:
        lure_id = CredentialPropagationNetwork.lure_id_for_username(str(target_user)[:64])
        if not lure_id:
            return jsonify({"error": f"Could not derive lure for username {target_user}"}), 400
    lure = network.plant_lure(platforms, lure_id=lure_id)

    if not lure:
        return jsonify({"error": "Planting failed"}), 500

    safe = {k: v for k, v in lure.items() if k != 'credentials'}
    return jsonify({"ok": True, "lure": safe})

@cred_prop_bp.route('/api/lures/stats', methods=['GET'])
def lure_stats():
    auth_err = _require_admin()
    if auth_err:
        return auth_err
    return jsonify({"ok": True, "stats": get_network().get_stats()})

@cred_prop_bp.route('/api/lures/<lure_id>', methods=['DELETE'])
def delete_lure(lure_id):
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    network = get_network()
    if not network.redis:
        return jsonify({"error": "Redis unavailable"}), 503

    raw = network.redis.get(f"lure:{lure_id}")
    if not raw:
        return jsonify({"error": "Lure not found"}), 404

    lure = json.loads(raw)
    for platform in lure.get('platforms', []):
        if platform.get('platform') == 'github_gist' and platform.get('gist_id'):
            network.seeder.delete_github_gist(platform['gist_id'])

    network.redis.delete(f"lure:{lure_id}")
    network.redis.zrem('lures:active', lure_id)
    network.redis.zrem('lures:triggered', lure_id)

    return jsonify({"ok": True, "message": f"Lure {lure_id} deleted"})
