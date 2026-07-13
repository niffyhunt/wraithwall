import os
import re
import json
import time
import math
import hashlib
import logging
import ipaddress
import threading
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Set, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, field, asdict
from enum import Enum
import concurrent.futures

import requests
import redis as redis_lib
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────

REDIS_URL = os.environ.get('REDIS_URL', '')
IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN', '')
ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY', '')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
WHOISXML_API_KEY = os.environ.get('WHOISXML_API_KEY', '')
RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
ABUSE_REPORT_FROM = os.environ.get('ABUSE_REPORT_FROM', '')
AUTO_ABUSE_REPORT = os.environ.get('AUTO_ABUSE_REPORT', 'false').lower() == 'true'
ASN_REPORT_THRESHOLD = int(os.environ.get('ASN_REPORT_THRESHOLD', '5'))
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')

IP_ENRICHMENT_TTL = int(os.environ.get('IP_ENRICHMENT_TTL', '604800'))
ASN_STATS_TTL = int(os.environ.get('ASN_STATS_TTL', '86400'))

KARMA_FREQ_WEIGHT = float(os.environ.get('KARMA_FREQ_WEIGHT', '0.25'))
KARMA_SEV_WEIGHT = float(os.environ.get('KARMA_SEV_WEIGHT', '0.30'))
KARMA_RECENCY_WEIGHT = float(os.environ.get('KARMA_RECENCY_WEIGHT', '0.25'))
KARMA_DIVERSITY_WEIGHT = float(os.environ.get('KARMA_DIVERSITY_WEIGHT', '0.20'))
KARMA_HALF_LIFE_DAYS = int(os.environ.get('KARMA_HALF_LIFE_DAYS', '30'))

# ────────────────────────────────────────────────────────────
# DATA MODELS
# ────────────────────────────────────────────────────────────

class RiskLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class IPIntelligence:
    ip: str
    enriched_at: str = ""
    private: bool = False
    asn: Optional[str] = None
    asn_name: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    country: Optional[str] = None
    country_code: Optional[str] = None
    city: Optional[str] = None
    is_hosting: bool = False
    hosting_provider: Optional[str] = None
    hosting_confidence: float = 0.0
    is_vpn: bool = False
    is_tor: bool = False
    is_proxy: bool = False
    abuse_score: int = 0
    abuse_reports: int = 0
    abuse_contact: Optional[str] = None
    abuse_contact_source: Optional[str] = None
    rdns: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    risk_level: RiskLevel = RiskLevel.LOW
    risk_score: float = 0.0
    confidence: float = 0.0
    sources: List[str] = field(default_factory=list)
    cached: bool = False
    bgp_hijack_risk: bool = False
    bgp_hijack_info: Optional[Dict] = None

# ────────────────────────────────────────────────────────────
# KNOWN HOSTING/CLOUD ASNs
# ────────────────────────────────────────────────────────────

HOSTING_ASNS = {
    'AS14061':   {'name': 'DigitalOcean', 'confidence': 0.99},
    'AS16276':   {'name': 'OVH', 'confidence': 0.99},
    'AS24940':   {'name': 'Hetzner', 'confidence': 0.99},
    'AS51167':   {'name': 'Contabo', 'confidence': 0.95},
    'AS20473':   {'name': 'Vultr', 'confidence': 0.99},
    'AS8100':    {'name': 'QuadraNet', 'confidence': 0.90},
    'AS46844':   {'name': 'SharkTech', 'confidence': 0.85},
    'AS9009':    {'name': 'M247', 'confidence': 0.85},
    'AS136907':  {'name': 'Huawei Cloud', 'confidence': 0.90},
    'AS45090':   {'name': 'Tencent Cloud', 'confidence': 0.95},
    'AS37963':   {'name': 'Alibaba Cloud', 'confidence': 0.95},
    'AS16509':   {'name': 'Amazon AWS', 'confidence': 0.99},
    'AS14618':   {'name': 'Amazon AWS', 'confidence': 0.99},
    'AS8075':    {'name': 'Microsoft Azure', 'confidence': 0.99},
    'AS15169':   {'name': 'Google Cloud', 'confidence': 0.99},
    'AS396982':  {'name': 'Google Cloud', 'confidence': 0.99},
    'AS63949':   {'name': 'Linode', 'confidence': 0.99},
    'AS12876':   {'name': 'Online.net', 'confidence': 0.90},
    'AS53667':   {'name': 'FranTech Solutions', 'confidence': 0.95},
}

HOSTING_KEYWORDS = [
    'cloud', 'vps', 'host', 'server', 'digitalocean', 'linode',
    'vultr', 'hetzner', 'contabo', 'ovh', 'aws', 'azure', 'google',
    'compute', 'node', 'instance', 'droplet', 'vm'
]

PROVIDER_ABUSE_CONTACTS = {
    'DigitalOcean': 'abuse@digitalocean.com',
    'OVH': 'abuse@ovh.net',
    'Hetzner': 'abuse@hetzner.com',
    'Vultr': 'abuse@vultr.com',
    'Amazon AWS': 'abuse@amazonaws.com',
    'Microsoft Azure': 'abuse@microsoft.com',
    'Google Cloud': 'abuse@google.com',
    'Linode': 'abuse@linode.com',
}

# ────────────────────────────────────────────────────────────
# IP ENRICHMENT ENGINE
# ────────────────────────────────────────────────────────────

class IPEnrichmentEngine:
    """Multi-source‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ IP enrichment with parallel API calls."""

    def __init__(self, redis_client):
        self.redis = redis_client
        self.session = requests.Session()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=8)

    def enrich(self, ip: str) -> IPIntelligence:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback:
                return IPIntelligence(ip=ip, private=True, enriched_at=datetime.utcnow().isoformat())
        except ValueError:
            return IPIntelligence(ip=ip, enriched_at=datetime.utcnow().isoformat())

        cache_key = f"ip_enrich:{hashlib.sha256(ip.encode()).hexdigest()[:16]}"
        if self.redis:
            cached = self.redis.get(cache_key)
            if cached:
                data = json.loads(cached)
                data['cached'] = True
                data['risk_level'] = RiskLevel[data['risk_level']] if isinstance(data.get('risk_level'), str) else data['risk_level']
                return IPIntelligence(**{k: v for k, v in data.items() if k in IPIntelligence.__dataclass_fields__})

        intel = IPIntelligence(ip=ip, enriched_at=datetime.utcnow().isoformat())

        futures = []
        if IPINFO_TOKEN:
            futures.append(self.executor.submit(self._enrich_ipinfo, ip, intel))
        if ABUSEIPDB_API_KEY:
            futures.append(self.executor.submit(self._enrich_abuseipdb, ip, intel))
        if SHODAN_API_KEY:
            futures.append(self.executor.submit(self._enrich_shodan, ip, intel))

        for future in concurrent.futures.as_completed(futures):
            try:
                future.result(timeout=10)
            except Exception as e:
                logger.debug(f"Enrichment error for {ip}: {e}")

        self._detect_hosting(intel)
        self._calculate_risk(intel)
        self._find_abuse_contact(intel)
        self._check_bgp_hijack(intel)

        if self.redis:
            data = asdict(intel)
            data['risk_level'] = intel.risk_level.name
            self.redis.setex(cache_key, IP_ENRICHMENT_TTL, json.dumps(data))

        return intel

    def _enrich_ipinfo(self, ip: str, intel: IPIntelligence):
        try:
            headers = {}
            if IPINFO_TOKEN:
                headers['Authorization'] = f"Bearer {IPINFO_TOKEN}"
            resp = self.session.get(f"https://ipinfo.io/{ip}/json", headers=headers, timeout=8)
            if resp.status_code == 200:
                data = resp.json()
                intel.sources.append('ipinfo')
                org_raw = data.get('org', '')
                if org_raw:
                    m = re.match(r'(AS\d+)\s+(.*)', org_raw)
                    if m:
                        intel.asn = m.group(1)
                        intel.asn_name = m.group(2)
                        intel.isp = m.group(2)
                intel.country = data.get('country', '')
                intel.country_code = data.get('country', '')
                intel.city = data.get('city', '')
                intel.rdns = data.get('hostname', '')
                intel.org = org_raw
        except Exception as e:
            logger.debug(f"IPinfo error: {e}")

    def _enrich_abuseipdb(self, ip: str, intel: IPIntelligence):
        try:
            resp = self.session.get(
                "https://api.abuseipdb.com/api/v2/check",
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
                headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
                timeout=8
            )
            if resp.status_code == 200:
                data = resp.json().get('data', {})
                intel.sources.append('abuseipdb')
                intel.abuse_score = data.get('abuseConfidenceScore', 0)
                intel.abuse_reports = data.get('totalReports', 0)
                intel.is_tor = data.get('isTor', False)
                if not intel.isp:
                    intel.isp = data.get('isp', '')
                if not intel.country_code:
                    intel.country_code = data.get('countryCode', '')
                    intel.country = data.get('countryCode', '')
        except Exception as e:
            logger.debug(f"AbuseIPDB error: {e}")

    def _enrich_shodan(self, ip: str, intel: IPIntelligence):
        try:
            resp = self.session.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={'key': SHODAN_API_KEY},
                timeout=8
            )
            if resp.status_code == 200:
                data = resp.json()
                intel.sources.append('shodan')
                intel.open_ports = data.get('ports', [])
                if not intel.isp:
                    intel.isp = data.get('isp', '')
                if not intel.org:
                    intel.org = data.get('org', '')
        except Exception as e:
            logger.debug(f"Shodan error: {e}")

    def _detect_hosting(self, intel: IPIntelligence):
        if intel.asn in HOSTING_ASNS:
            intel.is_hosting = True
            intel.hosting_confidence = HOSTING_ASNS[intel.asn]['confidence']
            intel.hosting_provider = HOSTING_ASNS[intel.asn]['name']

        if intel.rdns:
            matches = sum(1 for kw in HOSTING_KEYWORDS if kw in intel.rdns.lower())
            if matches >= 2 and not intel.is_hosting:
                intel.is_hosting = True
                intel.hosting_confidence = 0.7

    def _calculate_risk(self, intel: IPIntelligence):
        risk = 0.0
        risk += intel.abuse_score * 0.004
        if intel.is_hosting:
            risk += 30 * intel.hosting_confidence
        if intel.is_tor:
            risk += 40
        if intel.is_vpn:
            risk += 20
        if intel.abuse_reports > 50:
            risk += 20
        elif intel.abuse_reports > 10:
            risk += 10
        if len(intel.open_ports) > 100:
            risk += 10
        if intel.bgp_hijack_risk:
            risk += 35

        intel.risk_score = min(risk, 100)

        if intel.risk_score >= 75:
            intel.risk_level = RiskLevel.CRITICAL
        elif intel.risk_score >= 50:
            intel.risk_level = RiskLevel.HIGH
        elif intel.risk_score >= 25:
            intel.risk_level = RiskLevel.MEDIUM
        else:
            intel.risk_level = RiskLevel.LOW

        intel.confidence = min(len(intel.sources) / 3.0, 1.0)

    def _find_abuse_contact(self, intel: IPIntelligence):
        if intel.hosting_provider in PROVIDER_ABUSE_CONTACTS:
            intel.abuse_contact = PROVIDER_ABUSE_CONTACTS[intel.hosting_provider]
            intel.abuse_contact_source = 'known_provider'
            return

        try:
            resp = self.session.get(
                f"https://rdap.arin.net/registry/ip/{intel.ip}",
                headers={'Accept': 'application/json'},
                timeout=5
            )
            if resp.status_code == 200:
                data = resp.json()
                for entity in data.get('entities', []):
                    if 'abuse' in entity.get('roles', []):
                        vcard = entity.get('vcardArray', [])
                        if len(vcard) > 1:
                            for field in vcard[1]:
                                if field[0] == 'email':
                                    intel.abuse_contact = field[3]
                                    intel.abuse_contact_source = 'rdap'
                                    return
        except Exception:
            pass

    def _check_bgp_hijack(self, intel: IPIntelligence):
        try:
            from bgp_monitor import is_ip_from_hijacked_prefix
            hijack = is_ip_from_hijacked_prefix(intel.ip)
            if hijack:
                intel.bgp_hijack_risk = True
                intel.bgp_hijack_info = hijack
        except ImportError:
            pass

# ────────────────────────────────────────────────────────────
# ASN ANALYTICS ENGINE
# ────────────────────────────────────────────────────────────

class ASNAnalyticsEngine:
    """ASN-level‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ threat analytics with time-series tracking."""

    def __init__(self, redis_client):
        self.redis = redis_client

    def record_attack(self, ip: str, enrichment: IPIntelligence, campaign_id: str = None):
        if not self.redis or enrichment.private:
            return

        asn = enrichment.asn or 'unknown'
        date_str = datetime.utcnow().strftime('%Y-%m-%d')

        daily_key = f"asn:daily:{asn}:{date_str}"
        pipe = self.redis.pipeline()
        pipe.hincrby(daily_key, 'count', 1)
        pipe.hset(daily_key, 'name', enrichment.asn_name or '')
        pipe.hset(daily_key, 'country', enrichment.country_code or '')
        pipe.hset(daily_key, 'is_hosting', '1' if enrichment.is_hosting else '0')
        pipe.expire(daily_key, 86400 * 30)

        pipe.zincrby('asn:leaderboard:total', 1, asn)
        pipe.zincrby('asn:leaderboard:24h', 1, asn)
        pipe.expire('asn:leaderboard:24h', 86400)

        country = enrichment.country_code or 'XX'
        pipe.zincrby('asn:countries', 1, country)

        if enrichment.is_hosting and enrichment.hosting_provider:
            pipe.zincrby('asn:hosting_providers', 1, enrichment.hosting_provider)

        pipe.execute()

        # Check for high-risk ASNs from BGP data
        if self.redis.exists(f"asn:bgp_hijack:{asn}"):
            self.redis.zincrby('asn:high_risk', 1, asn)

        count = int(self.redis.hget(daily_key, 'count') or 0)
        if count == ASN_REPORT_THRESHOLD and AUTO_ABUSE_REPORT:
            t = threading.Thread(target=self._auto_report_asn, args=(asn, enrichment), daemon=True)
            t.start()

    def _auto_report_asn(self, asn: str, enrichment: IPIntelligence):
        pass

    def get_heatmap(self, days: int = 7, limit: int = 20) -> List[Dict]:
        if not self.redis:
            return []

        asns = self.redis.zrevrange('asn:leaderboard:total', 0, limit - 1, withscores=True)
        result = []
        end_date = datetime.utcnow().date()

        for asn, total in asns:
            asn = asn.decode() if isinstance(asn, bytes) else asn
            daily_counts = {}
            for i in range(days):
                day = (end_date - timedelta(days=i)).strftime('%Y-%m-%d')
                count = self.redis.hget(f"asn:daily:{asn}:{day}", 'count')
                if count:
                    daily_counts[day] = int(count)

            today_key = f"asn:daily:{asn}:{end_date.strftime('%Y-%m-%d')}"
            meta = self.redis.hgetall(today_key)
            name = meta.get('name', '') or meta.get(b'name', b'').decode() if b'name' in meta else ''
            country = meta.get('country', '') or meta.get(b'country', b'').decode() if b'country' in meta else ''

            recent = sum(daily_counts.get((end_date - timedelta(days=i)).strftime('%Y-%m-%d'), 0) for i in range(2))
            prev = sum(daily_counts.get((end_date - timedelta(days=i)).strftime('%Y-%m-%d'), 0) for i in range(2, 4))
            trend = 'up' if recent > prev else 'down' if recent < prev else 'stable'

            provider = HOSTING_ASNS.get(asn, {}).get('name', '')
            is_high_risk = bool(self.redis.zscore('asn:high_risk', asn)) if self.redis else False

            result.append({
                'asn': asn,
                'total_attacks': int(total),
                'name': name,
                'country': country,
                'is_hosting': meta.get('is_hosting') == '1' or meta.get(b'is_hosting') == b'1',
                'hosting_provider': provider,
                'recent_attacks_2d': recent,
                'trend': trend,
                'daily_counts': daily_counts,
                'risk_level': 'critical' if is_high_risk else 'high' if int(total) > 100 else 'medium' if int(total) > 20 else 'low',
                'bgp_high_risk': is_high_risk,
            })

        return result

    def get_country_stats(self) -> List[Dict]:
        if not self.redis:
            return []
        countries = self.redis.zrevrange('asn:countries', 0, 19, withscores=True)
        return [{'country': (c.decode() if isinstance(c, bytes) else c), 'attacks': int(s)} for c, s in countries]

    def get_hosting_stats(self) -> List[Dict]:
        if not self.redis:
            return []
        providers = self.redis.zrevrange('asn:hosting_providers', 0, 19, withscores=True)
        return [{'provider': (p.decode() if isinstance(p, bytes) else p), 'attacks': int(s)} for p, s in providers]

# ────────────────────────────────────────────────────────────
# ABUSE REPORT ENGINE
# ────────────────────────────────────────────────────────────

class AbuseReportEngine:
    """Automated‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ abuse report generation and dispatch."""

    def __init__(self, redis_client):
        self.redis = redis_client

    def generate_report(self, ip: str, sessions: List[Dict], enrichment: IPIntelligence) -> str:
        session_texts = []
        for s in sessions[:5]:
            intel = s.get('intelligence', {})
            cmds = s.get('commands', [])[:5]
            session_texts.append(
                f"Session: {s.get('session_id', '')[:16]}\n"
                f"  Time: {s.get('connected_at', '')}\n"
                f"  Duration: {s.get('duration', 0):.0f}s\n"
                f"  Stage: {intel.get('attack_stage', 'unknown')}\n"
                f"  Commands: {', '.join(c[:50] for c in cmds[:3])}"
            )

        return f"""Subject: Abuse Report — Unauthorized Access from {ip}

Dear Abuse Team,

We are writing to report malicious activity from IP {ip} under your control.

=== INCIDENT SUMMARY ===
IP: {ip}
ASN: {enrichment.asn} ({enrichment.asn_name})
ISP: {enrichment.isp}
Country: {enrichment.country}
IP Reputation Score: {enrichment.abuse_score}/100
Total Incidents: {len(sessions)}
Time: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}

=== SESSIONS ===
{chr(10).join(session_texts)}

=== REQUESTED ACTIONS ===
1. Investigate and terminate if policy violations confirmed
2. Preserve logs for law enforcement referral
3. Provide a case reference number if available

This activity violates standard AUP and may constitute unauthorized access.

Sincerely,
Security Operations Team
{ABUSE_REPORT_FROM}
"""

    def send_report(self, to_email: str, subject: str, body: str) -> bool:
        if not RESEND_API_KEY:
            logger.warning("RESEND_API_KEY not set")
            return False
        try:
            resp = requests.post(
                "https://api.resend.com/emails",
                headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
                json={"from": ABUSE_REPORT_FROM, "to": [to_email], "subject": subject, "text": body},
                timeout=15
            )
            if resp.status_code in (200, 201):
                logger.info(f"Abuse report sent to {to_email}")
                return True
            logger.error(f"Report send failed: {resp.status_code}")
            return False
        except Exception as e:
            logger.error(f"Report send error: {e}")
            return False

    @staticmethod
    def decay_weight(timestamp: float, half_life_days: float = KARMA_HALF_LIFE_DAYS) -> float:
        """Compute exponential decay factor for a single event timestamp.

        Returns a value in (0.0, 1.0] where 1.0 means the event just occurred
        and values approach 0.0 as the event ages beyond the half-life.
        """
        elapsed = time.time() - timestamp
        half_life_seconds = half_life_days * 86400
        decay_constant = math.log(2) / half_life_seconds
        return math.exp(-decay_constant * max(elapsed, 0.0))

    def get_asn_attacks(self, asn: str) -> List[Dict[str, Any]]:
        """Retrieve all attack records for a given ASN from Redis daily buckets.

        Returns a list of dicts each containing ``date`` (datetime), ``count`` (int),
        ``name`` (str), ``country`` (str), and ``is_hosting`` (bool).
        """
        if not self.redis:
            return []
        attacks: List[Dict[str, Any]] = []
        pattern = f"asn:daily:{asn}:*"
        for key in self.redis.scan_iter(match=pattern):
            data = self.redis.hgetall(key)
            if not data:
                continue
            date_part = key.split(':')[-1]
            try:
                attack_date = datetime.strptime(date_part, '%Y-%m-%d')
            except ValueError:
                continue
            count = int(data.get('count', data.get(b'count', 0)))
            name = data.get('name', data.get(b'name', ''))
            country = data.get('country', data.get(b'country', ''))
            is_hosting_raw = data.get('is_hosting', data.get(b'is_hosting', '0'))
            is_hosting = is_hosting_raw in ('1', b'1')
            attacks.append({
                'date': attack_date,
                'count': count,
                'name': name,
                'country': country,
                'is_hosting': is_hosting,
            })
        return attacks

    def compute_karma(self, asn: str) -> Dict[str, Any]:
        """Compute the KARMA reputation score for an ASN from stored attack data.

        Returns a dict with:
        - ``karma_score``: 0-100 overall score (higher = worse reputation)
        - ``sub_scores``: dict of {frequency, severity, recency, diversity} each 0-100
        - ``decay_info``: dict with half_life_days, total_events, unique_days, hosting_count
        - ``asn``: the ASN string
        """
        attacks = self.get_asn_attacks(asn)
        if not attacks:
            return {
                'karma_score': 50.0,
                'sub_scores': {
                    'frequency': 0.0,
                    'severity': 0.0,
                    'recency': 0.0,
                    'diversity': 0.0,
                },
                'decay_info': {
                    'half_life_days': KARMA_HALF_LIFE_DAYS,
                    'total_events': 0,
                    'unique_days': 0,
                    'hosting_count': 0,
                },
                'asn': asn,
            }

        total_attacks = sum(a['count'] for a in attacks)
        unique_days = len(attacks)
        hosting_count = sum(a['count'] for a in attacks if a['is_hosting'])
        hosting_ratio = hosting_count / total_attacks if total_attacks > 0 else 0.0

        max_expected = 1000.0
        freq_raw = min(math.log(total_attacks + 1) / math.log(max_expected + 1), 1.0)
        freq_score = freq_raw * 100.0

        sev_score = hosting_ratio * 100.0

        now_ts = time.time()
        weighted_sum = 0.0
        max_possible = 0.0
        for a in attacks:
            day_ts = a['date'].timestamp()
            w = self.decay_weight(day_ts, KARMA_HALF_LIFE_DAYS)
            weighted_sum += a['count'] * w
            weight_now = self.decay_weight(now_ts, KARMA_HALF_LIFE_DAYS)
            max_possible += a['count'] * weight_now

        recency_raw = weighted_sum / max_possible if max_possible > 0 else 0.0
        recency_score = recency_raw * 100.0

        max_days = 90.0
        div_raw = min(unique_days / max_days, 1.0)
        div_score = div_raw * 100.0

        karma = (
            KARMA_FREQ_WEIGHT * freq_score +
            KARMA_SEV_WEIGHT * sev_score +
            KARMA_RECENCY_WEIGHT * recency_score +
            KARMA_DIVERSITY_WEIGHT * div_score
        )

        karma_score = round(min(karma, 100.0), 2)

        return {
            'karma_score': karma_score,
            'sub_scores': {
                'frequency': round(freq_score, 2),
                'severity': round(sev_score, 2),
                'recency': round(recency_score, 2),
                'diversity': round(div_score, 2),
            },
            'decay_info': {
                'half_life_days': KARMA_HALF_LIFE_DAYS,
                'total_events': total_attacks,
                'unique_days': unique_days,
                'hosting_count': hosting_count,
            },
            'asn': asn,
        }

# ────────────────────────────────────────────────────────────
# MAIN SERVICE
# ────────────────────────────────────────────────────────────

class ASNIntelligenceService:
    """Unified ASN intelligence service."""

    def __init__(self):
        self.redis = self._connect_redis()
        self.enricher = IPEnrichmentEngine(self.redis)
        self.analytics = ASNAnalyticsEngine(self.redis)
        self.reporter = AbuseReportEngine(self.redis)
        self.metrics = defaultdict(int)
        self.lock = threading.RLock()

    def _connect_redis(self):
        if not REDIS_URL:
            return None
        for attempt in range(3):
            try:
                r = redis_lib.from_url(REDIS_URL, socket_connect_timeout=5, socket_keepalive=True,
                                       retry_on_timeout=True, decode_responses=True, max_connections=15)
                r.ping()
                return r
            except Exception as e:
                logger.warning(f"Redis attempt {attempt + 1}: {e}")
                time.sleep(2)
        return None

    def enrich_and_track(self, ip: str, campaign_id: str = None) -> IPIntelligence:
        with self.lock:
            intel = self.enricher.enrich(ip)
            if not intel.private:
                self.analytics.record_attack(ip, intel, campaign_id)
                self.metrics['ips_enriched'] += 1
            return intel

# ────────────────────────────────────────────────────────────
# SINGLETON
# ────────────────────────────────────────────────────────────

_service: Optional[ASNIntelligenceService] = None
_service_lock = threading.Lock()

def get_service() -> ASNIntelligenceService:
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = ASNIntelligenceService()
    return _service

def start_asn_engine():
    get_service()
    logger.info("ASN intelligence engine started")

# ────────────────────────────────────────────────────────────
# FLASK BLUEPRINT
# ────────────────────────────────────────────────────────────

asn_intel_bp = Blueprint('asn_intelligence', __name__)

def _require_auth(admin_only=False):
    try:

        if not is_logged_in():
            return jsonify({"error": "Login required"}), 403
        if admin_only and not is_admin():
            return jsonify({"error": "Admin required"}), 403
    except ImportError:
        pass
    return None

@asn_intel_bp.route('/api/intel/ip/<ip_address>', methods=['GET'])
def lookup_ip(ip_address):
    auth_err = _require_auth()
    if auth_err:
        return auth_err
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    intel = get_service().enrich_and_track(ip_address)
    return jsonify({"ok": True, "intel": asdict(intel)})

@asn_intel_bp.route('/api/intel/asn-heatmap', methods=['GET'])
def asn_heatmap():
    auth_err = _require_auth(admin_only=True)
    if auth_err:
        return auth_err
    days = int(request.args.get('days', 7))
    data = get_service().analytics.get_heatmap(days)
    return jsonify({"ok": True, "asns": data})

@asn_intel_bp.route('/api/intel/country-stats', methods=['GET'])
def country_stats():
    auth_err = _require_auth(admin_only=True)
    if auth_err:
        return auth_err
    data = get_service().analytics.get_country_stats()
    return jsonify({"ok": True, "countries": data})

@asn_intel_bp.route('/api/intel/hosting-stats', methods=['GET'])
def hosting_stats():
    auth_err = _require_auth(admin_only=True)
    if auth_err:
        return auth_err
    data = get_service().analytics.get_hosting_stats()
    return jsonify({"ok": True, "providers": data})

@asn_intel_bp.route('/api/intel/abuse-report', methods=['POST'])
def create_abuse_report():
    auth_err = _require_auth(admin_only=True)
    if auth_err:
        return auth_err

    data = request.get_json(silent=True) or {}
    ip = data.get('ip', '').strip()
    send = data.get('send', False)

    if not ip:
        return jsonify({"error": "IP required"}), 400

    svc = get_service()
    intel = svc.enricher.enrich(ip)

    sessions = []
    if svc.redis:
        session_ids = svc.redis.lrange('cowrie_sessions:recent', 0, 199)
        for sid in session_ids:
            raw = svc.redis.get(f"cowrie_completed:{sid}")
            if raw:
                s = json.loads(raw)
                if s.get('src_ip') == ip:
                    sessions.append(s)

    report = svc.reporter.generate_report(ip, sessions, intel)
    sent = False
    if send and intel.abuse_contact:
        sent = svc.reporter.send_report(intel.abuse_contact, f"Abuse Report — {ip}", report)
        if sent and svc.redis:
            svc.redis.setex(f"abuse_log:{ip}", 86400 * 30, json.dumps({
                'to': intel.abuse_contact,
                'sent_at': datetime.utcnow().isoformat()
            }))

    return jsonify({
        "ok": True,
        "sent": sent,
        "abuse_contact": intel.abuse_contact,
        "intel": asdict(intel),
        "report": report[:1000] + "..." if len(report) > 1000 else report
    })
