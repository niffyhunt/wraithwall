import os
import re
import json
import time
import math
import hashlib
import logging
import threading
import ipaddress
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Any, Set, Tuple
from collections import defaultdict, Counter, deque
from dataclasses import dataclass, field, asdict

import numpy as np
import redis as redis_lib
import requests
from flask import Blueprint, jsonify, request

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────

REDIS_URL = os.environ.get('REDIS_URL', '')
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')
HONEYPOT_SENSORS_RAW = os.environ.get('HONEYPOT_SENSORS', '')
HONEYPOT_SENSORS = [s.strip() for s in HONEYPOT_SENSORS_RAW.split(',') if s.strip()]
CAMPAIGN_ALERT_THRESHOLD = int(os.environ.get('CAMPAIGN_ALERT_THRESHOLD', '3'))
MIN_SIMILARITY_SCORE = float(os.environ.get('MIN_SIMILARITY_SCORE', '0.60'))
HIGH_CONFIDENCE_THRESHOLD = float(os.environ.get('HIGH_CONFIDENCE_THRESHOLD', '0.85'))

SESSION_TIMING_WINDOW = int(os.environ.get('SESSION_TIMING_WINDOW', '300'))
CAMPAIGN_TTL = int(os.environ.get('CAMPAIGN_TTL', '604800'))
FINGERPRINT_CACHE_TTL = int(os.environ.get('FINGERPRINT_CACHE_TTL', '259200'))
MAX_CANDIDATES = int(os.environ.get('MAX_CANDIDATES', '50'))

# ────────────────────────────────────────────────────────────
# REGULAR EXPRESSIONS FOR COMMAND NORMALIZATION
# ────────────────────────────────────────────────────────────

IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
HASH_PATTERN = re.compile(r'\b[a-fA-F0-9]{32,64}\b')
URL_PATTERN = re.compile(r'https?://[^\s]+')
PATH_PATTERN = re.compile(r'(?:/[\w.-]+)+')
PORT_PATTERN = re.compile(r':\d{2,5}\b')
BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?')

# ────────────────────────────────────────────────────────────
# KNOWN TOOL SIGNATURES
# ────────────────────────────────────────────────────────────

TOOL_SIGNATURES = {
    'masscan':       {'patterns': [r'masscan', r'--rate\s+\d+', r'-p\s*\d+-\d+'], 'confidence': 0.95, 'category': 'network_scanner'},
    'nmap':          {'patterns': [r'nmap', r'-s[STUV]', r'--script'], 'confidence': 0.90, 'category': 'network_scanner'},
    'zmap':          {'patterns': [r'zmap', r'--probe-module'], 'confidence': 0.95, 'category': 'network_scanner'},
    'hydra':         {'patterns': [r'hydra', r'-l\s+\w+', r'-P\s+\S+'], 'confidence': 0.95, 'category': 'brute_forcer'},
    'medusa':        {'patterns': [r'medusa', r'-u\s+\w+', r'-M\s+ssh'], 'confidence': 0.90, 'category': 'brute_forcer'},
    'ncrack':        {'patterns': [r'ncrack', r'--user', r'--pass'], 'confidence': 0.90, 'category': 'brute_forcer'},
    'metasploit':    {'patterns': [r'msf\w+', r'meterpreter', r'exploit/multi'], 'confidence': 0.85, 'category': 'exploitation_framework'},
    'cobalt_strike': {'patterns': [r'beacon', r'cobaltstrike', r'teamserver'], 'confidence': 0.80, 'category': 'c2_framework'},
    'mirai':         {'patterns': [r'busybox', r'tftp.*mirai', r'/bin/busybox\s+\w+'], 'confidence': 0.90, 'category': 'botnet'},
    'xmrig':         {'patterns': [r'xmrig', r'stratum\+tcp://', r'--coin'], 'confidence': 0.95, 'category': 'cryptominer'},
    'gost':          {'patterns': [r'gost', r'-L\s+\S+:\S+'], 'confidence': 0.85, 'category': 'proxy_tunnel'},
    'chisel':        {'patterns': [r'chisel', r'client.*server', r'R:socks'], 'confidence': 0.90, 'category': 'tunneling'},
    'frp':           {'patterns': [r'frpc', r'frps', r'\[common\]'], 'confidence': 0.85, 'category': 'tunneling'},
    'linpeas':       {'patterns': [r'linpeas', r'peass', r'linux.*enumeration'], 'confidence': 0.90, 'category': 'enumeration'},
}

# ────────────────────────────────────────────────────────────
# FINGERPRINT BUILDER
# ────────────────────────────────────────────────────────────

@dataclass
class BehavioralFingerprint:
    """Multi-dimensional‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ behavioral fingerprint for correlation."""
    fingerprint_id: str
    session_id: str
    sensor_id: str
    timestamp: datetime

    # Command analysis
    command_sequence_hash: str
    command_ngrams: List[str]
    command_entropy: float
    command_complexity: float
    normalized_commands: List[str]

    # Tool detection
    tool_signatures: Dict[str, float]
    tool_sequence_pattern: List[str]

    # Credential analysis
    credential_patterns: List[Dict[str, Any]]
    credential_entropy: float
    username_diversity: float

    # Behavioral metrics
    inter_command_timing: List[float]
    typing_rhythm_signature: str
    human_confidence: float
    session_pacing: str

    # Network
    src_ip: str
    src_port: int
    session_count: int = 1

    # Feature vector for ML comparison
    feature_vector: List[float] = field(default_factory=lambda: [0.0] * 64)
    anomaly_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d['timestamp'] = self.timestamp.isoformat()
        return d

class Fingerprinter:
    """Builds‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ behavioral fingerprints from Cowrie sessions."""

    @classmethod
    def build(cls, session: Dict) -> BehavioralFingerprint:
        commands = session.get('commands', [])
        login_attempts = session.get('login_attempts', [])
        session_id = session.get('session_id', '')
        sensor = session.get('sensor', 'unknown')
        timestamp = cls._parse_timestamp(session.get('connected_at'))
        # Cowrie stores duration as a string (e.g. "1.6"); coerce before any
        # numeric comparison downstream or ingestion throws TypeError.
        try:
            duration = float(session.get('duration') or 0)
        except (TypeError, ValueError):
            duration = 0.0

        normalized = [cls._normalize_command(c) for c in commands]
        simhash = cls._simhash(normalized)
        ngrams = cls._generate_ngrams(normalized, n=3)
        entropy = cls._shannon_entropy(' '.join(normalized))
        complexity = cls._command_complexity(commands)

        tool_sigs = cls._detect_tools(commands)
        tool_seq = cls._extract_tool_sequence(commands)

        cred_patterns = cls._analyze_credentials(login_attempts)
        cred_entropy = cls._shannon_entropy(
            ''.join(a.get('password', '') for a in login_attempts)
        )
        username_div = cls._username_diversity(login_attempts)

        inter_timing = cls._inter_command_timing(commands, duration)
        typing_sig = cls._typing_signature(inter_timing)
        human_prob = cls._human_probability(inter_timing, len(login_attempts))
        pacing = cls._session_pacing(inter_timing)

        feature_vec = cls._build_feature_vector(
            normalized, tool_sigs, cred_patterns,
            inter_timing, len(commands), duration
        )

        return BehavioralFingerprint(
            fingerprint_id=hashlib.sha256(
                f"{simhash}:{session_id}:{timestamp.isoformat()}".encode()
            ).hexdigest()[:16],
            session_id=session_id,
            sensor_id=sensor,
            timestamp=timestamp,
            command_sequence_hash=simhash,
            command_ngrams=ngrams,
            command_entropy=entropy,
            command_complexity=complexity,
            normalized_commands=normalized,
            tool_signatures=tool_sigs,
            tool_sequence_pattern=tool_seq,
            credential_patterns=cred_patterns,
            credential_entropy=cred_entropy,
            username_diversity=username_div,
            inter_command_timing=inter_timing,
            typing_rhythm_signature=typing_sig,
            human_confidence=human_prob,
            session_pacing=pacing,
            src_ip=session.get('src_ip', ''),
            src_port=session.get('src_port', 0),
            feature_vector=feature_vec,
            anomaly_score=0.0,
        )

    @classmethod
    def _normalize_command(cls, cmd: str) -> str:
        normalized = cmd.lower().strip()
        normalized = IP_PATTERN.sub('IPV4', normalized)
        normalized = HASH_PATTERN.sub('HASH', normalized)
        normalized = URL_PATTERN.sub('URL', normalized)
        normalized = PATH_PATTERN.sub(lambda m: f'PATH_{len(m.group().split("/"))}', normalized)
        normalized = PORT_PATTERN.sub(':PORT', normalized)
        normalized = BASE64_PATTERN.sub('BASE64_DATA', normalized)
        normalized = re.sub(r'\b\d+\b', 'N', normalized)
        normalized = re.sub(r'\s+', ' ', normalized).strip()
        return normalized

    @classmethod
    def _simhash(cls, commands: List[str], bits: int = 64) -> str:
        if not commands:
            return '0' * (bits // 4)
        v = np.zeros(bits)
        text = ' '.join(commands)
        tokens = text.split()
        for token in tokens:
            h = hashlib.sha256(token.encode()).hexdigest()
            token_bits = bin(int(h, 16))[2:].zfill(256)[:bits]
            for i, b in enumerate(token_bits):
                v[i] += 1 if b == '1' else -1
        fingerprint = ''.join(['1' if x > 0 else '0' for x in v])
        return hex(int(fingerprint, 2))[2:].zfill(bits // 4)

    @classmethod
    def _generate_ngrams(cls, commands: List[str], n: int = 3) -> List[str]:
        ngrams = []
        for i in range(len(commands) - n + 1):
            ngram = ' → '.join(commands[i:i+n])
            ngrams.append(ngram)
        return ngrams

    @classmethod
    def _shannon_entropy(cls, text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
        return round(entropy, 4)

    @classmethod
    def _command_complexity(cls, commands: List[str]) -> float:
        if not commands:
            return 0.0
        complexities = []
        for cmd in commands:
            c = (cmd.count('|') * 2 + cmd.count(';') * 1.5 + cmd.count('&&') * 2 +
                 cmd.count('$(') * 3 + cmd.count('`') * 3 + (1 if len(cmd.split()) > 8 else 0))
            complexities.append(min(c, 20))
        return float(np.mean(complexities)) if complexities else 0.0

    @classmethod
    def _detect_tools(cls, commands: List[str]) -> Dict[str, float]:
        cmd_text = ' '.join(commands).lower()
        detected = {}
        for tool, info in TOOL_SIGNATURES.items():
            matches = sum(1 for p in info['patterns'] if re.search(p, cmd_text))
            if matches > 0:
                detected[tool] = round(info['confidence'] * (matches / len(info['patterns'])), 3)
        return detected

    @classmethod
    def _extract_tool_sequence(cls, commands: List[str]) -> List[str]:
        sequence = []
        for cmd in commands:
            cmd_lower = cmd.lower()
            for tool, info in TOOL_SIGNATURES.items():
                if any(re.search(p, cmd_lower) for p in info['patterns']):
                    if not sequence or sequence[-1] != tool:
                        sequence.append(tool)
                    break
        return sequence

    @classmethod
    def _analyze_credentials(cls, login_attempts: List[Dict]) -> List[Dict]:
        patterns = []
        for a in login_attempts[:20]:
            pw = a.get('password', '')
            complexity = 'simple'
            if len(pw) > 12:
                complexity = 'complex'
            elif len(pw) > 8 and any(c.isupper() for c in pw) and any(c.isdigit() for c in pw):
                complexity = 'medium'
            patterns.append({
                'username': a.get('username', ''),
                'password_complexity': complexity,
                'password_length': len(pw)
            })
        return patterns

    @classmethod
    def _username_diversity(cls, login_attempts: List[Dict]) -> float:
        usernames = [a.get('username', '') for a in login_attempts if a.get('username')]
        if not usernames:
            return 0.0
        return len(set(usernames)) / len(usernames)

    @classmethod
    def _inter_command_timing(cls, commands: List[str], duration: float) -> List[float]:
        if len(commands) < 2:
            return [0.0]
        if duration > 0:
            avg = duration / len(commands)
            return [avg * (0.8 + 0.4 * np.random.random()) for _ in range(len(commands) - 1)]
        return [1.0 for _ in range(len(commands) - 1)]

    @classmethod
    def _typing_signature(cls, inter_timing: List[float]) -> str:
        if not inter_timing:
            return hashlib.sha256(b'empty').hexdigest()[:16]
        bins = [0, 0.5, 1, 2, 5, 10, 30, float('inf')]
        hist = np.histogram(inter_timing, bins=bins)[0]
        return hashlib.sha256(hist.tobytes()).hexdigest()[:16]

    @classmethod
    def _human_probability(cls, inter_timing: List[float], login_attempts: int) -> float:
        if not inter_timing:
            return 0.5
        variance = float(np.var(inter_timing)) if len(inter_timing) > 1 else 0.0
        has_pause = any(t > 10 for t in inter_timing)
        score = 0.3
        if variance > 2: score += 0.2
        if has_pause: score += 0.2
        if login_attempts > 0: score += 0.2
        if login_attempts <= 5: score += 0.1
        return min(score, 0.95)

    @classmethod
    def _session_pacing(cls, inter_timing: List[float]) -> str:
        if not inter_timing:
            return 'unknown'
        mean_t = float(np.mean(inter_timing))
        if mean_t < 0.5: return 'burst'
        if mean_t < 2: return 'fast'
        if mean_t < 10: return 'steady'
        return 'slow'

    @classmethod
    def _build_feature_vector(cls, commands: List[str], tools: Dict[str, float],
                               cred_patterns: List[Dict], inter_timing: List[float],
                               cmd_count: int, duration: float) -> List[float]:
        features = [
            float(len(commands)),
            cls._command_complexity(commands),
            cls._shannon_entropy(' '.join(commands)),
            float(len(tools)),
            max(tools.values()) if tools else 0.0,
            sum(tools.values()) / len(tools) if tools else 0.0,
            float(len(cred_patterns)),
            float(np.mean(inter_timing)) if inter_timing else 0.0,
            float(np.std(inter_timing)) if inter_timing else 0.0,
            duration,
            cmd_count / duration if duration > 0 else 0.0,
        ]
        while len(features) < 64:
            features.append(0.0)
        return features[:64]

    @classmethod
    def _parse_timestamp(cls, ts: str) -> datetime:
        try:
            return datetime.fromisoformat(ts.replace('Z', '+00:00'))
        except (ValueError, AttributeError):
            return datetime.utcnow()

# ────────────────────────────────────────────────────────────
# SIMILARITY ENGINE
# ────────────────────────────────────────────────────────────

class SimilarityEngine:
    """Multi-dimensional‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ similarity computation."""

    WEIGHTS = {
        'command_sequence': 0.20,
        'ngram_jaccard': 0.15,
        'tool_overlap': 0.20,
        'credential_similarity': 0.15,
        'behavioral_rhythm': 0.10,
        'typing_signature': 0.05,
        'feature_cosine': 0.10,
        'operator_consistency': 0.03,
        'pacing_consistency': 0.02,
    }

    @classmethod
    def compute(cls, fp1: BehavioralFingerprint, fp2: BehavioralFingerprint) -> Dict[str, Any]:
        scores = {}

        # Hamming similarity on SimHash
        try:
            b1 = bin(int(fp1.command_sequence_hash, 16))[2:].zfill(64)
            b2 = bin(int(fp2.command_sequence_hash, 16))[2:].zfill(64)
            dist = sum(c1 != c2 for c1, c2 in zip(b1, b2))
            scores['command_sequence'] = 1.0 - (dist / max(len(b1), len(b2)))
        except (ValueError, TypeError):
            scores['command_sequence'] = 0.0

        # Jaccard on n-grams
        ngrams1 = set(fp1.command_ngrams)
        ngrams2 = set(fp2.command_ngrams)
        union = len(ngrams1 | ngrams2)
        scores['ngram_jaccard'] = len(ngrams1 & ngrams2) / union if union > 0 else 0.0

        # Weighted tool overlap
        tools1 = fp1.tool_signatures
        tools2 = fp2.tool_signatures
        all_tools = set(tools1.keys()) | set(tools2.keys())
        if all_tools:
            tool_score = 0.0
            for tool in all_tools:
                c1 = tools1.get(tool, 0.0)
                c2 = tools2.get(tool, 0.0)
                tool_score += min(c1, c2) if (c1 > 0 and c2 > 0) else max(c1, c2) * 0.3
            scores['tool_overlap'] = tool_score / len(all_tools)
        else:
            scores['tool_overlap'] = 0.0

        # Credential similarity
        scores['credential_similarity'] = cls._credential_sim(
            fp1.credential_patterns, fp2.credential_patterns
        )

        # Rhythm similarity
        scores['behavioral_rhythm'] = cls._rhythm_sim(
            fp1.inter_command_timing, fp2.inter_command_timing
        )

        # Typing signature
        scores['typing_signature'] = 1.0 if fp1.typing_rhythm_signature == fp2.typing_rhythm_signature else 0.0

        # Feature vector cosine
        v1 = np.array(fp1.feature_vector)
        v2 = np.array(fp2.feature_vector)
        dot = float(np.dot(v1, v2))
        norm = float(np.linalg.norm(v1) * np.linalg.norm(v2))
        scores['feature_cosine'] = float(dot / norm) if norm > 0 else 0.0

        # Operator consistency
        scores['operator_consistency'] = 1.0 - abs(fp1.human_confidence - fp2.human_confidence)

        # Pacing consistency
        scores['pacing_consistency'] = 1.0 if fp1.session_pacing == fp2.session_pacing else 0.3

        # Weighted ensemble
        weighted = sum(scores.get(k, 0.0) * w for k, w in cls.WEIGHTS.items())
        confidence = min(len([s for s in scores.values() if s > 0]) / len(cls.WEIGHTS), 1.0)

        return {
            'similarity_score': round(weighted, 4),
            'confidence': round(confidence, 4),
            'dimension_scores': scores,
            'is_match': weighted >= MIN_SIMILARITY_SCORE and confidence >= 0.6,
        }

    @classmethod
    def _credential_sim(cls, p1: List[Dict], p2: List[Dict]) -> float:
        if not p1 and not p2:
            return 0.0
        us1 = Counter(p.get('username', '') for p in p1)
        us2 = Counter(p.get('username', '') for p in p2)
        all_u = set(us1.keys()) | set(us2.keys())
        if not all_u:
            return 0.0
        overlap = sum(min(us1.get(u, 0), us2.get(u, 0)) for u in all_u)
        total = sum(max(us1.get(u, 0), us2.get(u, 0)) for u in all_u)
        return overlap / total if total > 0 else 0.0

    @classmethod
    def _rhythm_sim(cls, t1: List[float], t2: List[float]) -> float:
        if not t1 or not t2:
            return 0.0
        a1, a2 = np.array(t1), np.array(t2)
        m1 = [float(np.mean(a1)), float(np.std(a1))]
        m2 = [float(np.mean(a2)), float(np.std(a2))]
        diffs = [abs(m1[i] - m2[i]) / max(abs(m1[i]), abs(m2[i]), 1.0) for i in range(2)]
        return max(0.0, 1.0 - float(np.mean(diffs)))

# ────────────────────────────────────────────────────────────
# CAMPAIGN CORRELATION ENGINE
# ────────────────────────────────────────────────────────────

class CampaignCorrelator:
    """Campaign detection and management."""

    def __init__(self):
        self.redis = self._connect_redis()
        self.fingerprinter = Fingerprinter()
        self.similarity = SimilarityEngine()
        self.lock = threading.RLock()

        # In-memory similarity graph
        self.graph: Dict[str, Set[str]] = defaultdict(set)
        self.clusters: Dict[str, str] = {}

        # Metrics
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
                    max_connections=15
                )
                r.ping()
                logger.info("Campaign correlator connected to Redis")
                return r
            except Exception as e:
                logger.warning(f"Redis attempt {attempt + 1}: {e}")
                time.sleep(2)
        return None

    def ingest_deception_event(self, event: Dict) -> Optional[Dict]:
        """Ingest non-Cowrie deception bus events for cross-bait correlation."""
        ip = event.get('attacker_ip')
        if not ip or not self.redis:
            return None
        try:
            key = f"deception:correlation:{ip}"
            self.redis.lpush(key, json.dumps({
                'source': event.get('source'),
                'bait_id': event.get('bait_id'),
                'bait_type': event.get('bait_type'),
                'trigger_type': event.get('trigger_type'),
                'ts': event.get('timestamp'),
            }))
            self.redis.ltrim(key, 0, 199)
            self.redis.expire(key, 86400)
            self.metrics['deception_events_ingested'] = self.metrics.get('deception_events_ingested', 0) + 1
        except Exception as e:
            logger.debug(f"deception event ingest: {e}")
        return None

    def ingest_session(self, session: Dict) -> Optional[Dict]:
        """Ingest a completed Cowrie session for campaign correlation."""
        if not session.get('commands'):
            return None

        with self.lock:
            self.metrics['sessions_processed'] += 1
            try:
                fp = self.fingerprinter.build(session)

                cred_attack = session.get('credential_attack', {})
                if cred_attack.get('attack_type'):
                    velocity = cred_attack.get('details', {}).get('velocity', '')
                    cmd_text = ' '.join(session.get('commands', [])).lower()
                    if velocity in ('high', 'medium'):
                        for tool, info in TOOL_SIGNATURES.items():
                            if info.get('category') == 'brute_forcer':
                                if any(re.search(p, cmd_text) for p in info['patterns']):
                                    self.metrics['cred_storm_crossref'] += 1
                                    break

                self._store_fingerprint(fp)

                candidates = self._find_candidates(fp)
                best_match = None
                best_score = 0.0

                for candidate in candidates:
                    sim = self.similarity.compute(fp, candidate)
                    if sim['is_match'] and sim['similarity_score'] > best_score:
                        best_score = sim['similarity_score']
                        best_match = {'fingerprint': candidate, 'similarity': sim}

                campaign = None
                if best_match and best_score >= HIGH_CONFIDENCE_THRESHOLD:
                    campaign = self._update_campaign(best_match['fingerprint'], fp, best_match['similarity'])
                elif best_match and best_score >= MIN_SIMILARITY_SCORE:
                    campaign = self._consider_new_campaign(fp, best_match['similarity'])
                else:
                    self._track_for_future(fp)

                if campaign:
                    self.metrics['campaigns_updated'] += 1

                return campaign

            except Exception as e:
                logger.error(f"Session ingestion error: {e}", exc_info=True)
                self.metrics['errors'] += 1
                return None

    def _store_fingerprint(self, fp: BehavioralFingerprint):
        if not self.redis:
            return
        fp_key = f"cowrie_fp:{fp.session_id}"
        payload = json.dumps(fp.to_dict())
        self.redis.setex(fp_key, FINGERPRINT_CACHE_TTL, payload)
        self.redis.setex(f"fingerprint_data:{fp.fingerprint_id}", FINGERPRINT_CACHE_TTL, payload)
        self.redis.lpush('recent_fingerprints', fp.fingerprint_id)
        self.redis.ltrim('recent_fingerprints', 0, 9999)

    def _find_candidates(self, fp: BehavioralFingerprint) -> List[BehavioralFingerprint]:
        candidates = []
        if not self.redis:
            return candidates

        recent_ids = self.redis.lrange('recent_fingerprints', 0, MAX_CANDIDATES - 1)
        for fid in recent_ids:
            if fid == fp.fingerprint_id:
                continue
            raw = self.redis.get(f"fingerprint_data:{fid}")
            if not raw:
                continue
            try:
                fp_dict = json.loads(raw)
                if self._quick_filter(fp, fp_dict):
                    candidates.append(self._deserialize(fp_dict))
            except Exception:
                continue
        return candidates

    def _quick_filter(self, fp: BehavioralFingerprint, fp_dict: Dict) -> bool:
        tools1 = set(fp.tool_signatures.keys())
        tools2 = set(fp_dict.get('tool_signatures', {}).keys())
        if tools1 and tools2 and not (tools1 & tools2):
            return False
        return True

    def _deserialize(self, data: Dict) -> BehavioralFingerprint:
        return BehavioralFingerprint(
            fingerprint_id=data.get('fingerprint_id', ''),
            session_id=data.get('session_id', ''),
            sensor_id=data.get('sensor_id', ''),
            timestamp=datetime.fromisoformat(data.get('timestamp', datetime.utcnow().isoformat())),
            command_sequence_hash=data.get('command_sequence_hash', ''),
            command_ngrams=data.get('command_ngrams', []),
            command_entropy=data.get('command_entropy', 0.0),
            command_complexity=data.get('command_complexity', 0.0),
            normalized_commands=data.get('normalized_commands', []),
            tool_signatures=data.get('tool_signatures', {}),
            tool_sequence_pattern=data.get('tool_sequence_pattern', []),
            credential_patterns=data.get('credential_patterns', []),
            credential_entropy=data.get('credential_entropy', 0.0),
            username_diversity=data.get('username_diversity', 0.0),
            inter_command_timing=data.get('inter_command_timing', []),
            typing_rhythm_signature=data.get('typing_rhythm_signature', ''),
            human_confidence=data.get('human_confidence', 0.5),
            session_pacing=data.get('session_pacing', 'unknown'),
            src_ip=data.get('src_ip', ''),
            src_port=data.get('src_port', 0),
            feature_vector=data.get('feature_vector', [0.0] * 64),
        )

    def _update_campaign(self, existing_fp: BehavioralFingerprint,
                         new_fp: BehavioralFingerprint,
                         sim: Dict) -> Optional[Dict]:
        if not self.redis:
            return None

        campaign_id = self._find_campaign_for_fingerprint(existing_fp)
        if not campaign_id:
            campaign = self._create_campaign(new_fp, sim)
            return campaign

        raw = self.redis.get(f"campaign:{campaign_id}")
        if not raw:
            return None

        campaign = json.loads(raw)
        campaign['last_seen'] = new_fp.timestamp.isoformat()
        campaign['session_count'] = campaign.get('session_count', 0) + 1

        sensors = campaign.get('sensors_hit', [])
        if new_fp.sensor_id not in sensors:
            sensors.append(new_fp.sensor_id)
            campaign['sensors_hit'] = sensors

        ips = campaign.get('unique_ips', [])
        if new_fp.src_ip not in ips:
            ips.append(new_fp.src_ip)
            campaign['unique_ips'] = ips

        campaign['threat_level'] = self._assess_threat(campaign)

        self.redis.setex(f"campaign:{campaign_id}", CAMPAIGN_TTL, json.dumps(campaign))
        self.redis.zadd('active_campaigns', {campaign_id: time.time()})

        if campaign['session_count'] % 5 == 0:
            self._notify_update(campaign)

        return campaign

    def _consider_new_campaign(self, fp: BehavioralFingerprint,
                               sim: Dict) -> Optional[Dict]:
        if not self.redis:
            return None

        pattern_key = f"potential:{fp.command_sequence_hash[:12]}"
        count = self.redis.incr(pattern_key)
        self.redis.expire(pattern_key, SESSION_TIMING_WINDOW)

        if count >= CAMPAIGN_ALERT_THRESHOLD:
            campaign = self._create_campaign(fp, sim)
            self.metrics['campaigns_detected'] += 1
            self._notify_new(campaign)
            return campaign
        return None

    def _track_for_future(self, fp: BehavioralFingerprint):
        if not self.redis:
            return
        data = fp.to_dict()
        self.redis.setex(f"fingerprint_data:{fp.fingerprint_id}", FINGERPRINT_CACHE_TTL, json.dumps(data))
        self.redis.zadd(f"window:{int(time.time() // SESSION_TIMING_WINDOW)}", {fp.fingerprint_id: time.time()})

    def _create_campaign(self, fp: BehavioralFingerprint, sim: Dict) -> Dict:
        campaign_id = hashlib.sha256(
            f"{fp.command_sequence_hash}:{datetime.utcnow().date()}".encode()
        ).hexdigest()[:16]

        campaign = {
            'campaign_id': campaign_id,
            'status': 'active',
            'threat_level': 'high' if fp.human_confidence > 0.7 else 'medium',
            'first_seen': fp.timestamp.isoformat(),
            'last_seen': fp.timestamp.isoformat(),
            'session_count': 1,
            'unique_ips': [fp.src_ip] if fp.src_ip else [],
            'sensors_hit': [fp.sensor_id],
            'tool_signatures': fp.tool_signatures,
            'tool_sequence': fp.tool_sequence_pattern,
            'command_pattern_hash': fp.command_sequence_hash,
            'human_confidence': fp.human_confidence,
            'session_pacing': fp.session_pacing,
            'representative_fingerprint': fp.to_dict(),
        }

        if self.redis:
            self.redis.setex(f"campaign:{campaign_id}", CAMPAIGN_TTL, json.dumps(campaign))
            self.redis.zadd('active_campaigns', {campaign_id: time.time()})
            self.redis.lpush('campaigns:active', campaign_id)
            self.redis.ltrim('campaigns:active', 0, 499)

        return campaign

    def _find_campaign_for_fingerprint(self, fp: BehavioralFingerprint) -> Optional[str]:
        if not self.redis:
            return None
        active = self.redis.zrange('active_campaigns', 0, -1)
        for cid in active:
            campaign = self._get_campaign(cid)
            if not campaign:
                continue
            rep = campaign.get('representative_fingerprint', {})
            if rep.get('command_sequence_hash') == fp.command_sequence_hash:
                return cid
            c_tools = set(campaign.get('tool_signatures', {}).keys())
            f_tools = set(fp.tool_signatures.keys())
            if c_tools and f_tools and (c_tools & f_tools):
                return cid
        return None

    def _get_campaign(self, campaign_id: str) -> Optional[Dict]:
        if not self.redis:
            return None
        raw = self.redis.get(f"campaign:{campaign_id}")
        return json.loads(raw) if raw else None

    def _assess_threat(self, campaign: Dict) -> str:
        score = 0
        if campaign.get('session_count', 0) > 10: score += 20
        if len(campaign.get('sensors_hit', [])) > 1: score += 30
        if len(campaign.get('unique_ips', [])) > 5: score += 20
        if campaign.get('human_confidence', 0) > 0.7: score += 20
        if score >= 60: return 'critical'
        if score >= 40: return 'high'
        if score >= 20: return 'medium'
        return 'low'

    def get_active_campaigns(self) -> List[Dict]:
        if not self.redis:
            return []
        ids = self.redis.lrange('campaigns:active', 0, 99)
        campaigns = []
        for cid in ids:
            c = self._get_campaign(cid)
            if c:
                c.pop('representative_fingerprint', None)
                campaigns.append(c)
        campaigns.sort(key=lambda x: x.get('last_seen', ''), reverse=True)
        return campaigns

    def _notify_new(self, campaign: Dict):
        self._send_telegram(
            f"📡 <b>NEW ATTACK CAMPAIGN DETECTED</b>\n"
            f"<b>ID:</b> <code>{campaign['campaign_id']}</code>\n"
            f"<b>Tools:</b> {', '.join(campaign.get('tool_signatures', {}).keys()) or 'unknown'}\n"
            f"<b>Threat:</b> {campaign['threat_level'].upper()}\n"
            f"<b>Human:</b> {'Yes' if campaign.get('human_confidence', 0) > 0.7 else 'No'}"
        )

    def _notify_update(self, campaign: Dict):
        self._send_telegram(
            f"📊 <b>CAMPAIGN UPDATE</b>\n"
            f"<b>ID:</b> <code>{campaign['campaign_id']}</code>\n"
            f"<b>Sessions:</b> {campaign.get('session_count', 0)}\n"
            f"<b>Sensors:</b> {len(campaign.get('sensors_hit', []))}\n"
            f"<b>IPs:</b> {len(campaign.get('unique_ips', []))}"
        )

    def _send_telegram(self, msg: str):
        if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
            return
        try:
            requests.post(
                f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"},
                timeout=5
            )
        except Exception as e:
            logger.error(f"Campaign Telegram alert failed: {e}")

# ────────────────────────────────────────────────────────────
# SINGLETON
# ────────────────────────────────────────────────────────────

_correlator: Optional[CampaignCorrelator] = None
_correlator_lock = threading.Lock()

def get_correlator() -> CampaignCorrelator:
    global _correlator
    if _correlator is None:
        with _correlator_lock:
            if _correlator is None:
                _correlator = CampaignCorrelator()
    return _correlator

def start_campaign_engine():
    get_correlator()
    logger.info("Campaign correlation engine started")

# ────────────────────────────────────────────────────────────
# FLASK BLUEPRINT
# ────────────────────────────────────────────────────────────

campaign_bp = Blueprint('campaign_correlator', __name__)

def _require_admin():
    try:

        if not is_logged_in() or not is_admin():
            return jsonify({"error": "Admin authentication required"}), 403
    except ImportError:
        pass
    return None

@campaign_bp.route('/api/campaigns', methods=['GET'])
def list_campaigns():
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    campaigns = get_correlator().get_active_campaigns()
    return jsonify({
        "ok": True,
        "count": len(campaigns),
        "campaigns": campaigns
    })

@campaign_bp.route('/api/campaigns/<campaign_id>', methods=['GET'])
def get_campaign(campaign_id):
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    c = get_correlator()._get_campaign(campaign_id)
    if not c:
        return jsonify({"error": "Campaign not found"}), 404
    c.pop('representative_fingerprint', None)
    return jsonify(c)

@campaign_bp.route('/api/campaigns/ingest', methods=['POST'])
def ingest_session():
    auth_err = _require_admin()
    if auth_err:
        return auth_err

    data = request.get_json(silent=True) or {}
    if not data:
        return jsonify({"error": "Session data required"}), 400

    result = get_correlator().ingest_session(data)
    return jsonify({"ok": True, "campaign": result})

@campaign_bp.route('/api/campaigns/stats', methods=['GET'])
def campaign_stats():
    # Allow logged-in users for home dashboard stats
    try:

        if is_logged_in():
            pass
        else:
            auth_err = _require_admin()
            if auth_err:
                return auth_err
    except:
        auth_err = _require_admin()
        if auth_err:
            return auth_err

    return jsonify({
        "ok": True,
        "metrics": dict(get_correlator().metrics),
        "active_campaigns": len(get_correlator().get_active_campaigns())
    })
