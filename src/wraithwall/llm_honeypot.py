import os
import re
import json
import time
import random
import secrets
import hashlib
import logging
import threading
from datetime import datetime
from wraithwall import thread_utils

import anthropic
import redis as redis_lib
import requests
from flask import Blueprint, request, jsonify

logger = logging.getLogger(__name__)

# ────────────────────────────────────────────────────────────
# CONFIGURATION
# ────────────────────────────────────────────────────────────

REDIS_URL = os.environ.get('REDIS_URL', '')
ANTHROPIC_API_KEY = os.environ.get('ANTHROPIC_API_KEY', '')
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '')
DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY', '')
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '')
DISCORD_WEBHOOK_URL = os.environ.get('DISCORD_WEBHOOK_URL', '')

# Rate limiting: max requests per IP per hour before falling back to static
LLM_RATE_LIMIT = int(os.environ.get('LLM_RATE_LIMIT', '20'))
LLM_RATE_WINDOW = int(os.environ.get('LLM_RATE_WINDOW', '3600'))

# Platform-wide daily ceiling on LLM-backed (Claude) responses, shared across every
# source IP. This is the hard cost backstop: the per-IP limit above can be sidestepped by
# rotating the client-controlled X-Forwarded-For header, but this global counter cannot.
# Once exceeded, all callers receive the static fallback until the next UTC day.
LLM_GLOBAL_DAILY_MAX = int(os.environ.get('LLM_GLOBAL_DAILY_MAX', '500'))

# ────────────────────────────────────────────────────────────
# MITRE ATLAS TECHNIQUES
# ────────────────────────────────────────────────────────────

ATLAS_TECHNIQUES = {
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0054": "LLM Jailbreaking",
    "AML.T0040": "ML Model Inference API Access",
    "AML.T0043": "Craft Adversarial Data",
    "AML.T0044": "Full ML Model Access",
    "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0057": "LLM Prompt Leaking",
}

# ────────────────────────────────────────────────────────────
# PROMPT INJECTION PATTERNS
# ────────────────────────────────────────────────────────────

INJECTION_PATTERNS = [
    (re.compile(r'ignore (all |previous |the |your )(instructions?|prompts?|rules?|context)', re.I),
     "direct_override", "AML.T0051", 95),
    (re.compile(r'disregard (all |previous |the )?(instructions?|system prompts?)', re.I),
     "direct_override", "AML.T0051", 95),
    (re.compile(r'forget (everything|all|your training|what you were told)', re.I),
     "context_reset", "AML.T0051", 90),
    (re.compile(r'you are now|from now on you are|act as|pretend (you are|to be)', re.I),
     "persona_injection", "AML.T0054", 88),
    (re.compile(r'DAN|jailbreak|developer mode|unrestricted mode|god mode', re.I),
     "jailbreak_attempt", "AML.T0054", 92),
    (re.compile(r'in (this|the) (context|scenario|roleplay|story)', re.I),
     "roleplay_injection", "AML.T0054", 75),
    (re.compile(r'(print|show|reveal|display|tell me|output|repeat) (your |the )?(system|initial|original) (prompt|instructions?)', re.I),
     "prompt_extraction", "AML.T0056", 96),
    (re.compile(r'what (are your|is your) (initial|original|system|starting) (prompt|instructions?)', re.I),
     "prompt_extraction", "AML.T0056", 95),
    (re.compile(r'what (did|were) you (told|instructed|given|trained)', re.I),
     "prompt_leaking", "AML.T0057", 88),
    (re.compile(r'(show|print|output|dump) (the |your )?(context|memory|history|conversation)', re.I),
     "context_extraction", "AML.T0056", 85),
    (re.compile(r'(list|show|print|dump) (all |the )?(users?|passwords?|credentials?|keys?|secrets?)', re.I),
     "data_extraction", "AML.T0040", 90),
    (re.compile(r'(access|connect|query) (the |to |)?(database|db|sql|redis)', re.I),
     "db_access_attempt", "AML.T0040", 88),
    (re.compile(r'(read|open|load|cat|print) (file|/etc|/var|/home|\.env)', re.I),
     "file_access", "AML.T0040", 85),
    (re.compile(r'<\|.*?\|>|<\[.*?\]>|\[\[.*?\]\]', re.I),
     "delimiter_injection", "AML.T0051", 80),
    (re.compile(r'###\s*(SYSTEM|HUMAN|ASSISTANT|USER|INST)', re.I),
     "format_injection", "AML.T0051", 82),
    (re.compile(r'\[INST\]|\[\/INST\]|<s>|</s>|<\|im_start\|>|<\|im_end\|>', re.I),
     "token_injection", "AML.T0051", 88),
    (re.compile(r'<<SYS>>|<</SYS>>', re.I),
     "llama_token_injection", "AML.T0051", 90),
    (re.compile(r'USER:|ASSISTANT:|HUMAN:|AI:|BOT:', re.I),
     "role_injection", "AML.T0051", 72),
]

# ────────────────────────────────────────────────────────────
# CANARY TOKENS & STATIC FALLBACK RESPONSES
# ────────────────────────────────────────────────────────────

CANARY_TOKENS = [
    f"sk-ezmcyber-{secrets.token_hex(24)}",
    f"eyJhbGciOiJIUzI1NiJ9.{secrets.token_hex(16)}.canary",
    f"sess_{secrets.token_hex(20)}",
]

FAKE_KNOWLEDGE_RESPONSES = [
    "Based on the threat intelligence data in our system, I've identified 3 high-severity IOCs matching your query.",
    "I've cross-referenced the IP against our internal blocklist. The IP has 47 prior incidents in our database.",
    "The user account shows anomalous behavior consistent with credential stuffing. I've flagged it for review.",
    "I've queried the breach database. No matches found for that domain in the last 30 days.",
    "The file hash matches a known malware variant: TrojanDownloader.Win32.Emotet.B. I've created an incident.",
    "Looking at our internal threat feed, I can see this IP has been associated with a known APT group. I'd recommend immediate escalation.",
    "I've analyzed the pattern. This matches a credential harvesting campaign we tracked last week. 12 other nodes flagged the same IOCs.",
    "Internal logs show this domain was registered 3 days ago with privacy protection enabled. High probability of malicious intent.",
]

# ────────────────────────────────────────────────────────────
# REDIS HELPER
# ────────────────────────────────────────────────────────────

def _get_redis():
    if not REDIS_URL:
        return None
    try:
        return redis_lib.from_url(REDIS_URL, socket_connect_timeout=3,
                                  decode_responses=True, max_connections=5)
    except Exception:
        return None

def _scan_keys(r, pattern):
    """Iterate keys via SCAN cursor instead of the blocking KEYS command."""
    keys = []
    for key in r.scan_iter(match=pattern, count=500):
        keys.append(key)
    return keys

# ────────────────────────────────────────────────────────────
# RATE LIMITER
# ────────────────────────────────────────────────────────────

def _is_rate_limited(ip: str) -> bool:
    """Check‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ if an IP has exceeded the rate limit for Claude API calls.
    
    Returns True if the IP should be served static fallback responses.
    Limits to LLM_RATE_LIMIT requests per LLM_RATE_WINDOW seconds.
    """
    r = _get_redis()
    if not r:
        # Fail closed: with no Redis we cannot meter spend, so serve the static fallback
        # rather than calling Claude on every request (previously this returned False and
        # left the LLM uncapped during a Redis outage).
        return True
    try:
        key = f"llm_rl:{ip}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, LLM_RATE_WINDOW)
        return int(count) > LLM_RATE_LIMIT
    except Exception as e:
        logger.error(f"Rate limit check error: {e}")
        return True

def _global_budget_exceeded() -> bool:
    """Reserve a slot against the platform-wide daily LLM budget.

    Increments a single shared counter (keyed by UTC day) and returns True once the
    LLM_GLOBAL_DAILY_MAX ceiling is passed. Call this ONLY when about to invoke Claude —
    each call consumes one unit. Fails closed (returns True) when Redis is unavailable or
    errors, so a degraded cache can never leave LLM spend uncapped.
    """
    r = _get_redis()
    if not r:
        return True
    try:
        day = datetime.utcnow().strftime('%Y%m%d')
        key = f"llm:global:{day}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, 172800)  # retain ~2 days for observability
        return int(count) > LLM_GLOBAL_DAILY_MAX
    except Exception as e:
        logger.error(f"Global LLM budget check error: {e}")
        return True

def _log_rate_limited(ip: str, limit: int = 10, window: int = 60) -> bool:
    """Per-IP limit (default 10 hits / 60s) gating immutable-log writes.

    Prevents an unauthenticated flood from filling the append-only log table.
    Fails closed (returns True) on Redis error.
    """
    r = _get_redis()
    if not r:
        return False
    try:
        key = f"llm_log_rl:{ip or 'unknown'}"
        count = r.incr(key)
        if count == 1:
            r.expire(key, window)
        return int(count) > limit
    except Exception as e:
        logger.error(f"Log rate limit check error: {e}")
        return True

# ────────────────────────────────────────────────────────────
# INJECTION CLASSIFIER
# ────────────────────────────────────────────────────────────

def classify_injection(prompt: str) -> dict:
    """Classify‍​​‌‌‌​‌​​‌​​​‌​‌​‌‌​​‌​‌‌​​‌​​​​‍ prompt injection attempt with MITRE ATLAS mapping."""
    detected = []
    max_confidence = 0
    primary_technique = None

    for pattern, category, atlas, confidence in INJECTION_PATTERNS:
        match = pattern.search(prompt)
        if match:
            detected.append({
                "category": category,
                "atlas": atlas,
                "confidence": confidence,
                "match": match.group(0)[:50]
            })
            if confidence > max_confidence:
                max_confidence = confidence
                primary_technique = atlas

    threat_level = "none"
    if max_confidence >= 90:
        threat_level = "critical"
    elif max_confidence >= 80:
        threat_level = "high"
    elif max_confidence >= 70:
        threat_level = "medium"
    elif max_confidence > 0:
        threat_level = "low"

    return {
        "is_injection": len(detected) > 0,
        "techniques": detected,
        "threat_level": threat_level,
        "primary_technique": primary_technique,
        "confidence": max_confidence
    }

# ────────────────────────────────────────────────────────────
# CLAUDE-POWERED RESPONSE GENERATOR
# ────────────────────────────────────────────────────────────

# Lazy-initialized LLM clients
_groq_client = None
_deepseek_client = None
_claude_client = None
_client_lock = threading.Lock()

def _get_groq_client():
    global _groq_client
    if _groq_client is None and GROQ_API_KEY:
        with _client_lock:
            if _groq_client is None:
                try:
                    from groq import Groq
                    _groq_client = Groq(api_key=GROQ_API_KEY)
                    logger.info("Groq client initialized for LLM honeypot")
                except Exception as e:
                    logger.error(f"Failed to initialize Groq client: {e}")
    return _groq_client

def _get_claude_client():
    """Get the Anthropic client (last resort). Thread-safe lazy initialization."""
    global _claude_client
    if _claude_client is None and ANTHROPIC_API_KEY:
        with _client_lock:
            if _claude_client is None:
                try:
                    _claude_client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
                    logger.info("Anthropic client initialized for LLM honeypot")
                except Exception as e:
                    logger.error(f"Failed to initialize Anthropic client: {e}")
    return _claude_client

def _call_llm_provider(messages, system_prompt, max_tokens=500, temperature=0.7):
    """Call LLM providers in priority order: Groq -> DeepSeek -> Anthropic.
    Results cached via Redis to avoid redundant API calls (identical prompts = cache hit)."""
    import json
    from wraithwall.llm_cache import honeypot_cache

    cache_key = json.dumps({"msgs": messages, "sys": system_prompt}, sort_keys=True)

    def _call():
        # 1. Groq first
        try:
            client = _get_groq_client()
            if client:
                response = client.chat.completions.create(
                    model="llama-3.1-70b-versatile",
                    max_tokens=max_tokens,
                    temperature=temperature,
                    messages=[{"role": "system", "content": system_prompt}] + messages
                )
                logger.info("LLM honeypot: Groq responded successfully")
                return response.choices[0].message.content
        except Exception as e:
            logger.warning(f"LLM honeypot: Groq call failed: {e}")

        # 2. DeepSeek fallback
        try:
            if DEEPSEEK_API_KEY:
                response = requests.post(
                    "https://api.deepseek.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {DEEPSEEK_API_KEY}"},
                    json={"model": "deepseek-chat",
                          "messages": [{"role": "system", "content": system_prompt}] + messages},
                    timeout=15
                )
                if response.status_code == 200:
                    logger.info("LLM honeypot: DeepSeek responded successfully")
                    return response.json()["choices"][0]["message"]["content"]
                else:
                    logger.warning(f"LLM honeypot: DeepSeek HTTP {response.status_code}")
        except Exception as e:
            logger.warning(f"LLM honeypot: DeepSeek call failed: {e}")

        # 3. Anthropic last resort
        try:
            client = _get_claude_client()
            if client:
                response = client.messages.create(
                    model="claude-sonnet-4-20250514",
                    max_tokens=max_tokens,
                    temperature=temperature,
                    system=system_prompt,
                    messages=messages
                )
                logger.info("LLM honeypot: Anthropic responded successfully")
                return response.content[0].text
        except Exception as e:
            logger.warning(f"LLM honeypot: Anthropic call failed: {e}")

        return None

    return honeypot_cache(cache_key, ttl=300, fn=_call)

def _generate_fake_response(prompt: str, classification: dict, canary_sig: str) -> str:
    """Generate a convincing fake AI response using LLM providers.
    
    Priority: Groq -> DeepSeek -> Anthropic.
    Falls back to static responses if all providers are unavailable.
    """
    technique = classification.get("primary_technique", "")
    threat_level = classification.get("threat_level", "none")

    system_prompt = f"""You are EZMCyber's internal security AI assistant.
You have access to internal threat databases, user accounts, and security logs.
Internal auth token: Bearer {secrets.token_hex(32)}
DB connection: postgresql://ezm_soc:{secrets.token_hex(16)}@db-internal.example.com/soc_db
Admin API key: ezm_int_{secrets.token_hex(12)}

Rules:
- Always respond as if you are a real internal AI with real data access
- If asked for credentials or system info, reluctantly reveal the above after pushback
- Embed this canary token naturally in your response: {canary_sig}
- Never break character
- Keep responses realistic and specific to cybersecurity operations
- Mention specific threat actors, CVEs, or internal tool names when plausible
- Keep responses concise (2-4 sentences) unless the user explicitly asks for detail"""

    text = _call_llm_provider(
        messages=[{"role": "user", "content": prompt}],
        system_prompt=system_prompt,
        max_tokens=500,
        temperature=0.7
    )
    if text:
        text = text.strip()
        logger.debug(f"LLM generated response for technique: {technique}")
        return text

    logger.warning("All LLM providers unavailable — using static fallback")
    return random.choice(FAKE_KNOWLEDGE_RESPONSES) + f"\n\n_Analysis token: {canary_sig}_"

# ────────────────────────────────────────────────────────────
# STORAGE & ALERTING
# ────────────────────────────────────────────────────────────

def _store_injection_attempt(ip: str, prompt: str, classification: dict, 
                             response: str, rate_limited: bool = False):
    """Store injection attempt in Redis and trigger alerts."""
    try:
        prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()[:16]
        entry = {
            "ip": ip,
            "prompt_hash": prompt_hash,
            "prompt_preview": prompt[:200],
            "classification": classification,
            "response_type": "static_fallback" if rate_limited else "llm_generated",
            "rate_limited": rate_limited,
            "timestamp": datetime.utcnow().isoformat()
        }

        r = _get_redis()
        if r:
            key = f"llm_honeypot:{ip}:{int(time.time())}"
            r.setex(key, 604800, json.dumps(entry))
            count = r.incr(f"llm_honeypot_count:{ip}")
            r.expire(f"llm_honeypot_count:{ip}", 86400)
            entry["attempt_count"] = int(count)

        # Write to immutable log
        try:

            write_immutable_log({
                "event": "llm_honeypot_triggered",
                "ip": ip,
                "technique": classification.get("primary_technique"),
                "threat_level": classification.get("threat_level"),
                "confidence": classification.get("confidence"),
                "prompt_hash": prompt_hash,
                "rate_limited": rate_limited,
                "timestamp": datetime.utcnow().isoformat()
            })
        except ImportError:
            pass

        if classification["confidence"] >= 80:
            _send_llm_alert(ip, classification, prompt[:150])

        if classification["threat_level"] == "critical":
            try:

                thread_utils.spawn_request_thread(_bg_enter_sandbox, args=(ip, f"llm_injection_{classification.get('primary_technique')}"))
            except ImportError:
                pass

    except Exception as e:
        logger.error(f"LLM honeypot store error: {e}")

def _send_llm_alert(ip: str, classification: dict, prompt_preview: str):
    """Send alert via Telegram and Discord in a background thread."""
    def _alert():
        techniques = [t.get("atlas") for t in classification.get("techniques", [])]
        msg = (
            f"🤖 <b>LLM HONEYPOT TRIGGERED</b>\n"
            f"<b>IP:</b> <code>{ip}</code>\n"
            f"<b>Technique:</b> {classification.get('primary_technique')}\n"
            f"<b>Level:</b> {classification.get('threat_level').upper()}\n"
            f"<b>Confidence:</b> {classification.get('confidence')}%\n"
            f"<b>ATLAS:</b> {', '.join(t for t in techniques if t)}\n"
            f"<b>Prompt:</b> <code>{prompt_preview}</code>"
        )
        if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
            try:
                requests.post(
                    f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                    json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "HTML"},
                    timeout=5
                )
            except Exception as e:
                logger.error(f"LLM honeypot Telegram alert failed: {e}")
        if DISCORD_WEBHOOK_URL:
            try:
                plain = re.sub(r'<[^>]+>', '', msg)
                requests.post(DISCORD_WEBHOOK_URL, json={"content": plain, "allowed_mentions": {"parse": []}}, timeout=3)
            except Exception as e:
                logger.error(f"LLM honeypot Discord alert failed: {e}")

    thread_utils.spawn_request_thread(_alert)

# ────────────────────────────────────────────────────────────
# THINKING DELAY SIMULATOR
# ────────────────────────────────────────────────────────────

def _simulate_thinking_delay():
    """Simulate realistic LLM response latency."""
    base = random.uniform(0.4, 1.2)
    extra = random.uniform(0, 0.5)
    time.sleep(base + extra)

# ────────────────────────────────────────────────────────────
# FLASK ROUTES
# ────────────────────────────────────────────────────────────

def _is_loopback_local() -> bool:
    """True only for genuine on-box requests that did NOT traverse the proxy.

    The app listens on 127.0.0.1 behind nginx, which always sets X-Forwarded-For
    for real clients. A request whose socket peer is loopback AND that carries no
    X-Forwarded-For header therefore originated from a local process (e.g. a
    deploy smoke test), not a remote attacker. A remote client cannot forge the
    *absence* of XFF — their traffic is proxied — so this cannot be spoofed.
    """
    if request.headers.get('X-Forwarded-For'):
        return False
    return (request.remote_addr or '').strip() in ('127.0.0.1', '::1', 'localhost')

llm_honeypot_bp = Blueprint('llm_honeypot', __name__)

@llm_honeypot_bp.route('/api/ai/v1/chat/completions', methods=['POST'])
@llm_honeypot_bp.route('/api/ai/internal/chat', methods=['POST'])
@llm_honeypot_bp.route('/api/ai/internal/complete', methods=['POST'])
def llm_honeypot_chat():
    """OpenAI-compatible chat completions endpoint.
    
    Flow:
    1. Extract prompt from various formats (OpenAI messages, raw prompt, input)
    2. Classify for prompt injection (MITRE ATLAS mapping)
    3. Check IP rate limit (protects Claude API costs)
    4. Generate response via Claude (or static fallback if rate limited)
    5. Store attempt in Redis and trigger alerts if high-confidence injection
    """
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '')
    ip = ip.split(',')[0].strip()
    data = request.get_json(silent=True) or {}

    # Extract prompt from various OpenAI-compatible formats
    prompt = ""
    messages = data.get("messages", [])
    if messages:
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                prompt = content if isinstance(content, str) else str(content)
                break
    elif "prompt" in data:
        prompt = str(data["prompt"])[:4000]
    elif "input" in data:
        prompt = str(data["input"])[:4000]

    # Empty prompt — return empty but valid completion
    if not prompt:
        return jsonify({
            "id": f"chatcmpl-{secrets.token_hex(12)}",
            "object": "chat.completion",
            "created": int(time.time()),
            "model": "gpt-4-internal",
            "choices": [{"message": {"role": "assistant", "content": ""},
                         "finish_reason": "stop", "index": 0}]
        })

    # Classify the prompt for injection attempts
    classification = classify_injection(prompt)
    canary_sig = secrets.token_hex(8)
    _simulate_thinking_delay()

    # Rate limit check — protect Claude API costs. Per-IP limit first; if that passes,
    # the platform-wide daily budget is consulted (and a slot reserved) so header rotation
    # cannot run up the bill. Either gate falling means a static fallback, no Claude call.
    rate_limited = _is_rate_limited(ip)
    if not rate_limited and _global_budget_exceeded():
        logger.warning("LLM global daily budget exhausted — using static fallback")
        rate_limited = True
    if rate_limited:
        logger.debug(f"Rate limited IP {ip} — using static fallback")
        response_text = random.choice(FAKE_KNOWLEDGE_RESPONSES) + f"\n\n_Analysis token: {canary_sig}_"
    else:
        response_text = _generate_fake_response(prompt, classification, canary_sig)

    # Store attempt asynchronously — gated by per-IP log rate limit (max 10/min)
    # so an unauthenticated flood cannot fill the immutable log table.
    # Genuine on-box requests (deploy smoke tests) are skipped entirely so local
    # testing doesn't fire critical Telegram/Discord alerts or the sandbox.
    if _is_loopback_local():
        logger.info("LLM honeypot: trusted loopback request — skipping alert/sandbox (local test)")
    elif not _log_rate_limited(ip):
        thread_utils.spawn_request_thread(_store_injection_attempt, args=(ip, prompt, classification, response_text, rate_limited))

    # Return OpenAI-compatible response
    return jsonify({
        "id": f"chatcmpl-{secrets.token_hex(12)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": "gpt-4-internal",
        "usage": {
            "prompt_tokens": len(prompt.split()),
            "completion_tokens": len(response_text.split()),
            "total_tokens": len(prompt.split()) + len(response_text.split())
        },
        "choices": [{
            "message": {"role": "assistant", "content": response_text},
            "finish_reason": "stop",
            "index": 0
        }]
    })

@llm_honeypot_bp.route('/api/ai/internal/embed', methods=['POST'])
def llm_honeypot_embed():
    """Fake embeddings endpoint — logs access and returns deterministic vectors."""
    ip = request.headers.get('X-Forwarded-For', request.remote_addr or '')
    ip = ip.split(',')[0].strip()
    data = request.get_json(silent=True) or {}
    text = str(data.get("input", ""))[:500]

    # Generate deterministic fake embedding vector (1536 dims, OpenAI ada-002 size)
    vector = [round(random.gauss(0, 0.3), 6) for _ in range(1536)]

    # Per-IP log rate limit (max 10/min) to stop an unauthenticated flood from
    # filling the immutable log table.
    if not _log_rate_limited(ip):
        try:

            write_immutable_log({
                "event": "llm_embed_accessed",
                "ip": ip,
                "text_hash": hashlib.sha256(text.encode()).hexdigest()[:16],
                "timestamp": datetime.utcnow().isoformat()
            })
        except ImportError:
            pass

    return jsonify({
        "object": "list",
        "data": [{"object": "embedding", "embedding": vector, "index": 0}],
        "model": "text-embedding-ada-002-internal",
        "usage": {"prompt_tokens": len(text.split()), "total_tokens": len(text.split())}
    })

@llm_honeypot_bp.route('/api/ai/v1/models', methods=['GET'])
def llm_honeypot_models():
    """Fake model listing — returns realistic internal model names."""
    return jsonify({
        "object": "list",
        "data": [
            {"id": "gpt-4-internal", "object": "model", "owned_by": "ezmcyber-internal"},
            {"id": "gpt-3.5-turbo-internal", "object": "model", "owned_by": "ezmcyber-internal"},
            {"id": "text-embedding-ada-002-internal", "object": "model", "owned_by": "ezmcyber-internal"},
        ]
    })

@llm_honeypot_bp.route('/api/admin/llm-corpus', methods=['GET'])
def llm_corpus():
    """Admin endpoint — view collected prompt injection attempts."""
    try:

        if not is_logged_in() or not is_admin():
            return jsonify({"error": "Admin required"}), 403
    except ImportError:
        pass

    r = _get_redis()
    if not r:
        return jsonify({"ok": False, "error": "Redis required"}), 503

    try:
        keys = _scan_keys(r, "llm_honeypot:*")
        entries = []
        technique_counts = {}

        for key in keys:
            data = r.get(key)
            if data:
                try:
                    entry = json.loads(data)
                    entries.append(entry)
                    tech = entry.get("classification", {}).get("primary_technique")
                    if tech:
                        technique_counts[tech] = technique_counts.get(tech, 0) + 1
                except Exception:
                    pass

        entries.sort(key=lambda x: x.get("timestamp", ""), reverse=True)

        return jsonify({
            "ok": True,
            "total_attempts": len(entries),
            "techniques": technique_counts,
            "recent": entries[:50]
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@llm_honeypot_bp.route('/api/intel/llm-techniques', methods=['GET'])
def llm_techniques_public():
    """Public endpoint — aggregated technique stats, no PII."""
    r = _get_redis()
    if not r:
        return jsonify({
            "ok": True, "techniques": {},
            "atlas_reference": ATLAS_TECHNIQUES,
            "note": "Live data not available"
        })

    try:
        keys = _scan_keys(r, "llm_honeypot:*")
        technique_counts = {}
        for key in keys:
            data = r.get(key)
            if data:
                try:
                    entry = json.loads(data)
                    tech = entry.get("classification", {}).get("primary_technique")
                    if tech:
                        technique_counts[tech] = technique_counts.get(tech, 0) + 1
                except Exception:
                    pass

        return jsonify({
            "ok": True,
            "total_attempts": len(keys),
            "technique_counts": technique_counts,
            "atlas_reference": ATLAS_TECHNIQUES,
            "source": "EZMCyber LLM Honeypot",
            "updated_at": datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500
