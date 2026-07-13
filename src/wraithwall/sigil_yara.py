# yara-python==4.5.1

import os
import json
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

logger = logging.getLogger(__name__)

REDIS_URL = os.environ.get("REDIS_URL", "")
YARA_RESULT_TTL = int(os.environ.get("YARA_RESULT_TTL", str(60 * 60 * 24 * 30)))

TIER2_SOURCE_URL = "https://github.com/Yara-Rules/rules"
TIER2_PINNED_REF = "v2.1.0"
TIER2_REVIEW_REQUIRED = (
    "Tier 2 community rules pinned to {} commit/release {}."
    " Any update to TIER2_PINNED_REF requires documented security review"
    " and re-validation against the current sample corpus. Do not change"
    " without a signed-off review in the repository change log."
).format(TIER2_SOURCE_URL, TIER2_PINNED_REF)

TIER3_REASON = (
    "Tier 3 auto-generated rules are NOT implemented."
    " Auto-generation from honeypot sample clustering is deferred"
    " until the corpus reaches a statistically significant threshold"
    " (>500 unique families with >50 samples each) and a manual"
    " false-positive audit process exists. Revisit when the honeypot"
    " has been running at production scale for at least 6 months."
)

MIRAI_RULE = r"""
rule Mirai_Botnet_Tier1 {
    meta:
        author = "WraithWall Sigil"
        description = "Detects Mirai botnet variants observed in honeypot captures"
        reference = "Curated from samples collected in cowrie honeypots"
        tier = 1
        family = "Mirai"
    strings:
        $s1 = "/dev/watchdog" ascii wide
        $s2 = "busybox" ascii wide nocase
        $s3 = "GET /cdn-cgi/" ascii
        $s4 = "attack_udp_generic" ascii wide nocase
        $s5 = { 2F 64 65 76 2F 6D 69 73 63 2F 77 61 74 63 68 64 6F 67 }
    condition:
        any of them
}
"""

GAFGYT_RULE = r"""
rule Gafgyt_BASHLITE_Tier1 {
    meta:
        author = "WraithWall Sigil"
        description = "Detects Gafgyt/BASHLITE IoT botnet variants"
        reference = "Curated from samples collected in cowrie honeypots"
        tier = 1
        family = "Gafgyt"
    strings:
        $s1 = "BASHBOT" ascii wide
        $s2 = "wget http" ascii nocase
        $s3 = "tftp -r" ascii nocase
        $s4 = { 42 4F 54 3A 20 63 6F 6E 6E 65 63 74 69 6F 6E }
        $s5 = "XOR'ing" ascii nocase
    condition:
        any of them
}
"""

XORDDOS_RULE = r"""
rule XorDDoS_Linux_Tier1 {
    meta:
        author = "WraithWall Sigil"
        description = "Detects XorDDoS Linux rootkit/trojan variants"
        reference = "Curated from samples collected in cowrie honeypots"
        tier = 1
        family = "XorDDoS"
    strings:
        $s1 = "/lib/libgcc4.so"
        $s2 = "xorddos" ascii wide nocase
        $s3 = { 78 6F 72 20 64 65 63 6F 64 65 }
        $s4 = "rootkit" ascii wide nocase
        $s5 = { 2F 6C 69 62 2F 6C 69 62 67 63 63 34 2E 73 6F }
    condition:
        2 of them
}
"""

TSUNAMI_RULE = r"""
rule Tsunami_Kaiten_IRC_Tier1 {
    meta:
        author = "WraithWall Sigil"
        description = "Detects Tsunami/Kaiten IRC-based backdoor variants"
        reference = "Curated from samples collected in cowrie honeypots"
        tier = 1
        family = "Tsunami"
    strings:
        $s1 = "PRIVMSG #" ascii
        $s2 = "NICK [" ascii
        $s3 = { 4A 4F 49 4E 20 23 }
        $s4 = "PING :" ascii
        $s5 = { 50 52 49 56 4D 53 47 }
    condition:
        any of them
}
"""

HAJIME_RULE = r"""
rule Hajime_P2P_Tier1 {
    meta:
        author = "WraithWall Sigil"
        description = "Detects Hajime P2P IoT worm variants"
        reference = "Curated from samples collected in cowrie honeypots"
        tier = 1
        family = "Hajime"
    strings:
        $s1 = ".i=/init.ps1" ascii
        $s2 = ".i" ascii fullword
        $s3 = "peer" ascii nocase
        $s4 = { 2E 69 3D 2F 69 6E 69 74 2E 70 73 31 }
        $s5 = "HaJ" ascii
    condition:
        any of them
}
"""

TIER1_RULES = [MIRAI_RULE, GAFGYT_RULE, XORDDOS_RULE, TSUNAMI_RULE, HAJIME_RULE]
RULE_COUNT = len(TIER1_RULES)

_redis = None
_redis_tried = False

def _get_redis() -> Optional[Any]:
    global _redis, _redis_tried
    if _redis is not None or _redis_tried:
        return _redis
    _redis_tried = True
    if not REDIS_URL:
        return None
    try:
        import redis as redis_lib

        _redis = redis_lib.from_url(
            REDIS_URL, socket_connect_timeout=3, decode_responses=True, max_connections=5
        )
        _redis.ping()
    except Exception as exc:
        logger.warning("sigil_yara: Redis unavailable: %s", exc)
        _redis = None
    return _redis

_yara_rules = None

def init_yara() -> Any:
    """Compile hand-authored Tier 1 YARA rules and return the compiled rules object.

    Returns:
        yara.Rules: Compiled YARA rules object, or None if compilation fails.
    """
    global _yara_rules
    if _yara_rules is not None:
        return _yara_rules
    try:
        import yara

        combined = "\n".join(TIER1_RULES)
        _yara_rules = yara.compile(source=combined)
        logger.info("sigil_yara: compiled %d Tier 1 rules", RULE_COUNT)
        return _yara_rules
    except ImportError:
        logger.error("sigil_yara: yara-python not installed")
        return None
    except Exception as exc:
        logger.error("sigil_yara: rule compilation failed: %s", exc)
        return None

def get_malware_family(matches: List[Any]) -> str:
    """Derive malware family name from YARA rule match metadata.

    Args:
        matches: A list of yara.Match objects from a scan.

    Returns:
        The primary malware family name, or "unknown" if none can be determined.
    """
    if not matches:
        return "unknown"
    families: Dict[str, int] = {}
    for match in matches:
        family = match.meta.get("family", match.rule)
        families[family] = families.get(family, 0) + 1
    if not families:
        return "unknown"
    return max(families, key=lambda k: families[k])

def analyze_file(file_path: str, file_hash: str) -> Dict[str, Any]:
    """Scan a file on disk with compiled Tier 1 YARA rules.

    The file is opened read-only and never executed. Matches and derived
    malware family are persisted to Redis.

    Args:
        file_path: Absolute or relative path to the file to scan.
        file_hash: SHA-256 hex digest of the file for Redis key and auditing.

    Returns:
        A dict with keys:
            - matches: list of matching rule names
            - malware_family: derived primary family string
            - rule_count: number of compiled rules used for the scan
            - error: error message string if the scan failed
    """
    rules = init_yara()
    if rules is None:
        return {
            "matches": [],
            "malware_family": "unknown",
            "rule_count": 0,
            "error": "yara rules not available",
        }
    try:
        result = rules.match(file_path)
    except Exception as exc:
        logger.error("sigil_yara: file scan failed for %s: %s", file_hash, exc)
        return {
            "matches": [],
            "malware_family": "unknown",
            "rule_count": RULE_COUNT,
            "error": str(exc),
        }
    match_names = [m.rule for m in result]
    family = get_malware_family(result)
    output = {
        "matches": match_names,
        "malware_family": family,
        "rule_count": RULE_COUNT,
    }
    store_analysis_result(file_hash, output)
    return output

def analyze_bytes(data: bytes, file_hash: str) -> Dict[str, Any]:
    """Scan in-memory bytes with compiled Tier 1 YARA rules.

    The data is never written to disk or executed. Matches and derived
    malware family are persisted to Redis.

    Args:
        data: Raw file bytes to scan.
        file_hash: SHA-256 hex digest of the data for Redis key and auditing.

    Returns:
        A dict with keys:
            - matches: list of matching rule names
            - malware_family: derived primary family string
            - rule_count: number of compiled rules used for the scan
            - error: error message string if the scan failed
    """
    rules = init_yara()
    if rules is None:
        return {
            "matches": [],
            "malware_family": "unknown",
            "rule_count": 0,
            "error": "yara rules not available",
        }
    try:
        result = rules.match(data=data)
    except Exception as exc:
        logger.error("sigil_yara: bytes scan failed for %s: %s", file_hash, exc)
        return {
            "matches": [],
            "malware_family": "unknown",
            "rule_count": RULE_COUNT,
            "error": str(exc),
        }
    match_names = [m.rule for m in result]
    family = get_malware_family(result)
    output = {
        "matches": match_names,
        "malware_family": family,
        "rule_count": RULE_COUNT,
    }
    store_analysis_result(file_hash, output)
    return output

def store_analysis_result(file_hash: str, result: Dict[str, Any]) -> bool:
    """Persist YARA analysis result to Redis under yara:result:{hash}.

    Args:
        file_hash: SHA-256 hex digest used as the Redis key suffix.
        result: Dict with matches, malware_family, and rule_count.

    Returns:
        True if the result was stored, False if Redis is unavailable.
    """
    r = _get_redis()
    if r is None:
        return False
    try:
        key = f"yara:result:{file_hash}"
        serialized = json.dumps(result, ensure_ascii=False)
        r.set(key, serialized, ex=YARA_RESULT_TTL)
        return True
    except Exception as exc:
        logger.warning("sigil_yara: failed to store result for %s: %s", file_hash, exc)
        return False
