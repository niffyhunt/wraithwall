"""
Command intent classifier for Cowrie honeypot sessions.

Classifies shell commands into five intent categories using regex/keyword matching.
No LLM calls -- purely rules-based, false-positive resistant.
"""

import re
from typing import Dict, List, Any, Optional, Tuple
from collections import Counter

# ── Intent constants ──

INTENT_DOWNLOAD_EXECUTABLE = "DOWNLOAD_EXECUTABLE"
INTENT_ESTABLISH_PERSISTENCE = "ESTABLISH_PERSISTENCE"
INTENT_ESCALATE_PRIVILEGE = "ESCALATE_PRIVILEGE"
INTENT_ENUMERATE_SYSTEM = "ENUMERATE_SYSTEM"
INTENT_ENUMERATE_NETWORK = "ENUMERATE_NETWORK"

ALL_INTENTS: List[str] = [
    INTENT_DOWNLOAD_EXECUTABLE,
    INTENT_ESTABLISH_PERSISTENCE,
    INTENT_ESCALATE_PRIVILEGE,
    INTENT_ENUMERATE_SYSTEM,
    INTENT_ENUMERATE_NETWORK,
]

# ── Regex patterns ──

_CMD_SEP_RE: re.Pattern[str] = re.compile(r'\s*(?:&&|\|\||[;|])\s*')

_FIRST_WORD_RE: re.Pattern[str] = re.compile(r'^\s*(\S+)')

_REDIRECT_RE: re.Pattern[str] = re.compile(r'[12]?>>?\s*(\S+)')

_PERSIST_FILENAME_RE: re.Pattern[str] = re.compile(
    r'(?:\.bashrc|\.profile|\.bash_profile|\.bash_login|'
    r'\.zshrc|\.zprofile|rc\.local|authorized_keys|'
    r'crontab|\.ssh/config|sshd_config|\.bash_logout)$'
)

_PERSIST_PATH_RE: re.Pattern[str] = re.compile(
    r'(?:/etc/cron\.|/etc/init\.d/|/etc/systemd/|'
    r'\.ssh/authorized_keys|/var/spool/cron/|'
    r'/etc/rc\.d/|/lib/systemd/system/)'
)

_KERNEL_EXPLOIT_RE: re.Pattern[str] = re.compile(
    r'(?:dirtycow|dirty.cow|pwnkit|polkit|overlayfs|'
    r'netfilter|nftables|sudoedit|baron.samedit|'
    r'gameover|enlightenment|diamond|'
    r'CVE-\d{4}-\d{4,})',
    re.IGNORECASE,
)

_SETUID_SYMBOLIC_RE: re.Pattern[str] = re.compile(r'[ugoa]?\+s\b')

_SETUID_OCTAL_RE: re.Pattern[str] = re.compile(r'\b([0-7]{3,4})\b')

_FIND_SUID_RE: re.Pattern[str] = re.compile(r'-perm\s+[-/]?\d*4\d{2}')

_FIND_SYSTEM_PATH_RE: re.Pattern[str] = re.compile(r'\s/(?:\s|etc|var|proc|opt|root|home|tmp)')

_CAT_PROC_RE: re.Pattern[str] = re.compile(r'/proc/')

_CAT_ETC_SYSTEM_RE: re.Pattern[str] = re.compile(
    r'/etc/(?:passwd|shadow|group|sudoers|issue|release|os-release|hostname|fstab|'
    r'cron|shells|login\.defs|security/)'
)

_CAT_LOG_RE: re.Pattern[str] = re.compile(r'/var/log/')

_LS_ETC_RE: re.Pattern[str] = re.compile(r'\s/etc\b')

_LS_PROC_RE: re.Pattern[str] = re.compile(r'\s/proc\b')

_LS_SYSTEM_DIR_RE: re.Pattern[str] = re.compile(r'\s/(?:root|var|boot|sys)\b')

_IP_NETWORK_SUBCMD_RE: re.Pattern[str] = re.compile(
    r'\b(?:addr|a|route|r|link|l|neigh|n|maddr|netns|rule)\b'
)

_CAT_SYS_NET_RE: re.Pattern[str] = re.compile(r'/sys/class/net/')

_CRONTAB_EDIT_RE: re.Pattern[str] = re.compile(r'\s-(?:e|r)\b')

_CRONTAB_LIST_RE: re.Pattern[str] = re.compile(r'\s-l\b')

_SYSTEMCTL_ENABLE_RE: re.Pattern[str] = re.compile(r'\benable\b')

_SYSTEMCTL_STATUS_RE: re.Pattern[str] = re.compile(r'\b(?:status|list-units|list-timers)\b')

_CHKCONFIG_ON_RE: re.Pattern[str] = re.compile(r'\bon\b')

_TEE_APPEND_RE: re.Pattern[str] = re.compile(r'\s-a\b')

_TFTP_GET_RE: re.Pattern[str] = re.compile(r'\s-g\b')

_FTP_GET_RE: re.Pattern[str] = re.compile(r'\bget\b')

# ── Binary name sets ──

_DOWNLOAD_BINARIES: frozenset[str] = frozenset({
    'curl', 'wget', 'tftp', 'ftp', 'lwp-download', 'axel', 'aria2c',
})

_ENUM_SYSTEM_BINARIES: frozenset[str] = frozenset({
    'uname', 'lscpu', 'free', 'df', 'id', 'whoami', 'hostname',
    'uptime', 'dmesg', 'lsmod', 'lspci', 'lsblk', 'fdisk',
    'mount', 'ps', 'env', 'printenv', 'getenforce',
    'arch', 'nproc', 'last', 'w', 'lastlog', 'dmidecode',
    'lshw', 'lsusb', 'systemd-detect-virt',
})

_ENUM_NETWORK_BINARIES: frozenset[str] = frozenset({
    'ifconfig', 'netstat', 'ss', 'arp', 'route', 'iptables', 'ip6tables',
    'nslookup', 'dig', 'host', 'tcpdump', 'ping',
    'traceroute', 'tracepath',
})

_ESCALATE_BINARIES: frozenset[str] = frozenset({
    'sudo', 'su', 'pkexec', 'doas', 'setcap', 'getcap',
    'capsh', 'chage',
})

_PERSIST_BINARIES: frozenset[str] = frozenset({
    'crontab', 'systemctl', 'update-rc.d', 'chkconfig',
    'rc-update', 'sysv-rc-conf',
})

_NETWORK_SCANNER_BINARIES: frozenset[str] = frozenset({
    'nmap', 'masscan', 'zmap',
})

_WIRELESS_BINARIES: frozenset[str] = frozenset({
    'iwconfig', 'iw', 'iwlist',
})

_PACKAGE_QUERY_BINARIES: frozenset[str] = frozenset({
    'dpkg', 'rpm', 'pacman', 'apk',
})

# ── Helper functions ──

def _split_commands(raw_command: str) -> List[str]:
    """Split a raw command string into individual command segments at shell operators."""
    stripped = raw_command.strip()
    if not stripped or stripped.startswith('#'):
        return []
    segments = _CMD_SEP_RE.split(stripped)
    return [s.strip() for s in segments if s.strip() and not s.strip().startswith('#')]

def _extract_exe(segment: str) -> str:
    """Extract the executable name (first word) from a command segment.

    Strips path prefixes and skips environment variable assignments (VAR=val).
    """
    m = _FIRST_WORD_RE.match(segment)
    if not m:
        return ''
    word = m.group(1)
    if '=' in word:
        return ''
    return word.rsplit('/', 1)[-1].lower()

def _extract_redirect_targets(segment: str) -> List[str]:
    """Extract all file-redirect target paths from a command segment."""
    return _REDIRECT_RE.findall(segment)

def _check_persistence_path(path: str) -> bool:
    """Check whether a file path points to a persistence mechanism."""
    basename = path.rsplit('/', 1)[-1]
    if _PERSIST_FILENAME_RE.search(basename):
        return True
    if _PERSIST_PATH_RE.search(path):
        return True
    return False

def _check_kernel_exploit_filename(segment: str) -> Optional[str]:
    """Check whether a command invokes a file whose name matches known kernel exploits.

    Only matches relative/absolute paths (./exploit, /tmp/dirtycow) to avoid
    false positives on argument substrings.
    """
    m = _FIRST_WORD_RE.match(segment)
    if not m:
        return None
    word = m.group(1)
    if '/' not in word and not word.startswith('.'):
        return None
    basename = word.rsplit('/', 1)[-1]
    match = _KERNEL_EXPLOIT_RE.search(basename)
    if match:
        return f"exploit_name:{match.group(0).lower()}"
    return None

# ── Intent detection functions ──

def _detect_download(segment: str, exe: str) -> Optional[Tuple[str, float]]:
    """Detect DOWNLOAD_EXECUTABLE intent from curl/wget/tftp/ftp usage."""
    if exe in ('curl', 'wget', 'lwp-download', 'axel', 'aria2c'):
        return (f"binary:{exe}", 0.95)
    if exe == 'tftp':
        has_get_flag = bool(_TFTP_GET_RE.search(segment))
        confidence = 0.90 if has_get_flag else 0.80
        return (f"binary:tftp{'+get' if has_get_flag else ''}", confidence)
    if exe == 'ftp':
        has_get = bool(_FTP_GET_RE.search(segment))
        confidence = 0.85 if has_get else 0.60
        return (f"binary:ftp{'+get' if has_get else ''}", confidence)
    if re.search(r'(?:^|\s)(?:/usr/bin/|/bin/)(?:curl|wget)\b', segment):
        return ("full_path:download_binary", 0.90)
    return None

def _detect_persistence(segment: str, exe: str) -> Optional[Tuple[str, float]]:
    """Detect ESTABLISH_PERSISTENCE intent."""
    if exe == 'crontab':
        if _CRONTAB_EDIT_RE.search(segment):
            return ("binary:crontab-edit", 0.90)
        if _CRONTAB_LIST_RE.search(segment):
            return None
        return ("binary:crontab", 0.85)

    if exe == 'systemctl' and _SYSTEMCTL_ENABLE_RE.search(segment):
        return ("binary:systemctl+enable", 0.90)

    if exe in ('update-rc.d', 'sysv-rc-conf', 'rc-update'):
        return (f"binary:{exe}", 0.85)

    if exe == 'chkconfig' and _CHKCONFIG_ON_RE.search(segment):
        return ("binary:chkconfig+on", 0.85)

    if '@reboot' in segment:
        return ("keyword:@reboot", 0.85)

    for target in _extract_redirect_targets(segment):
        if target == '&1' or target == '&2':
            continue
        if _check_persistence_path(target):
            return (f"redirect:{target}", 0.85)

    if exe == 'tee' and _TEE_APPEND_RE.search(segment):
        args = segment.split()
        for i, arg in enumerate(args):
            if i == 0:
                continue
            if arg == '-a':
                continue
            if arg.startswith('-'):
                continue
            if _check_persistence_path(arg):
                return (f"tee+persist_path:{arg}", 0.85)

    return None

def _detect_escalation(segment: str, exe: str) -> Optional[Tuple[str, float]]:
    """Detect ESCALATE_PRIVILEGE intent."""
    if exe == 'sudo':
        return ("binary:sudo", 0.80)
    if exe == 'su':
        return ("binary:su", 0.85)
    if exe in ('pkexec', 'doas'):
        return (f"binary:{exe}", 0.90)
    if exe == 'setcap':
        return ("binary:setcap", 0.95)

    if exe == 'chmod':
        if _SETUID_SYMBOLIC_RE.search(segment):
            return ("binary:chmod+setuid_symbolic", 0.90)
        octal_match = _SETUID_OCTAL_RE.search(segment)
        if octal_match:
            octal = octal_match.group(1)
            if len(octal) >= 3 and octal[-3] in ('2', '4', '6', '7'):
                return ("binary:chmod+setuid_octal", 0.85)
            if len(octal) >= 4 and octal[-4] in ('2', '4', '6', '7'):
                return ("binary:chmod+setuid_octal", 0.85)

    if exe in ('getcap', 'capsh'):
        return (f"binary:{exe}", 0.80)

    exploit_evidence = _check_kernel_exploit_filename(segment)
    if exploit_evidence:
        return (exploit_evidence, 0.75)

    if exe == 'find' and _FIND_SUID_RE.search(segment):
        return ("binary:find+suid_search", 0.75)

    return None

def _detect_system_enum(segment: str, exe: str) -> Optional[Tuple[str, float]]:
    """Detect ENUMERATE_SYSTEM intent."""
    if exe in _ENUM_SYSTEM_BINARIES:
        return (f"binary:{exe}", 0.90)

    if exe == 'cat':
        if _CAT_PROC_RE.search(segment):
            return ("binary:cat+proc", 0.85)
        if _CAT_ETC_SYSTEM_RE.search(segment):
            return ("binary:cat+etc_system", 0.85)
        if _CAT_LOG_RE.search(segment):
            return ("binary:cat+log", 0.75)

    if exe == 'ls':
        if _LS_ETC_RE.search(segment):
            return ("binary:ls+etc", 0.80)
        if _LS_PROC_RE.search(segment):
            return ("binary:ls+proc", 0.80)
        if _LS_SYSTEM_DIR_RE.search(segment):
            return ("binary:ls+system_dir", 0.75)

    if exe == 'ps':
        return ("binary:ps", 0.85)

    if exe == 'crontab' and _CRONTAB_LIST_RE.search(segment):
        return ("binary:crontab-list", 0.80)

    if exe == 'systemctl' and _SYSTEMCTL_STATUS_RE.search(segment):
        return ("binary:systemctl+status", 0.75)

    if exe == 'find' and _FIND_SYSTEM_PATH_RE.search(segment):
        return ("binary:find+system_path", 0.75)

    if exe in _PACKAGE_QUERY_BINARIES:
        return (f"binary:{exe}", 0.70)

    return None

def _detect_network_enum(segment: str, exe: str) -> Optional[Tuple[str, float]]:
    """Detect ENUMERATE_NETWORK intent."""
    if exe in _ENUM_NETWORK_BINARIES:
        return (f"binary:{exe}", 0.90)

    if exe == 'ip' and _IP_NETWORK_SUBCMD_RE.search(segment):
        return ("binary:ip+network_subcmd", 0.85)

    if exe == 'cat':
        if '/etc/hosts' in segment:
            return ("binary:cat+hosts_file", 0.85)
        if '/etc/resolv.conf' in segment:
            return ("binary:cat+resolv_file", 0.85)
        if '/etc/networks' in segment:
            return ("binary:cat+networks_file", 0.80)
        if _CAT_SYS_NET_RE.search(segment):
            return ("binary:cat+sys_net", 0.80)

    if exe in _NETWORK_SCANNER_BINARIES:
        return (f"binary:{exe}", 0.85)

    if exe in ('nc', 'netcat', 'ncat'):
        return (f"binary:{exe}", 0.65)

    if exe in _WIRELESS_BINARIES:
        return (f"binary:{exe}", 0.85)

    return None

# ── Detector registry ──

_DETECTORS: List[Tuple[str, Any]] = [
    (INTENT_DOWNLOAD_EXECUTABLE, _detect_download),
    (INTENT_ESTABLISH_PERSISTENCE, _detect_persistence),
    (INTENT_ESCALATE_PRIVILEGE, _detect_escalation),
    (INTENT_ENUMERATE_SYSTEM, _detect_system_enum),
    (INTENT_ENUMERATE_NETWORK, _detect_network_enum),
]

def _classify_segment(segment: str) -> Optional[Dict[str, Any]]:
    """Run all detectors on a single command segment and return the highest-confidence match."""
    exe = _extract_exe(segment)
    best_match: Optional[Dict[str, Any]] = None
    best_confidence = 0.0

    for intent, detector in _DETECTORS:
        result = detector(segment, exe)
        if result:
            evidence, confidence = result
            if confidence > best_confidence:
                best_confidence = confidence
                best_match = {
                    "intent": intent,
                    "confidence": confidence,
                    "evidence": evidence,
                }

    return best_match

# ── Public API ──

def classify_command(command: str) -> Dict[str, Any]:
    """Classify a single shell command into an intent category.

    Args:
        command: A raw shell command string from a Cowrie honeypot session.

    Returns:
        Dict with keys ``intent``, ``confidence``, and ``evidence``.
        ``intent`` is ``None`` and ``confidence`` is ``0.0`` when no
        intent is detected.
    """
    segments = _split_commands(command)
    best: Optional[Dict[str, Any]] = None

    for segment in segments:
        match = _classify_segment(segment)
        if match and (best is None or match["confidence"] > best["confidence"]):
            best = match

    if best is None:
        return {"intent": None, "confidence": 0.0, "evidence": ""}
    return best

def classify_session_commands(commands: List[str]) -> Dict[str, Any]:
    """Aggregate intent classifications across every command in a session.

    Args:
        commands: List of raw command strings from a single Cowrie session.

    Returns:
        Dict with session-level intent profile:

        - ``session_intent`` -- the dominant intent if it accounts for >50%
          of classified commands, otherwise ``"MIXED"``.
        - ``intent_counts`` -- ``Dict[str, int]`` mapping each intent to
          its occurrence count.
        - ``dominant_intent`` -- the single most frequent intent.
        - ``dominant_ratio`` -- proportion of classified commands that
          belong to the dominant intent.
        - ``detections`` -- ``List[Dict]`` of per-command classifications
          (unclassified commands excluded).
        - ``total_commands`` -- number of input commands.
        - ``classified_commands`` -- number of commands where an intent
          was detected.
    """
    counts: Counter[str] = Counter()
    detections: List[Dict[str, Any]] = []

    for cmd in commands:
        result = classify_command(cmd)
        if result["intent"] is not None:
            counts[result["intent"]] += 1
            detections.append({"command": cmd, **result})

    total = len(commands)
    classified = len(detections)

    if not counts:
        return {
            "session_intent": None,
            "intent_counts": {},
            "dominant_intent": None,
            "dominant_ratio": 0.0,
            "detections": detections,
            "total_commands": total,
            "classified_commands": classified,
        }

    dominant_intent, dominant_count = counts.most_common(1)[0]
    dominant_ratio = dominant_count / classified if classified > 0 else 0.0

    if dominant_ratio > 0.5:
        session_intent: Optional[str] = dominant_intent
    else:
        session_intent = "MIXED"

    return {
        "session_intent": session_intent,
        "intent_counts": dict(counts),
        "dominant_intent": dominant_intent,
        "dominant_ratio": round(dominant_ratio, 3),
        "detections": detections,
        "total_commands": total,
        "classified_commands": classified,
    }

def spot_check_precision(labeled_sessions: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute classification precision against manually labeled sessions.

    Args:
        labeled_sessions: List of dicts. Each dict must have:

            - ``commands`` (``List[str]``) -- the raw commands for a session.
            - ``label`` (``str``) -- the ground-truth intent for that session.

    Returns:
        Dict with:

        - ``precision`` -- overall precision (correct / total).
        - ``total`` -- total number of labeled sessions.
        - ``correct`` -- number of correct predictions.
        - ``per_intent`` -- ``Dict[str, Dict]`` with per-intent precision,
          ``total``, and ``correct`` counts.
    """
    per_intent_total: Counter[str] = Counter()
    per_intent_correct: Counter[str] = Counter()

    for session in labeled_sessions:
        commands: List[str] = session["commands"]
        label: str = session["label"]

        result = classify_session_commands(commands)
        predicted: Optional[str] = result["session_intent"]

        per_intent_total[label] += 1

        if predicted == label:
            per_intent_correct[label] += 1

    total = len(labeled_sessions)
    correct = sum(per_intent_correct.values())
    precision = correct / total if total > 0 else 0.0

    per_intent: Dict[str, Dict[str, Any]] = {}
    for intent in sorted(per_intent_total.keys()):
        t = per_intent_total[intent]
        c = per_intent_correct.get(intent, 0)
        per_intent[intent] = {
            "precision": round(c / t, 3) if t > 0 else 0.0,
            "total": t,
            "correct": c,
        }

    return {
        "precision": round(precision, 3),
        "total": total,
        "correct": correct,
        "per_intent": per_intent,
    }
