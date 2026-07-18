"""MITRE ATT&CK mapping tables.

This module holds the static, hand-curated mapping from observed shell-command
substrings to MITRE ATT&CK tactics and techniques, plus the per-stage danger
scores used by the deterministic scorer.

The tables are copied verbatim from the original WraithWall Cowrie intelligence
pipeline. Matching is a **case-insensitive substring test** — see the README for
the honest caveats about how crude that is, and why the confidence value is a
hardcoded constant rather than a learned probability.
"""

from __future__ import annotations

from typing import Any, Dict

# Hardcoded per-match confidence. This is NOT a learned or calibrated probability;
# it is a fixed constant attached to every substring hit. Treat it as a label, not
# a statistic.
TECHNIQUE_CONFIDENCE: float = 0.85

# Canonical kill-chain ordering of the tactics we track.
TACTIC_ORDER = [
    'reconnaissance', 'persistence', 'privilege_escalation',
    'defense_evasion', 'credential_access', 'lateral_movement',
    'collection', 'exfiltration', 'command_and_control', 'impact',
]

# stage -> {id, techniques, command substrings, prerequisite technique ids}
# Copied verbatim from the source pipeline. The 'commands' entries are matched as
# case-insensitive substrings against each command line.
MITRE_TECHNIQUES: Dict[str, Dict[str, Any]] = {
    'reconnaissance': {
        'id': 'TA0043',
        'techniques': ['T1082', 'T1033', 'T1016', 'T1057', 'T1595', 'T1592'],
        'commands': [
            'uname', 'whoami', 'id', 'hostname', 'ifconfig', 'ip addr',
            'cat /etc/passwd', 'cat /proc/cpuinfo', 'ps aux', 'netstat',
            'ss -tlnp', 'lsb_release', 'cat /etc/*release', 'w', 'who',
            'env', 'printenv', 'cat /proc/version', 'lscpu', 'free -m',
            'df -h', 'mount', 'fdisk -l', 'systemctl status'
        ],
        'prerequisites': []
    },
    'persistence': {
        'id': 'TA0003',
        'techniques': ['T1053', 'T1136', 'T1098', 'T1546', 'T1543'],
        'commands': [
            'crontab', 'useradd', 'adduser', 'ssh-keygen', 'authorized_keys',
            'systemctl enable', 'rc.local', '.bashrc', '.profile',
            'update-rc.d', 'chkconfig', 'crontab -e', 'ssh-copy-id',
            'systemctl daemon-reload', 'passwd'
        ],
        'prerequisites': ['T1033']
    },
    'privilege_escalation': {
        'id': 'TA0004',
        'techniques': ['T1068', 'T1548', 'T1543'],
        'commands': [
            'sudo', 'su -', 'su root', 'chmod +s', 'SUID', '/etc/sudoers',
            'pkexec', 'doas', 'exploit', 'CVE-', 'dirtycow', 'polkit',
            'setuid', 'getcap', 'capsh', 'docker exec', 'lxc exec'
        ],
        'prerequisites': ['T1082', 'T1033']
    },
    'defense_evasion': {
        'id': 'TA0005',
        'techniques': ['T1070', 'T1027', 'T1564'],
        'commands': [
            'history -c', 'unset HISTFILE', 'rm -rf /var/log',
            'shred', 'wipe', 'base64', 'chmod 777',
            'chattr +i', 'setfacl', 'mount -o remount',
            'kill -9', 'pkill', 'systemctl stop'
        ],
        'prerequisites': ['T1082']
    },
    'credential_access': {
        'id': 'TA0006',
        'techniques': ['T1110', 'T1552', 'T1003'],
        'commands': [
            'cat /etc/shadow', 'cat /etc/passwd', 'grep password',
            'find . -name "*.env"', 'find . -name "config"',
            'cat ~/.ssh', 'env | grep', 'printenv',
            'mimikatz', 'pwdump', 'hashdump', 'cat .git/config',
            'cat /root/.bash_history', 'cat /home/*/.bash_history',
            'tar -czf /tmp/passwd.tar.gz /etc/passwd',
            'find / -name "id_rsa"', 'cat ~/.aws/credentials'
        ],
        'prerequisites': ['T1082', 'T1548']
    },
    'lateral_movement': {
        'id': 'TA0008',
        'techniques': ['T1021', 'T1563'],
        'commands': [
            'ssh ', 'scp ', 'rsync', 'nc ', 'ncat', 'socat',
            'sshpass', 'autossh', 'ssh -o StrictHostKeyChecking=no',
            'winexe', 'psexec', 'smbclient'
        ],
        'prerequisites': ['T1003', 'T1082']
    },
    'collection': {
        'id': 'TA0009',
        'techniques': ['T1005', 'T1074'],
        'commands': [
            'tar ', 'zip ', 'gzip', 'find / -name', 'locate',
            'grep -r', 'cat', 'head -n 100', 'tail -n 100',
            'find / -type f -name "*.sql"', 'mysqldump', 'pg_dump',
            'tar -czf /tmp/data.tar.gz'
        ],
        'prerequisites': ['T1082']
    },
    'exfiltration': {
        'id': 'TA0010',
        'techniques': ['T1048', 'T1041'],
        'commands': [
            'wget ', 'curl ', 'ftp ', 'scp ', 'rsync', 'nc -',
            'python -c', 'curl -X POST', 'wget --post-data',
            'curl -F', 'scp -r', 'rsync -avz',
            'python -m http.server', 'php -S', 'nc -lvp'
        ],
        'prerequisites': ['TA0009', 'TA0011']
    },
    'command_and_control': {
        'id': 'TA0011',
        'techniques': ['T1095', 'T1571', 'T1071'],
        'commands': [
            'python', 'perl', 'ruby', 'php', 'bash -i', '/dev/tcp',
            'mkfifo', 'mknod', 'socat', 'ncat', 'nc -e',
            'bash -i >&', 'python -c "import socket',
            'perl -e \'use Socket', 'ruby -rsocket',
            'php -r \'$sock=fsockopen', 'lua -e',
            'wget -qO-', 'curl -s', 'curl -o-'
        ],
        'prerequisites': []
    },
    'impact': {
        'id': 'TA0040',
        'techniques': ['T1485', 'T1486', 'T1529'],
        'commands': [
            'rm -rf', 'dd if=', 'mkfs', 'cryptsetup', 'openssl enc',
            ':(){ :|:& };:', 'shutdown', 'reboot', 'halt', 'poweroff',
            'rm -rf /', 'dd if=/dev/zero', 'mkfs.ext4',
            'chmod 000 /', 'mv / /dev/null'
        ],
        'prerequisites': ['T1548']
    },
}

# Stages considered high-risk when a single command lands in one of them.
HIGH_RISK_STAGES = {'credential_access', 'impact', 'exfiltration', 'command_and_control'}

# Per-stage base score used by the deterministic scorer. Copied verbatim.
DANGER_SCORES: Dict[str, int] = {
    'impact': 40, 'exfiltration': 35, 'credential_access': 30,
    'command_and_control': 30, 'privilege_escalation': 25,
    'lateral_movement': 20, 'defense_evasion': 15,
    'persistence': 15, 'collection': 10, 'reconnaissance': 5,
}

# Default base score for an unknown / unmatched stage.
DEFAULT_BASE_SCORE: int = 5
