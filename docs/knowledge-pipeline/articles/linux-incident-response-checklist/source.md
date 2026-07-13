---
title: "Practical Linux Incident Response Checklist"
slug: linux-incident-response-checklist
version: "1.1"
updated: "2026-07-09"
reading_time: "18 min"
description: "Field reference for Linux incident responders — preserve evidence, contain damage, and produce analyst-ready artifacts on Ubuntu/Debian and RHEL-family systems."
canonical: "https://wraithwall.online/docs/knowledge/linux-incident-response-checklist"
og_image: "/static/img/knowledge/linux-ir-banner.png"
license: "CC BY 4.0"
status: "EDITORIAL_REVIEW"
pair_guide: "detection-engineering-handbook"
---

# Practical Linux Incident Response Checklist

**Version 1.1 · Updated 2026-07-09 · ~18 min read · CC BY 4.0**

Linux remains the default substrate for web apps, CI runners, container hosts, and cloud VMs. When compromise is suspected, teams without a written procedure waste the first critical hour rebooting, reinstalling packages, or deleting files — destroying evidence while persistence survives.

This checklist is a **field reference** for responders with shell access who need ordered actions that preserve evidence, contain blast radius, and produce artifacts a SIEM or analyst can consume. It targets **Ubuntu 22.04+/Debian 12+** and **RHEL 8+** with `systemd`, `journald`, and standard FHS layout. Adapt paths for your distribution.

**Use this document when:**
- A detection rule fires on suspicious execution, auth anomalies, or outbound beaconing ([Detection Engineering Handbook](/docs/knowledge/detection-engineering-handbook) — alert triage and rule context)
- A cloud provider flags mining, spam, or abuse from a VM
- A developer reports unexpected SSH keys, cron entries, or modified binaries
- A honeypot or canary signals interactive attacker access

**Companion guide:** [Detection Engineering Handbook](/docs/knowledge/detection-engineering-handbook) — turn IR findings into durable Sigma/SIEM rules.

---

## Prerequisites

| Requirement | Minimum |
|-------------|---------|
| Access | SSH with sudo, or out-of-band console (IPMI, serial, cloud serial console) |
| Tools | `ps`, `ss`, `lsof`, `pstree`, `auditd`, `tar`, `gzip`, `sha256sum` |
| External | Write-once evidence store (S3 Object Lock, WORM NFS, encrypted offline media) |
| People | Incident commander + scribe (document UTC timestamps from declaration) |
| Legal | Know evidence-handling requirements in your jurisdiction before imaging |

> **Operational note:** Install baseline tooling before an incident: `apt install auditd audispd-plugins debsums psmisc` (Debian/Ubuntu). `debsums` is not installed by default.

**Before an incident:** enable and start `auditd`, forward `journald` to a remote collector, snapshot filesystem baselines (`debsums -s`, `rpm -Va`, or AIDE), and store SSH host keys offline.

---

## Response flow (overview)

```
DECLARE → VOLATILE CAPTURE → BLAST RADIUS → TRIAGE → CONTAIN
    → EVIDENCE OFF-HOST → ANALYZE → ERADICATE → RECOVER → REPORT
```

Never: reboot first · `rm -rf` before hashing · rotate secrets on the suspect host  
Always: UTC timestamps · checksum evidence · scribe log

---

## Phase 0 — First five minutes

### 0.1 Declare and timestamp

```bash
INCIDENT_ID="IR-$(date -u +%Y%m%d-%H%M%S)"
echo "$INCIDENT_ID started $(date -u -Is)" | tee -a "/tmp/${INCIDENT_ID}.log"
```

Record: who declared, triggering alert/detection, hostname, suspected source IP.

### 0.2 Preserve volatile state (order matters)

Run as **root** on the suspect host **before** killing processes. Many `ss`/`lsof` fields require root or `CAP_NET_ADMIN`.

```bash
ID="$INCIDENT_ID"
OUT="/tmp/${ID}"
mkdir -p "$OUT"

ps auxwwf > "$OUT/ps.txt"
pstree -aap > "$OUT/pstree.txt" 2>/dev/null || pstree -p > "$OUT/pstree.txt"

ss -tunap > "$OUT/ss.txt"
ss -tunap | awk 'NR==1 || /ESTAB/' > "$OUT/ss-established.txt"

# Replace PID with suspicious process from ps/ss output
# lsof -p PID > "$OUT/lsof-PID.txt" 2>/dev/null

last -ai > "$OUT/last.txt" 2>/dev/null
lastb -ai > "$OUT/lastb.txt" 2>/dev/null

systemctl list-timers --all > "$OUT/timers.txt"
crontab -l -u root 2>/dev/null > "$OUT/cron-root.txt"
ls -la /etc/cron.* /var/spool/cron 2>/dev/null > "$OUT/cron-dirs.txt"
```

> **Common mistake:** Collecting evidence only under `/tmp` on the compromised host. Copy the entire `$OUT` directory off-host immediately — USB, SFTP to a bastion, or S3 with integrity checksums.

### 0.3 Blast radius (answer before containment)

1. Internet-facing or internal-only?
2. Credentials for other systems (`.env`, `~/.ssh`, CI tokens, kubeconfig)?
3. Container host? (`docker ps`, `crictl ps`, `podman ps`)
4. Unexpected outbound peers? (`ss -tunap` + WHOIS on external IPs)

Document answers in the incident log.

### Container and orchestrator context

If the host runs containers, capture scope **before** stopping workloads:

```bash
command -v docker >/dev/null && docker ps -a > "$OUT/docker-ps.txt"
command -v docker >/dev/null && docker network ls > "$OUT/docker-net.txt"
command -v crictl >/dev/null && crictl ps -a > "$OUT/crictl-ps.txt"
command -v kubectl >/dev/null && kubectl get pods -A -o wide > "$OUT/k8s-pods.txt" 2>/dev/null
```

For a suspicious PID, map cgroup namespace:

```bash
PID=<suspicious_pid>
cat /proc/$PID/cgroup > "$OUT/cgroup-$PID.txt"
tr '\0' ' ' < /proc/$PID/cmdline > "$OUT/cmdline-$PID.txt"; echo >> "$OUT/cmdline-$PID.txt"
readlink /proc/$PID/exe > "$OUT/exe-$PID.txt" 2>/dev/null
```

> **Operational note:** Stopping a container before Phase 0 destroys process trees and open sockets. Snapshot first; stop only after volatile capture or explicit policy.

---

## Phase 1 — Triage (15–30 minutes)

### 1.1 Authentication anomalies

```bash
# Ubuntu/Debian: ssh unit is usually ssh.service (older: ssh)
journalctl -u ssh.service --since "24 hours ago" --no-pager \
  | grep -E 'Failed|Accepted|Invalid|Disconnected' > "$OUT/ssh-journal.txt"

who -a > "$OUT/who.txt"
w > "$OUT/w.txt"

find /home /root -name authorized_keys 2>/dev/null | while read -r f; do
  ls -la "$f"
  sha256sum "$f"
done > "$OUT/authkeys.txt"
```

**Look for:** new `authorized_keys` lines, `Accepted publickey` for users without keys, geography you do not operate in, `Failed password` burst followed by success.

**MITRE ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts · [T1110](https://attack.mitre.org/techniques/T1110/) Brute Force

> **Cross-reference:** After confirming auth abuse, add or tune brute-force correlation rules — see *Detection Engineering Handbook*, Chapter 7 (SSH brute → success).

### 1.2 Process and persistence

```bash
# Deleted executables still running
find /proc -maxdepth 2 -name exe -exec ls -l {} \; 2>/dev/null | grep deleted > "$OUT/deleted-exe.txt"

ss -tlnp > "$OUT/listeners.txt"

find /etc/systemd/system /lib/systemd/system -mtime -7 -ls 2>/dev/null > "$OUT/systemd-recent.txt"

find /usr /bin /sbin -perm -4000 -mtime -30 -ls 2>/dev/null > "$OUT/suid-recent.txt"
```

**Look for:** executables under `/tmp` or `/dev/shm`, fake `kthreadd` names, unknown listeners, systemd drop-ins invoking `curl|bash`.

**MITRE ATT&CK:** [T1059.004](https://attack.mitre.org/techniques/T1059/004/) Unix Shell · [T1543.002](https://attack.mitre.org/techniques/T1543/002/) Systemd Service

### 1.3 File integrity spot-check

```bash
for bin in /bin/bash /usr/sbin/sshd /usr/bin/sudo; do
  [ -e "$bin" ] && sha256sum "$bin"
done > "$OUT/critical-hashes.txt"

if command -v debsums >/dev/null; then
  debsums -s 2>/dev/null | head -50 >> "$OUT/debsums.txt"
elif command -v rpm >/dev/null; then
  rpm -Va 2>/dev/null | grep -E '^..5' | head -50 >> "$OUT/rpm-va.txt"
fi
```

If `sshd` or `sudo` fails package verification, assume privileged compromise until proven otherwise.

### 1.4 Web application indicators

```bash
find /var/www /srv/www -type f -mtime -3 -ls 2>/dev/null > "$OUT/www-recent.txt"

grep -rEl '(eval\s*\(|base64_decode|shell_exec|passthru)\s*\(' /var/www 2>/dev/null \
  | head -20 > "$OUT/php-suspect.txt"
```

**MITRE ATT&CK:** [T1505.003](https://attack.mitre.org/techniques/T1505/003/) Web Shell

---

## Phase 2 — Containment

Choose **one** primary strategy and document why.

```
                    ┌─ Active ransomware lateral? ──► Full shutdown (console ready)
                    │
Suspected compromise ─┼─ Credential leak only? ─────► Account disable + key rotation
                    │
                    ├─ Active C2/mining + Phase 0 done? ► Network isolate
                    │
                    └─ Phase 0 incomplete? ───────────► Finish volatile capture first
```

| Strategy | When | Tradeoff |
|----------|------|----------|
| **Network isolate** | Default when imaging next | May leave partial sessions; prefer cloud SG over host firewall when possible |
| **Account disable** | Credential compromise only | Other keys/sessions may remain |
| **Process kill** | Active mining with captured state | Destroys volatile evidence if Phase 0 incomplete |
| **Full shutdown** | Ransomware lateral spread | RAM evidence lost |

### 2.1 Network isolation

> **Security warning:** Host `iptables`/`nft` rules can lock **you** out. Confirm out-of-band console access first. Prefer **cloud security groups** or hypervisor port groups when available.

```bash
# Replace JUMP_IP with your bastion (RFC 5737 example: 203.0.113.10)
JUMP_IP="203.0.113.10"
iptables -I OUTPUT 1 -d "$JUMP_IP" -j ACCEPT
iptables -A OUTPUT -j DROP
iptables -A INPUT -j DROP
```

> **Operational note:** Ubuntu 22.04+ may use `nftables` backend. If `iptables` commands fail, use provider-level isolation or `nft` rules consistent with your image.

### 2.2 Credential containment

```bash
passwd -l suspectuser
usermod -s /usr/sbin/nologin suspectuser
```

Rotate adjacent secrets from a **clean** workstation — never from the suspect host.

### 2.3 Defer until evidence captured

- `rm -rf` on malware paths
- Reinstalling `openssh-server` pre-image
- Reboot (unless ransomware policy mandates)

---

## Phase 3 — Evidence collection

### 3.1 Logical bundle

```bash
EVIDENCE_DIR="/tmp/${INCIDENT_ID}-evidence"
mkdir -p "$EVIDENCE_DIR"/{logs,config,home}

journalctl --since "7 days ago" --no-pager > "$EVIDENCE_DIR/logs/journal-full.txt"
cp -a /var/log/auth.log /var/log/syslog "$EVIDENCE_DIR/logs/" 2>/dev/null
cp -a /var/log/audit "$EVIDENCE_DIR/logs/" 2>/dev/null

cp -a /etc/ssh/sshd_config /etc/crontab /etc/passwd /etc/group "$EVIDENCE_DIR/config/" 2>/dev/null

# Shadow/group only if policy permits — highly sensitive
# cp -a /etc/shadow "$EVIDENCE_DIR/config/" 2>/dev/null

for h in /root/.bash_history /home/*/.bash_history; do
  [ -f "$h" ] && cp -a "$h" "$EVIDENCE_DIR/home/"
done

command -v dpkg >/dev/null && dpkg -l > "$EVIDENCE_DIR/dpkg-list.txt"
command -v rpm >/dev/null && rpm -qa > "$EVIDENCE_DIR/rpm-list.txt"

tar -C /tmp -czf "/tmp/${INCIDENT_ID}-evidence.tar.gz" "$(basename "$EVIDENCE_DIR")"
sha256sum "/tmp/${INCIDENT_ID}-evidence.tar.gz" | tee "/tmp/${INCIDENT_ID}-evidence.tar.gz.sha256"
```

> **Security warning:** `/etc/shadow`, browser profiles, and `.env` files are regulated data in many jurisdictions. Copy only with legal approval; encrypt at rest; restrict access.

Transfer tarball + checksum off-host. Verify checksum on receipt.

### 3.2 Memory and disk

- **Memory:** LiME, AVML, or hypervisor snapshot — before shutdown if policy allows. Document *memory not captured* if skipped.
- **Disk:** `dd`/`dc3dd` or storage snapshot. Record serial, tool version, start/end UTC.

---

## Phase 4 — Analysis hooks

### 4.1 Timeline (UTC)

Merge sources into a single UTC-sorted table. Minimum columns: `timestamp_utc`, `source`, `event_type`, `actor`, `target`, `detail`, `evidence_path`.

| Source | Fields |
|--------|--------|
| `auth.log` / `journalctl` ssh | user, source IP, method |
| `auditd` | `execve`, `connect`, `chmod` |
| Web logs | URI, status, user-agent |
| Phase 0 `ps`/`ss` | parent PID, connections |

```bash
# Rough merge starter — normalize timestamps to ISO8601 in analysis tooling
grep -hE '^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)|^[0-9]{4}-' \
  "$EVIDENCE_DIR/logs/"* 2>/dev/null | head -200 > "$OUT/timeline-raw.txt"
```

> **Operational note:** Analysts should build the authoritative timeline in the SIEM or spreadsheet — shell `grep` is for triage only, not legal-grade chronology.

### 4.2 IOC extraction

```bash
grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /tmp/${INCIDENT_ID}* 2>/dev/null \
  | grep -vE '^(10\.|127\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' \
  | sort -u > "$OUT/external-ips.txt"
```

Validate IPs with threat intel before fleet-wide blocks. For parsing discipline, see *Detection Engineering Handbook*, Chapter 8 (IOC normalization).

### 4.3 Persistence checklist

- [ ] `/etc/rc.local`, `/etc/init.d/` (legacy)
- [ ] All user crontabs: `getent passwd | cut -d: -f1 | xargs -I{} crontab -l -u {} 2>/dev/null`
- [ ] `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`
- [ ] `/etc/ld.so.preload`
- [ ] `~/.ssh/authorized_keys`, `~/.bashrc`, `~/.profile`
- [ ] systemd units and drop-ins under `/etc/systemd/system/`
- [ ] `atq` / `/var/spool/at/`
- [ ] `lsmod` vs baseline
- [ ] `/etc/pam.d/` modifications
- [ ] Application schedulers (WordPress `wp-cron.php`, Celery beat, etc.)

**MITRE ATT&CK:** [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Cron · [T1546](https://attack.mitre.org/techniques/T1546/) Event Triggered Execution

---

## Phase 5 — Eradication

Proceed only after evidence is secured and blast radius is mapped.

1. **Rebuild from known-good image** (preferred)
2. If in-place cleaning is mandated: remove unauthorized keys, cron, units, SUID drops; `apt install --reinstall openssh-server` or `dnf reinstall openssh-server`; rotate **all** secrets that touched the host
3. Patch the vector (CVE, weak SSH, leaked deploy key, webshell upload path)

### SSH minimum after rebuild

```
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
# AllowUsers deploy   # usernames only — restrict by Match Address if needed
```

```bash
sshd -t && systemctl reload ssh.service
```

---

## Phase 6 — Recovery

| Step | Action |
|------|--------|
| 1 | Restore from image or redeploy via IaC |
| 2 | Patch before production VLAN |
| 3 | Restore data from pre-incident backup; scan backups for webshells |
| 4 | Confirm logs reach SIEM; re-enable detections from *Detection Engineering Handbook* baseline |
| 5 | Optional: canary tokens on adjacent segments |
| 6 | Gradual traffic restore with heightened alerting |

Re-run the detection rules that originally fired — they should not trigger on clean state.

---

## Communications (parallel track)

Assign a non-responder to external comms. Internal containment does not wait for legal, but **customer/regulator notice** may.

| Stakeholder | When | Content |
|-------------|------|---------|
| Engineering leadership | At declaration | Scope, containment, ETA |
| Legal / privacy | Before external notice | PII assessment |
| Customers | Confirmed data impact | Facts only |
| Regulators | Statutory deadline | Counsel-approved template |

> **Operational note:** Keep attorney-client materials on clean systems — never on the suspect host.

---

## Phase 7 — Post-incident

**Report minimum sections:** executive summary · UTC timeline · initial access vector (confirmed/suspected) · actions per phase · IOC list · lessons learned · remediations with owners

| Metric | Definition |
|--------|------------|
| MTTD | Alert time − earliest compromise indicator |
| MTTR | Production restored − declaration time |
| Recurrence | Same IOC within 90 days |

---

## Worked examples

### Example 1 — Suspicious SSH key

Unknown line in `REPO_ROOT/.ssh/authorized_keys`. Phase 0 snapshots; Phase 1 shows `Accepted publickey` from `TEST_NET_EXAMPLE` (TEST-NET-2). Contain egress; preserve key hash; analysis finds `/etc/cron.d/update-check` with `curl | bash`. Rebuild; rotate deploy and DB credentials; deploy `auditd` watch on `authorized_keys` writes.

**MITRE:** [T1098.004](https://attack.mitre.org/techniques/T1098/004/) SSH Authorized Keys · [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Cron

### Example 2 — Outbound beaconing

SIEM alert on sustained HTTPS to rare ASN. Phase 0: `python3` PID connected to `203.0.113.55:443`; `/proc/PID/exe` shows deleted path under `/tmp/.cache/`. Isolate network; capture `lsof` before kill. Root cause: webshell via `upload.php` 36h earlier. Rebuild; block execution under upload path; add Sigma rule for `www-data` python egress (*Detection Handbook*, Chapter 4).

**MITRE:** [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Web Protocols · [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer

### Example 3 — Container host mining

Cloud alert on Monero mining. `cat /proc/PID/cgroup` shows container scope; `docker diff` before stop. Isolate SG; host-level persistence check (Phase 1.2). Terminate container; rebuild host; pin images by digest; Falco/eBPF for breakout signals.

**MITRE:** [T1610](https://attack.mitre.org/techniques/T1610/) Deploy Container · [T1611](https://attack.mitre.org/techniques/T1611/) Escape to Host

---

## Post-recovery validation

```bash
systemctl is-active auditd
auditctl -l 2>/dev/null | head
ss -tlnp
command -v debsums >/dev/null && debsums -s 2>/dev/null | wc -l  # expect 0
```

Confirm remote log shipping: trigger a test `logger` event and verify arrival in SIEM within one minute. Re-enable detection rules from the companion handbook baseline before restoring production traffic.

---

## Common failures (avoid these)

| Mistake | Why it hurts | Instead |
|---------|--------------|---------|
| Reboot before volatile capture | Loses RAM-only malware, open sockets, parent chains | Phase 0 first; memory image if policy allows |
| `rm` webshell before tarball | Destroys content for YARA/hash IOCs | Hash, copy, then quarantine offline |
| Rotate DB password from suspect host | Attacker may capture new secret via keylogger | Rotate from clean bastion; assume host fully compromised |
| Block scanner IP fleet-wide from one regex hit | CDN/resolver collateral damage | Validate IOCs; correlate with auth success |
| Trust `debsums` alone on RHEL | Use `rpm -Va`; different package model | Match tool to distribution |
| Skip scribe / incident log | Reconstruction fails legal and post-mortem review | Assign scribe at declaration |

---

## Phase 3 — Volatile & Non-volatile Acquisition (robust evidence pipeline)

### 3.1 Memory acquisition (when feasible)

Modern persistence lives in memory (e.g., reflective DLLs, fileless).

```bash
# Install if missing (Ubuntu): apt install linux-headers-$(uname -r) avml
avml --compress /tmp/${ID}-memory.lime 2>/dev/null || \
  (echo "avml not present; falling back to dd if LiME available" && \
   insmod /path/to/lime.ko "path=/tmp/${ID}-memory.lime format=lime")
sha256sum /tmp/${ID}-memory.lime > /tmp/${ID}-memory.sha256
```

Copy off-host **before** any kill or reboot. Use `scp` to bastion or `aws s3 cp` with integrity.

### 3.2 Disk imaging (read-only where possible)

```bash
# Example for block device; adapt for LVM/containers
dd if=/dev/sda bs=4M status=progress | gzip > /evidence/${ID}-disk.img.gz
sha256sum /evidence/${ID}-disk.img.gz > /evidence/${ID}-disk.sha256
```

For live systems without full image: collect critical paths with `tar --create --preserve-permissions --xattrs` + hashes.

### 3.3 Timeline reconstruction

```bash
# Rough timeline from multiple sources (feed to log2timeline/plaso if available)
cat "$OUT"/ps.txt "$OUT"/ss.txt "$OUT"/journal-*.txt "$OUT"/authkeys.txt | \
  sort -k1,2 > "$OUT/timeline-raw.txt"
```

**Robustness:** Always capture in UTC, store hashes + original + chain-of-custody log (who, when, tool, hash).

---

## Phase 4 — Eradication (targeted, evidence-backed)

### 4.1 Persistence hunting (expand beyond basics)

```bash
# Kernel modules
lsmod | tee "$OUT/lsmod.txt"
find /lib/modules -name "*.ko" -newer /tmp/${ID}-start 2>/dev/null > "$OUT/new-modules.txt"

# Userland persistence
find /etc /usr /var -name "*.service" -o -name "*.timer" -newermt "7 days ago" 2>/dev/null | xargs grep -l "ExecStart" > "$OUT/persist-services.txt"
crontab -l 2>/dev/null; cat /var/spool/cron/* 2>/dev/null > "$OUT/all-cron.txt"

# SSH backdoors / authorized_keys across users
find /home /root -name authorized_keys -exec cat {} + | sort | uniq -c | sort -nr > "$OUT/authkeys-all.txt"

# LD_PRELOAD / /etc/ld.so.preload
cat /etc/ld.so.preload 2>/dev/null > "$OUT/ld-preload.txt"
```

**Container specific:**

```bash
docker ps -a --no-trunc | tee "$OUT/docker-all.txt"
# Remove suspicious container but keep volume for forensics
docker rm -f suspicious_id || true
# Inspect image layers for anomalies
docker history suspicious_image | tee "$OUT/image-history.txt"
```

### 4.2 Malware & artifact quarantine

```bash
# Quarantine without deletion
mkdir -p /quarantine/${ID}
find / -type f -newermt "48 hours ago" -exec file {} + | grep -E 'ELF|script' | cut -d: -f1 | \
  while read f; do cp --parents "$f" /quarantine/${ID}/; done
# Record
tar -czf /evidence/${ID}-quarantine.tar.gz /quarantine/${ID}
sha256sum /evidence/${ID}-quarantine.tar.gz
```

Never delete until after YARA/ hash / sandbox (see Detection Handbook).

### 4.3 Credential & secret rotation (from clean host)

Use a clean jump host or password manager. Rotate in this order:

1. Suspect host root / sudoers accounts
2. Service accounts on host
3. Adjacent systems (DB, API keys in .env, cloud IAM)
4. SSH keys globally if any extracted
5. Certificates / TLS if private keys touched

Document in incident log: "Rotated X on Y from clean host Z at UTC time T"

---

## Phase 5 — Recovery & Hardening (post-eradication)

### 5.1 Rebuild vs patch decision matrix

| Scenario | Recommended |
|----------|-------------|
| Rootkit suspected (modified kernel/modules) | Full rebuild from known-good image + immutable IaC |
| Webshell only (no priv esc) | Patch + remove, rotate app creds, enable WAF rules |
| Container escape | Rebuild node/image, rotate node certs, enforce pod security standards |

### 5.2 Post-recovery validation

```bash
# Re-run baseline
debsums -s || rpm -Va | grep '^..5'
# Verify no new listeners after reboot
ss -tlnp
# Check no new authorized_keys
find /root /home -name authorized_keys -exec cat {} +
```

Apply CIS benchmarks or your hardening baseline. Re-enable monitoring.

### 5.3 Validate detection coverage

Feed IOCs and TTPs observed back to detection team (see Handbook). Example: new systemd unit name → add rule.

---

## Phase 6 — Reporting & Lessons Learned (robust closure)

### 6.1 Minimum report template

- Executive: timeline, impact (data? credentials? duration?), cost (hours, rebuilds)
- Technical: attack path (initial vector → persistence → actions), IOCs (hashes, IPs, filenames, user agents), artifacts (links to evidence tarballs + hashes)
- Detection: which rules fired / missed, proposed new rules or tuning (link to Detection Handbook)
- Remediation: actions taken + owners + verification dates
- Recommendations: architecture, process, tooling gaps

### 6.2 Evidence package standard

- Tarball: /evidence/${ID}-full.tar.gz containing OUT/, memory, quarantine, logs, report.md, chain-of-custody.txt
- Manifest: SHA256 of every file + GPG signature of manifest
- Retention: per legal/policy (minimum 1 year, WORM if possible)

### 6.3 Post-incident review (PIR) checklist

- [ ] Was detection timely? MTTD recorded
- [ ] False positive rate of triggering rule acceptable?
- [ ] IR playbook followed? Deviations documented?
- [ ] New detections authored and deployed?
- [ ] Architecture gaps (e.g. no EDR on host) assigned owners + dates
- [ ] Runbook updated in IR checklist + linked from alert

---

## Cloud & Container Extensions (robust modern coverage)

### AWS quick IR commands (run from clean admin workstation)

```bash
# Instance metadata / user data
aws ec2 describe-instances --instance-ids i-xxx --query 'Reservations[0].Instances[0].UserData'
aws ec2 get-console-output --instance-id i-xxx

# CloudTrail recent activity for the instance role
aws cloudtrail lookup-events --lookup-attributes AttributeKey=ResourceName,AttributeValue=i-xxx --max-results 50
```

### Kubernetes / containerd

```bash
# Events + pod logs
kubectl get events -A --sort-by=.lastTimestamp | tail -50 > "$OUT/k8s-events.txt"
kubectl logs -n ns pod --previous > "$OUT/k8s-prev-logs.txt" 2>/dev/null

# CRI
crictl ps -a
crictl logs <container> > "$OUT/cri-logs.txt"
```

---

## Common Pitfalls & Anti-Patterns (added robustness)

| Pitfall | Consequence | Mitigation |
|---------|-------------|------------|
| Rebooting before volatile capture | RAM artifacts (fileless, keys in mem) lost forever | Phase 0 first; document "reboot only if ransomware confirmed and console ready" |
| Running `rm -rf` on attacker paths from suspect host | Evidence destruction + potential self-DoS if path wrong | Copy first, then (after off-host) quarantine |
| Rotating secrets while host is live | Attacker sees new creds via keylogger / memory | Rotate from clean host only after containment |
| Treating container as "just a process" | Miss namespace, image layer, volume persistence | Always snapshot container metadata + image |
| Ignoring supply-chain (new package in image) | Attacker persists via poisoned base image | Image SBOM + immutable tags + provenance checks |

---

## Further reading

- [NIST SP 800-61 Rev. 2](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final) — incident handling guide
- [MITRE ATT&CK Enterprise](https://attack.mitre.org/matrices/enterprise/) — technique reference
- [CIS Benchmarks — Linux](https://www.cisecurity.org/cis-benchmarks) — post-recovery hardening validation
- **WraithWall:** [Detection Engineering Handbook](/docs/knowledge/detection-engineering-handbook) — rules for scenarios encountered during IR

---

WraithWall Knowledge Base · https://wraithwall.online  
License: CC BY 4.0 · Corrections: contact@wraithwall.online  
Independent of WraithWall deception systems.