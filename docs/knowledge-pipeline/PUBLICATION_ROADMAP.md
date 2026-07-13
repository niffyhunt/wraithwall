# WraithWall Knowledge Publication Roadmap — 100 Topics

**Version:** 1.0  
**Updated:** 2026-07-09  
**Ranking method:** Composite score = `(Engineering Value × 0.45) + (Search Value × 0.30) + (Defender Utility × 0.25)`  
Each dimension scored 1–10. Higher composite = publish sooner.

**Legend:** ✅ Draft ready · 🔒 Awaiting approval · ⬜ Not started

---

## Top 20 (Publish First)

| Rank | ID | Topic | Category | Eng | Search | Util | **Score** | Status |
|------|-----|-------|----------|-----|--------|------|-----------|--------|
| 1 | PUBLISH-001 | Practical Linux Incident Response Checklist | Incident Response | 10 | 9 | 10 | **9.65** | ✅ Draft |
| 2 | PUBLISH-002 | Detection Engineering Handbook: Raw Logs to Deployable Rules | Detection Engineering | 10 | 9 | 10 | **9.65** | ✅ Draft |
| 3 | KR-003 | Redis Security Hardening for Production | Linux Engineering | 9 | 8 | 9 | **8.75** | ⬜ |
| 4 | KR-004 | Reverse Shell Detection Reference (Linux) | Detection Engineering | 9 | 9 | 9 | **9.00** | ⬜ |
| 5 | KR-005 | SSH Hardening Playbook (OpenSSH 9.x) | Linux Engineering | 9 | 9 | 8 | **8.75** | ⬜ |
| 6 | KR-006 | Docker Security Checklist for SOC Teams | Linux Engineering | 8 | 8 | 9 | **8.35** | ⬜ |
| 7 | KR-007 | Building Effective Canary Tokens (Defender Guide) | Deception Engineering | 8 | 7 | 9 | **8.05** | ⬜ |
| 8 | KR-008 | Threat Hunting Query Collection (Elastic + Splunk) | Threat Hunting | 8 | 8 | 9 | **8.35** | ⬜ |
| 9 | KR-009 | MITRE ATT&CK Mapping for Linux Intrusions | SOC Engineering | 9 | 8 | 8 | **8.45** | ⬜ |
| 10 | KR-010 | Sigma Rule Style Guide and Testing Workflow | Detection Engineering | 9 | 7 | 9 | **8.40** | ⬜ |
| 11 | KR-011 | Flask Application Security Checklist | Security Engineering | 8 | 7 | 8 | **7.75** | ⬜ |
| 12 | KR-012 | API Rate Limiting Patterns (Redis-backed) | Security Engineering | 8 | 6 | 8 | **7.50** | ⬜ |
| 13 | KR-013 | IOC Parsing and Normalization Reference | Detection Engineering | 8 | 7 | 9 | **8.05** | ⬜ |
| 14 | KR-014 | Bash One-Liners for Incident Responders | Linux Engineering | 7 | 8 | 9 | **7.95** | ⬜ |
| 15 | KR-015 | Nginx Hardening and Log Format Reference | Linux Engineering | 8 | 7 | 8 | **7.75** | ⬜ |
| 16 | KR-016 | Windows IR First-Hour Checklist | Incident Response | 9 | 9 | 8 | **8.75** | ⬜ |
| 17 | KR-017 | Kubernetes Pod Compromise Response | Incident Response | 8 | 8 | 8 | **8.00** | ⬜ |
| 18 | KR-018 | AWS Compromised IAM Key Playbook | Incident Response | 9 | 8 | 8 | **8.45** | ⬜ |
| 19 | KR-019 | Sentinel KQL Starter Pack for Threat Hunters | Threat Hunting | 8 | 8 | 8 | **8.00** | ⬜ |
| 20 | KR-020 | Alert Triage Rubric (P1–P4) with Examples | SOC Engineering | 8 | 6 | 9 | **7.85** | ⬜ |

---

## Ranks 21–50

| Rank | ID | Topic | Category | Eng | Search | Util | **Score** |
|------|-----|-------|----------|-----|--------|------|-----------|
| 21 | KR-021 | YARA Rule Performance Optimization | Detection Engineering | 8 | 6 | 8 | 7.50 |
| 22 | KR-022 | Suricata Rules for Common C2 Patterns | Detection Engineering | 8 | 7 | 7 | 7.55 |
| 23 | KR-023 | Falco Rules for Kubernetes Runtime | Detection Engineering | 7 | 7 | 8 | 7.35 |
| 24 | KR-024 | Webshell Upload Detection (Web Logs) | Detection Engineering | 8 | 7 | 8 | 7.75 |
| 25 | KR-025 | Cron Persistence Detection Patterns | Detection Engineering | 8 | 6 | 8 | 7.50 |
| 26 | KR-026 | Sudo Abuse Detection on Linux | Detection Engineering | 7 | 6 | 8 | 7.05 |
| 27 | KR-027 | PowerShell Encoded Command Detection | Detection Engineering | 8 | 8 | 7 | 7.75 |
| 28 | KR-028 | LOLBAS Detection Pack (Windows) | Detection Engineering | 8 | 7 | 7 | 7.55 |
| 29 | KR-029 | DNS Tunneling Detection Logic | Detection Engineering | 8 | 7 | 8 | 7.75 |
| 30 | KR-030 | Brute Force Detection Across Auth Logs | Detection Engineering | 7 | 7 | 8 | 7.35 |
| 31 | KR-031 | Docker Container Compromise IR | Incident Response | 8 | 7 | 8 | 7.75 |
| 32 | KR-032 | Azure AD Session Revocation Workflow | Incident Response | 8 | 7 | 7 | 7.45 |
| 33 | KR-033 | Ransomware Containment Decision Tree | Incident Response | 9 | 8 | 9 | 8.65 |
| 34 | KR-034 | Linux Memory Forensics Acquisition | Incident Response | 8 | 7 | 7 | 7.45 |
| 35 | KR-035 | Evidence Chain of Custody Template | Incident Response | 7 | 5 | 8 | 6.85 |
| 36 | KR-036 | Log Preservation Under Active Attack | Incident Response | 8 | 6 | 9 | 7.65 |
| 37 | KR-037 | Elastic KQL: Lateral Movement Hunts | Threat Hunting | 8 | 7 | 8 | 7.75 |
| 38 | KR-038 | Splunk SPL: Beaconing Statistics Primer | Threat Hunting | 8 | 7 | 8 | 7.75 |
| 39 | KR-039 | Chronicle UDM Query Patterns | Threat Hunting | 7 | 6 | 7 | 6.75 |
| 40 | KR-040 | Rare Process Parent-Child Hunt Hypotheses | Threat Hunting | 8 | 6 | 8 | 7.50 |
| 41 | KR-041 | Systemd Unit Security Audit Checklist | Linux Engineering | 7 | 6 | 8 | 7.05 |
| 42 | KR-042 | UFW + fail2ban Integration Guide | Linux Engineering | 7 | 7 | 8 | 7.35 |
| 43 | KR-043 | Auditd Ruleset for Compromise Detection | Linux Engineering | 9 | 6 | 9 | 8.10 |
| 44 | KR-044 | journald Remote Forwarding Setup | Linux Engineering | 7 | 5 | 8 | 6.85 |
| 45 | KR-045 | File Integrity Monitoring with AIDE | Linux Engineering | 7 | 6 | 8 | 7.05 |
| 46 | KR-046 | Kernel Hardening (sysctl) Reference | Linux Engineering | 8 | 7 | 8 | 7.75 |
| 47 | KR-047 | ASN Reputation Research Methodology | Threat Intelligence | 8 | 6 | 8 | 7.50 |
| 48 | KR-048 | OSINT Verification Checklist | Threat Intelligence | 7 | 7 | 8 | 7.35 |
| 49 | KR-049 | Campaign Timeline Construction Template | Threat Intelligence | 8 | 5 | 8 | 7.25 |
| 50 | KR-050 | IOC Decay and TTL Guidance | Threat Intelligence | 7 | 5 | 9 | 7.00 |

---

## Ranks 51–75

| Rank | ID | Topic | Category | Eng | Search | Util | **Score** |
|------|-----|-------|----------|-----|--------|------|-----------|
| 51 | KR-051 | Honey API Design Patterns (Educational) | Deception Engineering | 7 | 5 | 7 | 6.50 |
| 52 | KR-052 | Telemetry Design for Honeypots | Deception Engineering | 8 | 5 | 7 | 6.85 |
| 53 | KR-053 | High vs Low Interaction Deception Tradeoffs | Deception Engineering | 7 | 5 | 7 | 6.50 |
| 54 | KR-054 | Measuring Deception Signal Quality | Deception Engineering | 8 | 4 | 7 | 6.55 |
| 55 | KR-055 | Supply Chain Beacon Ethics and Scope | Deception Engineering | 6 | 4 | 7 | 5.75 |
| 56 | KR-056 | Python Dependency Security Audit | Security Engineering | 8 | 7 | 8 | 7.75 |
| 57 | KR-057 | API Authentication Patterns Compared | Security Engineering | 8 | 7 | 8 | 7.75 |
| 58 | KR-058 | CSRF and Origin-Gate Patterns for Flask | Security Engineering | 7 | 5 | 7 | 6.50 |
| 59 | KR-059 | SSRF Prevention Checklist | Security Engineering | 8 | 7 | 8 | 7.75 |
| 60 | KR-060 | Webhook Signature Verification Patterns | Security Engineering | 7 | 5 | 8 | 6.85 |
| 61 | KR-061 | Secret Management Without Vault Appliances | Security Engineering | 7 | 6 | 8 | 7.05 |
| 62 | KR-062 | Immutable Audit Log Design | Security Engineering | 8 | 5 | 8 | 7.25 |
| 63 | KR-063 | Observability RED/USE for Security Services | Security Engineering | 7 | 5 | 7 | 6.50 |
| 64 | KR-064 | Background Job Safety Under Attack Load | Security Engineering | 7 | 4 | 7 | 6.25 |
| 65 | KR-065 | Multi-Source Correlation Patterns | SOC Engineering | 9 | 6 | 9 | 8.10 |
| 66 | KR-066 | Detection Pipeline Architecture Reference | SOC Engineering | 9 | 6 | 9 | 8.10 |
| 67 | KR-067 | Playbook: Phishing to Endpoint Compromise | SOC Engineering | 8 | 6 | 9 | 7.65 |
| 68 | KR-068 | Playbook: Credential Leak to Account Takeover | SOC Engineering | 8 | 7 | 9 | 8.05 |
| 69 | KR-069 | False Positive Budget and Tuning Cadence | SOC Engineering | 8 | 5 | 9 | 7.50 |
| 70 | KR-070 | SOC Shift Handoff Template | SOC Engineering | 6 | 4 | 8 | 5.90 |
| 71 | KR-071 | Detection Coverage Map Template | SOC Engineering | 7 | 5 | 8 | 6.85 |
| 72 | KR-072 | Purple Team Finding → Detection Ticket Flow | SOC Engineering | 7 | 4 | 8 | 6.50 |
| 73 | KR-073 | Cloud IAM Privilege Escalation Hunts | Threat Hunting | 8 | 7 | 8 | 7.75 |
| 74 | KR-074 | Service Account Anomaly Hunts | Threat Hunting | 7 | 5 | 8 | 6.85 |
| 75 | KR-075 | Hunt Report Writing Template | Threat Hunting | 6 | 4 | 8 | 5.90 |

---

## Ranks 76–100

| Rank | ID | Topic | Category | Eng | Search | Util | **Score** |
|------|-----|-------|----------|-----|--------|------|-----------|
| 76 | KR-076 | Malware Infrastructure Pivot Techniques | Threat Intelligence | 8 | 6 | 7 | 7.15 |
| 77 | KR-077 | Passive DNS Analysis Primer | Threat Intelligence | 7 | 6 | 7 | 6.75 |
| 78 | KR-078 | STIX/TAXII for Small Teams | Threat Intelligence | 6 | 5 | 7 | 6.00 |
| 79 | KR-079 | Log Source Normalization (CEF, LEEF, JSON) | Detection Engineering | 7 | 5 | 8 | 6.85 |
| 80 | KR-080 | Windows Sysmon High-Value Event IDs | Detection Engineering | 8 | 7 | 7 | 7.55 |
| 81 | KR-081 | CloudTrail Suspicious API Call Set | Detection Engineering | 8 | 7 | 7 | 7.55 |
| 82 | KR-082 | TLS JA3/JA4 Fingerprinting for Hunters | Detection Engineering | 7 | 6 | 7 | 6.75 |
| 83 | KR-083 | Fileless Malware Detection Heuristics | Detection Engineering | 7 | 7 | 7 | 7.00 |
| 84 | KR-084 | Detection-as-Code CI Pipeline Template | Detection Engineering | 8 | 5 | 8 | 7.25 |
| 85 | KR-085 | EDR Isolation vs Network Isolation Tradeoffs | Incident Response | 7 | 5 | 8 | 6.85 |
| 86 | KR-086 | Post-Incident Root Cause Analysis Template | Incident Response | 7 | 5 | 8 | 6.85 |
| 87 | KR-087 | Tabletop Exercise Scenarios (Linux Breach) | Incident Response | 6 | 4 | 8 | 5.90 |
| 88 | KR-088 | Logrotate Pitfalls That Destroy Evidence | Linux Engineering | 7 | 4 | 8 | 6.50 |
| 89 | KR-089 | OpenSSL Certificate Rotation Runbook | Linux Engineering | 6 | 5 | 7 | 6.00 |
| 90 | KR-090 | Package Supply Chain Verification on Debian | Linux Engineering | 7 | 6 | 8 | 7.05 |
| 91 | KR-091 | Integrating Deception Alerts into SIEM | Deception Engineering | 7 | 4 | 7 | 6.25 |
| 92 | KR-092 | Deception OPSEC for Operators | Deception Engineering | 7 | 3 | 7 | 5.80 |
| 93 | KR-093 | Runtime Telemetry Schema Design | Security Engineering | 8 | 4 | 7 | 6.55 |
| 94 | KR-094 | On-Call Runbook for Intel Feed Failures | SOC Engineering | 6 | 4 | 8 | 5.90 |
| 95 | KR-095 | SOC Metrics Dashboard (MTTD, MTTR, FP Rate) | SOC Engineering | 7 | 5 | 8 | 6.85 |
| 96 | KR-096 | Email Security Rule Patterns (SPF/DKIM) | Detection Engineering | 6 | 5 | 7 | 6.00 |
| 97 | KR-097 | Threat Actor TTP Clustering Worksheet | Threat Intelligence | 7 | 4 | 7 | 6.15 |
| 98 | KR-098 | Linux Privilege Escalation Audit Script | Linux Engineering | 7 | 6 | 8 | 7.05 |
| 99 | KR-099 | Reverse Canary Concepts (Defender-Facing) | Deception Engineering | 6 | 4 | 7 | 5.75 |
| 100 | KR-100 | Hunt Hypothesis Backlog Management | Threat Hunting | 6 | 3 | 7 | 5.45 |

---

## Quarterly Targets

| Quarter | Target publishes | Focus categories |
|---------|-----------------|------------------|
| Q3 2026 | 4 (incl. PUBLISH-001/002) | IR, Detection Engineering |
| Q4 2026 | 8 cumulative | Linux Engineering, Threat Hunting |
| Q1 2027 | 16 cumulative | SOC Engineering, Security Engineering |
| Q2 2027 | 24 cumulative | Threat Intel, Deception (educational) |

---

## Topic Selection Rationale (Top 2)

**PUBLISH-001 — Linux IR Checklist** ranks #1 because:
- Highest defender utility across all team sizes
- Strong search intent (`linux incident response checklist`, `compromised server what to do`)
- Pairs with WraithWall honeypot/Cowrie operator audience without revealing deception internals
- Evergreen — not CVE-bound

**PUBLISH-002 — Detection Engineering Handbook** ranks #2 because:
- Directly leverages platform expertise (MITRE mapping, log pipelines, rule tuning)
- Complements open-source `honeypot-mitre` without duplicating README
- High citation potential from SOC engineers building in-house content programs
- Creates natural internal links to future Sigma/YARA/Suricata spin-off pastes (KR-010–030)

---

## Dependencies

```
PUBLISH-001 (Linux IR)
    ├── enables KR-031, KR-033, KR-036 (IR spin-offs)
    └── referenced by KR-067, KR-068 (SOC playbooks)

PUBLISH-002 (Detection Handbook)
    ├── enables KR-004, KR-010, KR-021–030 (rule packs)
    └── referenced by KR-066 (pipeline architecture)

KR-003 (Redis Hardening)
    └── independent; publish Q3 after approval gate
```

---

## Manifest Schema (Post-Approval)

On each manual Pastebin publish, append to `manifest.json`:

```json
{
  "id": "PUBLISH-001",
  "slug": "linux-incident-response-checklist",
  "pastebin_url": null,
  "category": "Incident Response",
  "version": "1.0",
  "status": "draft",
  "approved_by": null,
  "published_at": null
}
```

---

*Phase 5: Do not publish until operator approves `PUBLISH_001.md` and `PUBLISH_002.md`.*