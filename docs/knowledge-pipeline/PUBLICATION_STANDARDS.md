# WraithWall Knowledge Publication Standards

**Version:** 1.0  
**Effective:** 2026-07-09  
**Applies to:** All Pastebin (and future mirror) publications under the Knowledge Publishing Pipeline  
**Does not apply to:** Deception propagation (`credential_propagation.py`), supply-chain canaries, or honey-credential planting.

---

## Purpose

Every publication must earn trust from practicing security engineers. The pipeline optimizes for **long-term reference value**, not impressions. Marketing copy belongs on the landing page and blog; Pastebin knowledge posts are field manuals.

---

## Mandatory Requirements

Each publication **must**:

1. **Solve a real engineering problem** — State the problem in the first 200 words. A reader should know within 30 seconds whether the paste applies to their situation.
2. **Contain actionable technical information** — Commands, rule snippets, configuration blocks, query templates, or decision trees that can be copied and adapted.
3. **Include practical examples** — At least three worked examples with expected output or interpretation guidance.
4. **Avoid unnecessary marketing** — No product CTAs, pricing, or feature comparisons. A single attribution line (`Maintained by WraithWall — wraithwall.online`) at the footer is permitted.
5. **Maintain publication-quality formatting** — Consistent heading hierarchy, monospace blocks for code, tables for checklists, horizontal rules between major sections.
6. **Be reusable by security engineers** — License reference: CC BY 4.0 (consistent with blog). No ND restrictions on Pastebin mirrors.

---

## Content Structure Template

```
TITLE: <Category> — <Specific Topic>
VERSION: 1.0
UPDATED: YYYY-MM-DD
MAINTAINER: WraithWall Engineering
LICENSE: CC BY 4.0

## Problem Statement
<What breaks, what risk, who is affected>

## Prerequisites
<Tools, access level, OS versions>

## Procedure / Reference
<Numbered steps or reference sections>

## Examples
<Minimum 3, with context>

## Validation
<How to confirm the control or detection works>

## Common Failures
<Mistakes that cause false negatives or operational pain>

## References
<MITRE IDs, RFCs, vendor docs — white-label where platform policy requires>

---
Attribution: WraithWall — https://wraithwall.online
Not affiliated with Pastebin. For corrections: contact@wraithwall.online
```

---

## Formatting Rules

| Element | Rule |
|---------|------|
| Title | `Category — Topic` in Pastebin paste title; max 80 chars |
| Headings | `##` and `###` only (Pastebin renders plain text; structure aids skimming) |
| Code blocks | Triple-backtick fenced blocks in source `.md`; Pastebin paste as plain text with 4-space indent or `----` separators |
| Commands | Prefix with `$` for unprivileged, `#` for root; never include real secrets |
| IPs / hostnames | Use `203.0.113.0/24` (TEST-NET-3), `198.51.100.10`, `example.com` |
| Credentials | `CHANGEME`, `redacted`, or generated fake values clearly labeled |
| Length | Minimum 2,500 words for handbooks; 800 words minimum for focused references |
| MITRE ATT&CK | Include technique IDs where mappings strengthen the content |

---

## Prohibited Content

- Live production IPs, API keys, lure credentials, or honeypot topology
- Deception lure templates or synthetic `.env` dumps
- Unredacted customer data or breach findings from `breach-monitor`
- Internal audit documents (`*_AUDIT.md`, threat models marked internal)
- Speculative vulnerabilities without reproduction steps
- LLM-generated filler without engineer review
- Cross-links to deception infrastructure (Cowrie hosts, tunnel ports)

---

## Review Workflow (Phase 5 Gate)

```
Draft (.md in docs/knowledge-pipeline/)
    → Self-review checklist (below)
    → Operator approval (manual)
    → Pastebin publish (manual)
    → manifest.json update
    → Optional: excerpt on /blog with canonical URL to paste
```

**No automated publishing.** `credential_propagation.py` must never import or call the knowledge publisher.

---

## Self-Review Checklist

- [ ] Problem statement is specific and falsifiable
- [ ] Tested all commands on Ubuntu 22.04+ or stated platform exceptions
- [ ] No production secrets or deception indicators in body
- [ ] Three or more worked examples present
- [ ] MITRE / CVE references verified against current IDs
- [ ] Spell-check and monospace alignment pass
- [ ] Footer attribution only — no marketing CTA in body
- [ ] Category tag matches `PUBLICATION_BACKLOG.md` taxonomy
- [ ] Slug registered in roadmap (not duplicate of existing paste)

---

## SEO & Discovery Guidelines

Optimize for how defenders actually search:

- Title includes the primary keyword (`Linux Incident Response Checklist`, not `WraithWall IR Guide`)
- First paragraph contains 2–3 natural keyword variants
- Use standard acronyms (IR, IOC, SIEM, KQL, YARA, Sigma)
- Pastebin expiry: `10Y` or `N` (never) for evergreen references; `1M` only for time-bound CVE advisories
- After publish, add URL to `manifest.json` and optionally cross-post summary to `/blog`

---

## Versioning

| Change type | Version bump |
|-------------|--------------|
| Typo / formatting | Patch note in footer |
| New section, same scope | Minor (1.0 → 1.1) |
| Procedure change | Minor + `UPDATED` date |
| Fundamental rewrite | Major (2.0) — new Pastebin URL; old URL gets deprecation header |

---

## Attribution Footer (Required)

```
---
WraithWall Knowledge Base · https://wraithwall.online
License: CC BY 4.0 · Corrections: contact@wraithwall.online
This document is independent of WraithWall deception systems.
```