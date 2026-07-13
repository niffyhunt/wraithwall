# First Contributor Tasks — WraithWall Phase X

**Date:** 2026-07-10

---

## Label: `good first issue` — Ready for First-Time Contributors

These tasks are designed for contributors who have never seen the codebase before. Each can be completed in under 2 hours, requires no architecture knowledge, and involves editing exactly one file.

### Task 1: Fix newsletter branding error
**File:** `templates/newsletter.html`
**Line:** 179
**Issue:** Topbar brand reads "WraithCyber" instead of "WraithWall"
**Fix:** Change `WraithCyber` → `WraithWall`
**Time:** 5 minutes
**Teaches:** Template structure, brand conventions

### Task 2: Fix broken favicon path
**File:** `templates/home.html`
**Line:** 20
**Issue:** `/Static/images/banner.jpg` uses capital `S` — should be lowercase `/static/`
**Fix:** Change `/Static/` → `/static/`
**Time:** 5 minutes
**Teaches:** Flask static file serving, path conventions

### Task 3: Fix stale SECURITY.md reference
**File:** `CONTRIBUTING.md`
**Lines:** 9, 43
**Issue:** Calls `SECURITY.md` a "draft" — it has been finalized since Phase 2
**Fix:** Remove "draft" labels, update to "finalized"
**Time:** 5 minutes
**Teaches:** Documentation conventions, cross-referencing

### Task 4: Fix CHANGELOG.md dead references
**File:** `CHANGELOG.md`
**Lines:** 11, 18
**Issue:** References `POSTS/twitter_launch.md` and `POSTS/medium_launch.md` — these files were removed in Phase 11
**Fix:** Remove the two broken references
**Time:** 5 minutes
**Teaches:** Changelog format, repo history

### Task 5: Remove duplicate CHANGELOG sections
**File:** `CHANGELOG.md`
**Issue:** Two `### Added` sections exist (lines 9 and 21)
**Fix:** Merge into one `### Added` section
**Time:** 5 minutes
**Teaches:** Keep-a-Changelog format

### Task 6: Fix ROADMAP.md stale reference
**File:** `ROADMAP.md`
**Line:** 10
**Issue:** "Current focus: Phase 8 architecture corpus + operator console visualization" — Phase 9 is already live
**Fix:** Update to "Phase 10: Open source release + community readiness"
**Time:** 5 minutes
**Teaches:** Project phase tracking

### Task 7: Fix ROADMAP.md self-contradiction
**File:** `ROADMAP.md`
**Lines:** 17 vs 35
**Issue:** Line 17 lists "P1 — Finalize SECURITY.md" but line 35 says it's "Finalized"
**Fix:** Move SECURITY.md from P1 to "Completed" section
**Time:** 5 minutes
**Teaches:** Document consistency

### Task 8: Fix deployment.md broken path
**File:** `docs/deployment.md`
**Line:** 67
**Issue:** References `ARCHITECTURE_VALIDATION.md` — actual path is `docs/architecture/ARCHITECTURE_VALIDATION.md`
**Fix:** Update to correct relative path
**Time:** 5 minutes
**Teaches:** Doc cross-referencing

### Task 9: Clean contact.html service dropdown
**File:** `templates/contact.html`
**Lines:** 415-421
**Issue:** Service options mix security services with web design ("Website Design", "Mobile App Design", "Logo Design")
**Fix:** Remove non-security options, add "Canary/Honeypot Deployment" and "Threat Intelligence API Integration"
**Time:** 10 minutes
**Teaches:** Template editing, brand consistency

### Task 10: Add root LICENSE file
**File:** `/LICENSE` (create new)
**Issue:** README shows MIT badge but no root LICENSE file. MIT license exists at `open-source/LICENSE`.
**Fix:** Copy `open-source/LICENSE` to repo root as `LICENSE`
**Time:** 2 minutes
**Teaches:** OSS licensing conventions

---

## Label: `help wanted` — For Experienced Contributors

### Task 11: Add docstrings to one blueprint module
**File:** Any single `*_intelligence.py` or `*_service.py` module
**Scope:** Add Google-style docstrings to all public functions
**Time:** 1-2 hours
**Teaches:** Code style, subsystem understanding

### Task 12: Write a unit test for one model
**File:** `tests/` (add to existing test suite)
**Scope:** Test one SQLAlchemy model from `main.py` (e.g., User, CanaryRecord, HoneyToken)
**Time:** 1-2 hours
**Teaches:** Test patterns, model relationships, pytest fixtures

### Task 13: Create `.github/ISSUE_TEMPLATE/bug_report.md`
**Scope:** Standard bug report template with sections for description, steps, expected behavior, actual behavior, environment
**Time:** 30 minutes
**Teaches:** GitHub community infrastructure

### Task 14: Create `PULL_REQUEST_TEMPLATE.md`
**Scope:** PR template with checklist: tested locally, added tests, updated docs, screenshots if UI
**Time:** 15 minutes
**Teaches:** GitHub community infrastructure

### Task 15: Add one new deception bait to BAIT_INVENTORY.md
**Scope:** Propose a new bait tier entry following the existing format: name, purpose, layer, intelligence yield, engagement score, forensics score, safety score, deployment plan
**Time:** 30 minutes
**Teaches:** Deception architecture, threat modeling

---

## Label: `research` — For Security Researchers

### Task 16: Analyze one week of Cowrie sessions
**Scope:** Pull sanitized Cowrie data from `docs/` examples, write a 500-word analysis of attack patterns
**Time:** 2-4 hours
**Teaches:** Threat intelligence analysis, honeypot data interpretation

### Task 17: Write a Sigma rule for a Cowrie-detected TTP
**Scope:** Pick one attacker behavior from cowrie logs (e.g., admin/admin brute force, SOCKS proxy test via direct-tcp), write a Sigma detection rule
**Time:** 1-2 hours
**Teaches:** Detection engineering, Sigma format, MITRE mapping

### Task 18: Propose a new campaign correlation algorithm
**Scope:** Review `campaign_correlator.py`, propose an alternative clustering approach (e.g., DBSCAN instead of similarity threshold)
**Time:** 2-4 hours
**Teaches:** ML for security, campaign analysis

---

## Task Format for GitHub Issues

Each task issue should include:
```
### What needs to change
[One sentence describing the issue]

### Where
File: [path]
Line(s): [numbers]

### Current state
[Current code or text]

### Expected state
[What it should look like]

### How to test
[If applicable — commands to run, what to check]

### Time estimate
[X minutes/hours]

### First time?
If this is your first contribution, check out AGENTS.md for orientation.
```

---

## Verdict

These 18 tasks cover the full contributor spectrum: brand-new open-source contributors (Tasks 1-10), experienced engineers (Tasks 11-15), and security researchers (Tasks 16-18). The first 10 tasks are deliberately tiny — each takes under 10 minutes — to build contributor confidence before tackling anything architectural. Every task teaches one specific aspect of the codebase without requiring full system understanding.
