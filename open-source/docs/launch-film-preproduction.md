# WraithWall OSS — Launch Film (2:00)

## DELIVERY NOTICE

**This document is a pre-production package only.** It contains storyboard, shot list, narration, typography, motion/audio timing, color direction, and capture sources. It does **not** include a rendered film. Hand this to a human editor, motion designer, or generative video pipeline for execution.

**Retained reference asset:** `wraithwall-oss-launch.mp4` (v5 voiceover walkthrough) may be used as pacing/reference only — not as the final launch film.

---

## 1. PHASE 0 — LAUNCH READINESS STATUS

Checked **2026-07-12** against live endpoints and repo state.

### Confirmed (safe to state on-screen at launch)

| Item | Status | Evidence |
|------|--------|----------|
| Public platform repo | **LIVE** | `https://github.com/niffyhunt/wraithwall` — `main`, pushed 2026-07-11 |
| Public toolkit repo | **LIVE** | `https://github.com/niffyhunt/wraithwall-toolkit` — `main`, pushed 2026-07-11 |
| Version tags on GitHub | **LIVE** | Both repos carry tag `v0.1.0` |
| Public marketing site | **LIVE** | `https://wraithwall.online` — landing, architecture, docs, launch, security, roadmap |
| OSS packages in toolkit | **PRESENT** | canary-kit, honeypot-mitre, dml-spec (+ incidents) in `wraithwall-toolkit` |
| RavenScan in platform repo | **PRESENT** | `wraithwall/packages/ravenscan` — CLI `raven scan`, Python SAST, scoring |

### Placeholder — confirm at actual launch (do not assert as fact until verified)

| Item | Flag | Why |
|------|------|-----|
| `pip install` / PyPI | **[PLACEHOLDER — CONFIRM AT ACTUAL LAUNCH]** | `ravenscan`, `canary-kit` not found on PyPI at time of writing |
| GitHub Release artifacts | **[PLACEHOLDER — CONFIRM AT ACTUAL LAUNCH]** | Tags exist; no published GitHub Release via API |
| OSS extraction = canonical production | **[PLACEHOLDER — CONFIRM AT ACTUAL LAUNCH]** | Extracted `wraithwall-oss/` is a subset; full production monolith is not identical |
| Auth findings resolved in extracted code | **[PLACEHOLDER — CONFIRM AT ACTUAL LAUNCH]** | No fresh auth sign-off doc in OSS tree; re-run security review before claiming “audit-clean” |
| External contributors / community | **DO NOT STAGE** | Solo same-day launch — no contributor history to show |

### On-screen / narration rule from Phase 0

- **May say:** “Source available on GitHub,” “MIT licensed,” tag URLs if still accurate at launch.
- **May not say (until placeholders cleared):** “Install from PyPI today,” “Community-driven,” “Thousands of contributors,” “Fully audited and canonical.”
- **Closing card URLs (use at launch if still true):**
  - `wraithwall.online`
  - `github.com/niffyhunt/wraithwall`
  - `github.com/niffyhunt/wraithwall-toolkit` ← add second repo; do not imply single-repo OSS

---

## 2. FULL STORYBOARD (SHOT BY SHOT)

**Runtime:** 2:00 (120s) · **Aspect:** 16:9 · **Base resolution:** 1920×1080 (deliver 1280×720 proxy for web)

| Shot | Time | Duration | Type | Description |
|------|------|----------|------|-------------|
| 1 | 0:00 | 3s | STYLIZED | Black. Room tone only. |
| 2 | 0:03 | 5s | STYLIZED | Earth limb from orbit. Subtle grid. No music swell. |
| 3 | 0:08 | 4s | STYLIZED | Satellite drifts L→R. Telemetry arc begins drawing. |
| 4 | 0:12 | 4s | STYLIZED | Second arc + soft pulse nodes. Title materializes. |
| 5 | 0:16 | 6s | SCREEN-CAPTURE | Dissolve to live landing hero — orbital section, cream paper UI. |
| 6 | 0:22 | 8s | SCREEN-CAPTURE | Hero terminal panel: globe, live feed lines appearing. |
| 7 | 0:30 | 6s | SCREEN-CAPTURE | Slow push on terminal — Cowrie session lines scroll (sanitized). |
| 8 | 0:36 | 8s | SCREEN-CAPTURE | Architecture page — public diagram gallery, slow vertical pan. |
| 9 | 0:44 | 8s | SCREEN-CAPTURE | Launch page + docs page blend — “open source” context. |
| 10 | 0:52 | 2.5s | SCREEN-CAPTURE | **Canary Kit** — toolkit README or CLI `canary-kit mint` terminal. |
| 11 | 0:54.5 | 2.5s | SCREEN-CAPTURE | **DML Spec** — `dml validate` terminal or docs trap schema. |
| 12 | 0:57 | 2.5s | SCREEN-CAPTURE | **RavenScan** — `raven scan` + RiskScore output (Python path only). |
| 13 | 0:59.5 | 2.5s | SCREEN-CAPTURE | **Honeypot MITRE** — package README or sample JSON → technique map. |
| 14 | 1:02 | 2.5s | SCREEN-CAPTURE | **Threat Intelligence** — public `/architecture` TI pipeline SVG (public tier). |
| 15 | 1:04.5 | 2.5s | SCREEN-CAPTURE | **Gateway** — live `/gateway` challenge page (no internal Redis keys). |
| 16 | 1:07 | 2.5s | SCREEN-CAPTURE | **Incident Response** — `/incident-playbook` public page. |
| 17 | 1:09.5 | 2.5s | SCREEN-CAPTURE | **Knowledge** — `/docs/knowledge/` article (published public doc). |
| 18 | 1:12 | 10s | SCREEN-CAPTURE | GitHub `wraithwall-toolkit` repo — file tree, README, real commit history. |
| 19 | 1:22 | 8s | SCREEN-CAPTURE | Terminal: `pytest` run on OSS tree (passing tests — real output). |
| 20 | 1:30 | 8s | SCREEN-CAPTURE | Terminal: `raven score` or CI-style exit code demo (no fake green checks). |
| 21 | 1:38 | 10s | STYLIZED | Dissolve to orbit return — match Shots 2–4 palette. Calm. |
| 22 | 1:48 | 4s | STYLIZED | Satellite + telemetry hold. Typography only. |
| 23 | 1:52 | 3s | STYLIZED | Fade to black. |
| 24 | 1:55 | 5s | STYLIZED | End card — minimal URLs. Hold. Fade out. |

---

## 3. TIMELINE WITH TIMESTAMPS

```
0:00.0  ████ BLACK + room tone
0:03.0  █████ Earth orbit wide (STYLIZED)
0:08.0  ████ Satellite enter + arc 1
0:12.0  ████ Arc 2 + title “WraithWall OSS”
0:16.0  ──── NARRATION A begins ────
0:16.0  ██████ Landing hero (SCREEN-CAPTURE)
0:22.0  ████████ Hero terminal live feed
0:30.0  ██████ Terminal push / session lines
0:36.0  ──── NARRATION B begins ────
0:36.0  ████████ Architecture public gallery
0:44.0  ████████ Launch + docs
0:52.0  ═══ SUBSYSTEM MONTAGE (score forward, no VO) ═══
0:52.0  │ 2.5s Canary Kit
0:54.5  │ 2.5s DML Spec
0:57.0  │ 2.5s RavenScan (CLI only)
0:59.5  │ 2.5s Honeypot MITRE
1:02.0  │ 2.5s Threat Intel (public diagram)
1:04.5  │ 2.5s Gateway
1:07.0  │ 2.5s Incident Response
1:09.5  │ 2.5s Knowledge
1:12.0  ──── NARRATION C begins ────
1:12.0  ██████████ GitHub repo (honest — structure, not community)
1:22.0  ████████ pytest terminal
1:30.0  ████████ raven score / CI gate
1:38.0  ──── NARRATION D begins ────
1:38.0  ██████████ Orbit return (STYLIZED)
1:48.0  ████ Typography hold
1:52.0  ███ Fade black
1:55.0  █████ End card
2:00.0  END
```

---

## 4. CAMERA DIRECTIONS

| Shot range | Framing | Movement | Lens feel |
|------------|---------|----------|-----------|
| 1–4 Orbit | Wide 35mm | 2–4% slow drift, no shake | Documentary space unit |
| 5–9 UI | 50mm equivalent crop on 1080p capture | Push-in 4–8% over hold | Product honesty |
| 10–17 Montage | 45mm | **Continuous diagonal pan** — same vector across all 8 cuts | One connected world |
| 18–20 Engineering | 50mm terminal + 40mm GitHub | Static + micro-creep 1%/5s | Craft / process |
| 21–24 Orbit end | 35mm | Pull back 3% | Exhale |

**Banned:** handheld shake, whip pans, zoom punches, glitch transitions, matrix rain.

---

## 5. NARRATION SCRIPT

**Voice direction:** Warm, calm, African English male (reference: Edge `en-NG-AbeoNeural` from v5). Conversational documentary. No buzzwords. Pause at ellipses.

```
[0:16] NARRATION A
Most security platforms focus on detecting attacks.
WraithWall was built to understand them.

[0:36] NARRATION B
Built from real production infrastructure…
now becoming open source.

[1:12] NARRATION C
This isn't a concept.
It's software you can read, run, and challenge.

[1:38] NARRATION D
Built quietly.
Released openly.
```

**Do not add:** “Revolutionary,” “AI-powered,” “next-generation,” “join our community.”

---

## 6. ON-SCREEN TEXT (DESIGNED TYPOGRAPHY)

Not subtitles — composed type. **Font:** IBM Plex Sans / system grotesk. **Margins:** 80px. **Accent:** `#C41A1A` on “WraithWall” and “open source” only.

| Time | Line 1 | Line 2 | Motion |
|------|--------|--------|--------|
| 0:12 | — | **WraithWall OSS** (title) | Fade 24f, scale 0.97→1.0 |
| 0:16 | Most security platforms focus on detecting attacks. | WraithWall was built to **understand** them. | Line 1 @0:17, Line 2 @0:21, track up 14px |
| 0:36 | Built from real production infrastructure… | now becoming **open source**. | Stagger 0.4s |
| 0:52–1:09 | Subsystem name only (one per cut) | 01–08 index | Match cut, 12f fade |
| 1:12 | This isn't a concept. | Software you can inspect. | Hold through GitHub shots |
| 1:38 | Built quietly. | Released openly. | Wide tracking, lower third |
| 1:55 | **WraithWall OSS** | wraithwall.online · github.com/niffyhunt/wraithwall | Center, minimal |

**Placeholder line if PyPI not live at launch:** omit “pip install” from all typography.

---

## 7. MOTION NOTES

| Element | Behavior |
|---------|----------|
| Telemetry arcs (Shots 2–4, 21) | Bézier draw 0→100% over 4s; opacity 12–18% |
| Satellite | `x += sin(t*0.4)*0.3px/frame` |
| Terminal feed (6–7) | Only **record** real SSE from `/api/cowrie/stream` or replay sanitized capture — do not fabricate IPs |
| Architecture pan (8) | Scroll or post-move on **public** SVGs under `static/img/architecture/public/` |
| Montage (10–17) | Shared `pan_x` increment per shot; dissolve 10f between |
| GitHub (18) | Slow scroll README + visible **real** commit dates — no fake PR UI |
| pytest (19) | Real terminal recording; cut on actual pass summary |
| End card (24) | 0.3% scale breathe; no lens flare |

---

## 8. MUSIC & TRANSITION TIMING

### Music

| Time | Element | Level (under VO) |
|------|---------|------------------|
| 0:00–0:16 | Room tone + 55Hz pad | −42dB (near silence) |
| 0:16–0:52 | Pad opens + 110Hz harmonic | −30dB |
| 0:52–1:12 | Montage: same bed, no percussion | −28dB |
| 1:12–1:38 | Narrow EQ (LPF 500Hz) | −30dB |
| 1:38–1:52 | Strip to room tone | −36dB |
| 1:52–2:00 | Fade to silence | — |

### Transitions

| Cut | Type | Duration |
|-----|------|----------|
| Orbit → Landing | Luminance dissolve | 1.0s |
| Landing → Architecture | Cross-dissolve | 0.8s |
| Architecture → Montage | Match-cut motion carry | 0.5s |
| Montage internal | Dissolve | 0.35s |
| Montage → GitHub | Fade via paper white flash 15% | 0.6s |
| GitHub → Orbit | Dissolve | 1.2s |
| Orbit → Black | Fade | 1.0s |

---

## 9. COLOR GRADING DIRECTION

| Act | Base | Treatment |
|-----|------|-----------|
| Orbit (STYLIZED) | Navy `#0B1426` → graphite `#111318` | Lift shadows +3; desat −5% |
| Live UI (SCREEN-CAPTURE) | Paper cream `#FAFAF7` | Preserve warmth; contrast +4%; no teal/orange split |
| Montage | Unified LUT across 8 shots | Sat −8%; reds only on brand accent |
| Terminal / GitHub | Neutral | Slight desat −10% — engineering honesty |
| End card | Pure black `#000000` | Text `#FAFAF7` / muted `#969690` |

**Banned grades:** matrix green, neon cyan, “hacker” blue, crushed blacks on UI text.

---

## 10. PER-SHOT CAPTURE CLASSIFICATION & SOURCES

| Shot | Class | Record from (specific) | Readiness |
|------|-------|------------------------|-----------|
| 1–4, 21–24 | **STYLIZED** | Motion designer / AE / generative — match `open-source/docs/oss-ecosystem.svg` orbit language | N/A |
| 5 Landing hero | **SCREEN-CAPTURE** | `https://wraithwall.online/` — `frontend-landing` → `static/landing_dist` via `Landing.vue` + `WraithHero` | READY |
| 6–7 Terminal | **SCREEN-CAPTURE** | Same page, `HeroTerminal.vue` — live feed from `/api/cowrie/recent` or `/api/cowrie/stream` | READY — **sanitize IPs** (see §12) |
| 8 Architecture | **SCREEN-CAPTURE** | `https://wraithwall.online/architecture` — public diagrams only | READY |
| 9 Launch/Docs | **SCREEN-CAPTURE** | `/launch` + `/docs` server templates | READY |
| 10 Canary Kit | **SCREEN-CAPTURE** | Local: `wraithwall-toolkit/canary-kit` README + `canary-kit mint` CLI | READY |
| 11 DML Spec | **SCREEN-CAPTURE** | `wraithwall-toolkit/dml-spec` — `dml validate` example | READY |
| 12 RavenScan | **SCREEN-CAPTURE** | `raven scan .` on `wraithwall` repo — show **Python SAST + RiskScore grade only** | READY (see §11) |
| 13 Honeypot MITRE | **SCREEN-CAPTURE** | `wraithwall-toolkit/honeypot-mitre` sample output | READY |
| 14 Threat Intel | **SCREEN-CAPTURE** | `static/img/architecture/public/07-threat-intelligence-pipeline.svg` on `/architecture` | READY — public tier only |
| 15 Gateway | **SCREEN-CAPTURE** | `https://wraithwall.online/gateway` — `gateway.py` blueprint | READY |
| 16 Incident Response | **SCREEN-CAPTURE** | `https://wraithwall.online/incident-playbook` | READY |
| 17 Knowledge | **SCREEN-CAPTURE** | `https://wraithwall.online/docs/knowledge/<published-slug>` | READY |
| 18 GitHub | **SCREEN-CAPTURE** | `https://github.com/niffyhunt/wraithwall-toolkit` — real tree, README, commits | READY |
| 19 pytest | **SCREEN-CAPTURE** | `cd wraithwall && pytest` — real output | READY |
| 20 raven score | **SCREEN-CAPTURE** | `raven score --fail-under 70` on OSS repo | READY |

### Authenticated dashboard (optional B-roll — not required)

| Source | Note |
|--------|------|
| `https://wraithwall.online/home` — `frontend-home/HomeView.vue` | **Requires logged-in operator session.** Do not use stock dashboard UI. If used: capture offline from real session; blur any user email / API keys. |

---

## 11. SUBSYSTEM SEQUENCE — AUDIT BEFORE FILMING

| Subsystem | Include? | Representation | Honesty note |
|-----------|----------|----------------|--------------|
| **Canary Kit** | Yes | CLI + README | Package tested in toolkit repo |
| **DML Spec** | Yes | Validator terminal | Production-ready spec package |
| **RavenScan** | Yes — **narrow** | `raven scan` / `raven score` terminal + `.raven/RiskScore.json` | Show **Python scanner + scoring + CLI**. Do **not** claim full multi-language production analysis — Go/JS/Rust/Java plugins are regex-based alpha (`RAVEN_REVIEW.md` §1.2) |
| **Honeypot MITRE** | Yes | Sample log → ATT&CK map | Toolkit package ready |
| **Threat Intelligence** | Yes — **public diagram** | Architecture SVG public tier | Do not show internal Redis keys, thresholds, or live ASN feeds |
| **Gateway** | Yes | `/gateway` public page | OSS `gateway.py` — show challenge flow, not blocklist internals |
| **Incident Response** | Yes | Public playbook page | Playbook content — not unreleased operator console |
| **Knowledge** | Yes | Published knowledge doc | Real article from `/docs/knowledge/` |

**Cut if not ready at launch:** anything still marked [PLACEHOLDER] in §1.

---

## 12. DISCLOSURE REVIEW (PUBLIC FILM)

Flag and **sanitize or cut** before publish:

| Risk | Example | Action |
|------|---------|--------|
| Live attacker IPs | Cowrie feed shows real `203.0.x.x` | Use RFC5737 TEST-NET only in demo env, or blur last octet |
| BGP prefixes | Production prefix monitoring | Use public diagram — not live hijack alert with real ASN |
| Detection thresholds | Dashboard “2,847 threats” if operational | Landing stats are acceptable if they are **public marketing counters** — do not show admin-only thresholds |
| Internal API paths | `/api/admin/*`, sandbox internals | Terminal shot: landing public APIs only |
| Sensor topology | Full deception mesh with internal hostnames | Use `static/img/architecture/public/06-deception-mesh.svg` if needed — public variant |
| Secrets | `.env`, API keys in terminal | Record fresh session; audit every frame |
| Unreleased features | Console tabs not in OSS | Do not screen-cap private admin UI without clearance |

**Standard:** Same bar as public docs and blog — if it would not ship on `wraithwall.online/docs`, it does not ship in the film.

---

## 13. 40–50s BEAT — HONEST SOLO LAUNCH (NOT “COMMUNITY”)

**Do not film:** developers in stock footage, fake pull requests, “contributors” graph, Discord/community montage.

**Do film (Shots 18–20):**

1. GitHub repository file tree — real folders (`packages/`, `src/`, `tests/`, `docker/`)
2. README scroll — install from git clone `[PLACEHOLDER: pip if PyPI live]`
3. `git log --oneline -20` — real commit history (solo founder is fine — honesty is the point)
4. `pytest -q` — passing tests, real count
5. `raven doctor` or `wraithwall check` — environment sanity

**Narration supports craft, not crowd:** “Software you can read, run, and challenge.”

---

## 14. EXECUTION HANDOFF

### For human editor (DaVinci Resolve / Premiere)

1. Import §3 timeline as marker track.
2. Record §10 sources at 1920×1080 60fps → deliver 24fps timeline.
3. Apply §9 grade per act.
4. Place §5 VO; align §6 type to VO downbeats.
5. Mix §8 music under VO at specified levels.
6. Legal: confirm GitHub and site URLs on end card at export time.

### For generative / pipeline execution

- Input: this document + captured PNG/MP4 from §10.
- STYLIZED shots: generate from `oss-ecosystem.svg` palette reference.
- Hard constraint: **SCREEN-CAPTURE shots must use provided captures** — no synthetic dashboards.

### Reference pacing only

- `static/img/oss-launch/wraithwall-oss-launch.mp4` (v5) — voice and beat timing reference, not final picture lock.

---

## 15. EXPLICIT HANDOFF STATEMENT

This package is **pre-production**. No finished 2:00 film is delivered with this document. Execution is required by an editor or video pipeline. Phase 0 placeholders must be cleared or remain flagged in final typography and narration before public release.

---

*WraithWall OSS · Pre-production v1 · 2026-07-12*