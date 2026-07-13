# Community Roadmap — WraithWall Phase X

**Date:** 2026-07-10

---

## First 30 Days After Open Source

### Week 1: Launch
- [ ] Push to `github.com/niffyhunt/wraithwall` with all P0 items resolved
- [ ] Post announcement on X/Twitter (@Niffy_hunt)
- [ ] Submit to Hacker News "Show HN" with the real Cowrie attack stories
- [ ] Post on r/netsec, r/cybersecurity, r/homelab with the technical blog posts
- [ ] Enable GitHub Discussions on the repo
- [ ] Add shields.io badges: tests passing, license MIT, Python 3.12, stars

### Week 2-3: First Wave Response
- [ ] Triage incoming issues and PRs (expect 5-15 from launch visibility)
- [ ] Respond to all issues within 48 hours (solo-maintainer SLA)
- [ ] Identify 3-5 "good first issue" labels from incoming feedback
- [ ] Write response to common questions as FAQ in Discussions
- [ ] Accept simple PRs (doc fixes, typos, small bug fixes)

### Week 4: Community Calibration
- [ ] Publish a "What's next for WraithWall" blog post
- [ ] Triage community feature requests against ROADMAP.md
- [ ] Set up Open Collective or GitHub Sponsors if community shows interest
- [ ] Begin extracting models from `main.py` — public, live-streamed, with contributors

---

## Community Profiles and Strategies

### Security Researchers
**What they want:** Real honeypot data, novel deception techniques, reproducible attacker behavior analysis.

**Strategy:**
- Label issues tagged `cowrie-analysis`, `campaign-correlation`, `fingerprint` as research-friendly
- Share sanitized Cowrie session data as example datasets in `examples/`
- Encourage PRs that add new detection rules (Sigma, YARA, MITRE mappings)
- Cross-link with the blog posts that describe real incidents

### Enterprise Users
**What they want:** Production readiness, deployment guides, security guarantees, vendor support.

**Strategy:**
- Be honest: this is a solo-built platform, not a supported product
- Publish deployment hardening guide in `docs/deployment.md`
- Offer paid consulting/support as a separate commercial offering (no bait-and-switch)
- Keep the OSS version MIT-licensed — no open-core tricks

### Students and Learners
**What they want:** Something to study, clone, and learn from. Clear code, documented architecture.

**Strategy:**
- Create `docs/LEARNING_PATH.md` with a reading order:
  1. README → 2. AGENTS.md → 3. LAUNCH.md → 4. Blog posts → 5. Architecture corpus → 6. Source code
- Add docstrings to key functions in `main.py` (the most-studied file)
- Create a "WraithWall 101" video or blog series
- Add a `STUDY_GUIDE.md` walking through the Cowrie pipeline end-to-end

### Defenders and Blue Teams
**What they want:** Tools they can deploy, detection rules they can adapt, honeypots they can fork.

**Strategy:**
- Make the 3 OSS packages (`honeypot-mitre`, `canary-kit`, `dml-spec`) installable via `pip`
- Add `pip install` instructions to each package README
- Create deployment guides for each tool independently of the full WraithWall stack
- Cross-promote each tool in the main README

### Self-Hosters
**What they want:** One `docker-compose up` and it works.

**Strategy:**
- Build a root-level `docker-compose.yml` for the full stack (not yet; P2 item)
- Document all required env vars in one place
- Add health-check endpoints for monitoring
- Keep dependencies minimal — don't require Kubernetes

---

## Community Infrastructure

| Channel | Priority | Rationale |
|---------|----------|-----------|
| GitHub Discussions | P0 | Already built into repo; zero setup; keeps discussions near code |
| X/Twitter (@Niffy_hunt) | P0 | Existing presence; primary launch channel |
| Hacker News | P1 | Best audience for solo-built security tools |
| r/netsec | P1 | Security-focused; link blog posts, not self-promotion |
| Discord | P2 | Higher maintenance burden; only if community >100 members |
| Open Collective | P2 | Financial support if interest exists |
| YouTube/Twitch | P2 | Architecture walkthroughs, live coding sessions |

---

## Roadmap Labels for GitHub Issues

```
good first issue    — 1-hour tasks for first-time contributors
help wanted         — Open to community PRs
research            — Analysis/correlation tasks needing creative thinking
bug                 — Confirmed defects
enhancement         — Feature requests
documentation       — Docs, guides, tutorials
honeypot            — Cowrie, deception, bait infrastructure
deception           — Canary, honey-token, credential propagation
visualization       — Architecture graphs, frontend dashboards
infrastructure      — CI/CD, Docker, deployment
security            — Vulnerabilities, hardening (private disclosure for real sec issues)
```

---

## Contributor Recognition

- **CONTRIBUTORS.md** — List all contributors by name, linked to their GitHub profile
- **"First PR" label** — Celebrate first-time contributors
- **Shout-out in changelog** — Name contributors in release notes
- **Blog interview series** — "How I contributed to WraithWall" posts for substantial contributions

---

## Growth Expectations

Given the niche (deception engineering + threat intelligence) and the solo-maintainer nature:

- **Realistic:** 50-100 stars in first month, 5-10 contributors, 10-20 issues
- **Optimistic:** 200+ stars (if Show HN or r/netsec goes well), 20+ contributors, steady PR flow
- **Pessimistic:** 20-30 stars, 2-3 contributors — still a success for a solo platform

The platform's uniqueness (real production honeypot data, documented deception architecture) is its strongest growth lever. Most security tools claim they "could" detect attacks. WraithWall has the actual attack logs.

---

## Sustained Engagement Plan (Months 3-12)

1. **Monthly blog post** — One Cowrie incident analysis, one architecture deep-dive, one tool release
2. **Quarterly architecture review** — Update the corpus, publish findings as blog post
3. **"Attacker of the Month"** — Feature one interesting attacker session from the honeypots
4. **Community challenges** — "Write a Sigma rule for this Cowrie session" or "Add a new deception bait"
5. **Office hours** — Monthly 1-hour live stream where contributors can ask questions in real-time

---

## Verdict

WraithWall's community potential is **above average for solo-maintained security tools** because:
- It has real production data (not simulated)
- The architecture documentation is unusually thorough
- The blog content provides context and stories, not just code
- The deception subsystem (canary tokens, credential propagation, DML) is genuinely unique

The limiting factor is the solo maintainer's bandwidth. Be honest about this in the README and CONTRIBUTING.md. A project that sets clear expectations and delivers on them builds more trust than one that promises rapid responses and misses them.
