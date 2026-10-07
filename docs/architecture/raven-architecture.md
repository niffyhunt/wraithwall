# Raven — Autonomous Cybersecurity Reasoning Engine

**Status:** Architecture Proposal  
**Date:** 2026-07-18

---

## Mission

Raven is an autonomous cybersecurity reasoning engine that understands WraithWall's live telemetry, correlates detections across subsystems, and produces evidence-backed investigation conclusions — with or without human analysts in the loop.

Raven is not a chatbot. It's an AI security analyst that reads Cowrie sessions, follows MITRE kill chains, checks playbooks, queries threat intel, and produces investigation reports.

---

## Architecture

```
                    ┌─────────────────────────────┐
                    │        RAVEN CORE            │
                    │                              │
  Cowrie ──────────►│  Evidence Graph              │
  MITRE  ──────────►│  ┌───────┐  ┌───────────┐   │
  UNISON ──────────►│  │Memory │  │Reasoning  │   │
  Campaigns ───────►│  │Graph  │  │Pipeline   │   │
  Playbooks ───────►│  └───┬───┘  └─────┬─────┘   │
  Prediction ──────►│      │              │         │
  Intel ───────────►│  ┌───┴──────────────┴───┐    │
  Cases ───────────►│  │   Tool Orchestrator   │    │
                    │  └──────────┬───────────┘    │
                    │             │                 │
                    │  ┌──────────┴───────────┐    │
                    │  │  Investigation Agent  │    │
                    │  └──────────┬───────────┘    │
                    │             │                 │
                    │  ┌──────────┴───────────┐    │
                    │  │    Human Review       │    │
                    │  │    (HITL Gateway)     │    │
                    │  └──────────────────────┘    │
                    └─────────────────────────────┘
```

## Reasoning Pipeline

```
Event detected (Cowrie session, MITRE technique, campaign trigger)
        │
        ▼
1. CLASSIFY — What happened? (MITRE technique, severity, confidence)
        │
        ▼
2. CORRELATE — What else is connected? (same actor, campaign, timeline)
        │
        ▼
3. HYPOTHESIZE — What is the attacker trying to do? (prediction engine)
        │
        ▼
4. INVESTIGATE — Query evidence (sessions, logs, intel, canaries)
        │
        ▼
5. RECOMMEND — What should we do? (playbook, deception, containment)
        │
        ▼
6. EXECUTE — Deploy deception, block IP, notify (with human approval)
        │
        ▼
7. LEARN — Update actor profile, confidence, prediction model
```

## Agent Architecture

Raven uses specialized sub-agents, not a single monolithic LLM:

| Agent | Responsibility | Tools |
|-------|---------------|-------|
| **Classifier** | Map events to MITRE techniques | `mitre_engine.map_session()` |
| **Correlator** | Link events to actors/campaigns | `identity_graph.resolve_actor()`, `campaign_correlator` |
| **Hypothesizer** | Predict next technique | `prediction_engine.predict_next_technique()` |
| **Investigator** | Gather evidence from all subsystems | Cowrie sessions, intel collector, webhooks, canaries |
| **Recommender** | Generate playbook actions | `playbooks/engine.get_full_playbook()` |
| **Executor** | Deploy deception, block IP (gated) | `canary_service`, gateway, SOAR |
| **Reporter** | Generate investigation report | `report_generator` |

## Autonomous vs Human-in-the-Loop

| Action | Autonomous? | Gate |
|--------|------------|------|
| Classify event | ✅ Auto | None |
| Correlate with existing campaigns | ✅ Auto | None |
| Predict next technique | ✅ Auto | None |
| Generate playbook recommendation | ✅ Auto | None |
| Deploy honeytoken | ⚠️ Semi | Confirmation if severity ≥ high |
| Block IP | ❌ Manual | Always requires human approval |
| Disable account | ❌ Manual | Always requires human approval |
| Generate investigation report | ✅ Auto | None |
| Close case | ⚠️ Semi | Human review required |

## Evidence Graph

Raven maintains a temporal evidence graph connecting:
- Actor → Session → Commands → MITRE techniques
- Campaign → Sessions → Timeline
- Evidence → Sources → Confidence

This is the reasoning backbone — every conclusion links back to specific evidence with confidence scores.

## Integration Points

| Existing System | How Raven Integrates |
|----------------|---------------------|
| AI Concierge | Raven is the reasoning layer; Concierge is the user interface |
| RAG Engine | Raven queries docs for playbook/technique reference |
| MITRE Engine | Raven maps every event to techniques |
| Playbook Engine | Raven recommends and orchestrates playbooks |
| Prediction Engine | Raven feeds "next technique" into deception planning |
| Campaign Correlator | Raven links new events to existing campaigns |
| Identity Graph | Raven resolves attacker identity for cross-session tracking |
| UNISON | Raven contributes to and reads from UNISON scoring |
| Intel Collector | Raven queries threat intel for IOC enrichment |
| Case Management | Raven auto-creates and updates investigation cases |
| Notification Engine | Raven triggers alerts for significant findings |

## Roadmap

| Phase | Deliverable | Est. |
|-------|------------|------|
| 1 | Classifier + Correlator agents | 2 weeks |
| 2 | Investigation + Recommendation agents | 2 weeks |
| 3 | Execution agent (gated) + Evidence graph | 2 weeks |
| 4 | Learning loop + autonomous mode | 2 weeks |
