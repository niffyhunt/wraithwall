# WraithMesh — Distributed Intelligence Fabric

**Status:** Architecture Proposal  
**Date:** 2026-07-18

---

## Mission

WraithMesh is the distributed intelligence fabric that connects every WraithWall deployment — honeypot sensors, remote VPS instances, edge collectors, and partner deployments — into a unified intelligence-sharing network. It provides sensor enrollment, secure telemetry collection, distributed deception coordination, and privacy-preserving threat intelligence sharing.

---

## Architecture

```
                        ┌──────────────────────┐
                        │   WRAITHWALL HUB     │
                        │   (Primary Node)     │
                        │                      │
                        │  ┌────────────────┐  │
                        │  │ Mesh Controller│  │
                        │  │ - Enrollment   │  │
                        │  │ - Certificate  │  │
                        │  │ - Routing      │  │
                        │  │ - Sync Engine  │  │
                        │  └───────┬────────┘  │
                        │          │            │
                        │  ┌───────┴────────┐  │
                        │  │ Intel Aggregator│  │
                        │  │ - Deception sync│  │
                        │  │ - Campaign merge│  │
                        │  │ - Actor merge   │  │
                        │  └────────────────┘  │
                        └──────────┬───────────┘
                                   │
              ┌────────────────────┼────────────────────┐
              │                    │                    │
    ┌─────────┴──────┐  ┌─────────┴──────┐  ┌─────────┴──────┐
    │ Cowrie Sensor  │  │ Intel Collector│  │ Edge Deploy    │
    │ (217.76.55.55) │  │ (Cowrie VPS)   │  │ ($4 VPS)       │
    │                │  │                │  │                │
    │ - SSH honeypot │  │ - OSINT fetch  │  │ - Mini-Cloud   │
    │ - Malware lab  │  │ - IOC shipping │  │ - Deception    │
    │ - BTCPay       │  │ - Threat feed  │  │ - Webhooks     │
    └────────────────┘  └────────────────┘  └────────────────┘
```

## Sensor Enrollment

Every sensor goes through a bootstrap process:

```
1. Generate enrollment token (one-time, shown once)
2. Sensor downloads bootstrap agent
3. Agent registers with Hub using token
4. Hub issues X.509 certificate + mesh identity
5. Sensor establishes mTLS connection to mesh
6. Hub assigns sensor role + capabilities
7. Sensor begins telemetry streaming
```

## Trust Model

| Layer | Mechanism |
|-------|-----------|
| Identity | X.509 certificates, auto-rotated |
| Transport | mTLS 1.3 |
| Authentication | Enrollment tokens (hashed server-side, never stored) |
| Authorization | RBAC per sensor (read/write/deploy) |
| Privacy | Anonymized hashes for shared intel |
| Integrity | HMAC-signed telemetry payloads |

## Distributed Intelligence

Shared across the mesh with privacy preservation:

| Data | Shared? | Anonymized? |
|------|---------|-------------|
| JA3/HASSH fingerprints | ✅ | Hashed |
| MITRE technique patterns | ✅ | Aggregated |
| Campaign hashes | ✅ | Hashed |
| Behavioral embeddings | ✅ | Vector only |
| IP addresses | ❌ | N/A |
| Credentials | ❌ | N/A |
| Full session data | ❌ | N/A |
| Customer PII | ❌ | N/A |

## Synchronization

| Sync Type | Frequency | Conflict Resolution |
|-----------|-----------|---------------------|
| Heartbeat | 30s | N/A |
| Telemetry | Real-time | Timestamp ordering |
| Deception config | On change | Last-write-wins |
| Threat intel | Hourly | Merge by source |
| Campaign merge | On detection | Confidence-weighted |
| Actor merge | On detection | Behavioral similarity |

## Self-Healing

- Heartbeat failure → 3 retries → mark offline → re-enroll on reconnect
- Certificate expiry → auto-renewal 7 days before
- Mesh partition → local queue → replay on reconnect
- Hub failure → secondary hub promotion

## Integration Points

| Existing System | How WraithMesh Integrates |
|----------------|---------------------------|
| Deployments | Mesh manages remote Docker/SSH deployments |
| Hooks | Webhook endpoints registered per-sensor |
| Sensors | Cowrie, canaries, web honeypots enroll through mesh |
| Intel Collector | Ships collected intel through mesh to hub |
| Campaign Correlator | Merges campaigns across sensors |
| Identity Graph | Merges actor identities across deployments |
| Notification Engine | Mesh health alerts routed through enterprise_notify |
| Case Management | Auto-creates cases for offline/misbehaving sensors |

## Raven + WraithMesh Separation

| Concern | Raven | WraithMesh |
|---------|-------|------------|
| Scope | Reasoning about attacks | Connecting deployments |
| Data flow | Reads from subsystems, produces insights | Routes telemetry between nodes |
| Autonomy | Can act autonomously | Infrastructure, not autonomous |
| User | SOC analyst | Platform operator |
| Output | Investigation reports, deception actions | Synchronized state, merged intelligence |

They complement: Mesh brings the data together; Raven makes sense of it.

## Roadmap

| Phase | Deliverable | Est. |
|-------|------------|------|
| 1 | Enrollment + certificate management + heartbeat | 2 weeks |
| 2 | Telemetry streaming + sensor health dashboard | 2 weeks |
| 3 | Distributed intelligence sharing (hashed fingerprints, campaign hashes) | 2 weeks |
| 4 | Self-healing + multi-region + offline mode | 2 weeks |
