# WraithWall Event Validation Report — Phase C (Regenerated)

**Generated:** 2026-07-09
**Source commit:** `51554d9cd5b989f14c8b687e7574454fd8ab387a`
**Derived from:** event_graph.json (authoritative), architecture.json

## 0. Corpus Sync Verification

| Metric | Value |
|--------|-------|
| Events in event_graph.json | 173 |
| Events documented below | 173 |
| Orphans (JSON → MD) | 0 |
| Event storms (ES-01..ES-05) | 5 patterns (not individual graph nodes) |

---

## 1. Per-Event Verification

### 1.1 Authentication (A-01 – A-20)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| A-01 | `login_attempt` | Authentication | Database (LoginAttempt) | email, ip, success, user_agent | tier2 | 1.0 | None |
| A-02 | `login_bot_detected` | Authentication | AuditLog | email, ip, user_agent | tier1 | 1.0 | no retry on critical tier |
| A-03 | `login_blocked` | Authentication | AuditLog | email, ip, reason | tier2 | 1.0 | None |
| A-04 | `login_success` | Authentication | Database (LoginAttempt, ActiveSession, UserBehavior), Telegram | email, ip, user_agent, session_token | tier2 | 1.0 | None |
| A-05 | `login_failed` | Authentication | Database (LoginAttempt), Rate limiter | email, ip, user_agent, attempt_count | tier2 | 1.0 | None |
| A-06 | `mfa_required` | Authentication | AuditLog, Response | email, ip | tier2 | 1.0 | None |
| A-07 | `mfa_success` | Authentication | Database (ActiveSession, LoginAttempt) | email, ip | tier2 | 1.0 | None |
| A-08 | `mfa_failed` | Authentication | Database (LoginAttempt), Rate limiter | email, ip, attempts | tier0 | 1.0 | None |
| A-09 | `otp_generated` | Authentication | Database (EmailVerification) | email, ip | tier2 | 1.0 | None |
| A-10 | `otp_login_success` | Authentication | Database (ActiveSession) | email, ip | tier2 | 1.0 | None |
| A-11 | `device_verification_sent` | Authentication | Database (TrustedDevice), Email (Resend) | email, device_fingerprint, ip | tier2 | 1.0 | None |
| A-12 | `device_verified` | Authentication | Database (TrustedDevice) | email, device_fingerprint | tier3 | 1.0 | None |
| A-13 | `password_reset_requested` | Authentication | Database (PasswordReset), Email (Resend) | email, ip | tier2 | 1.0 | None |
| A-14 | `password_reset_completed` | Authentication | Database (PasswordReset) | email, ip | tier2 | 1.0 | None |
| A-15 | `logout` | Authentication | Database (ActiveSession) | email, session_token | tier3 | 1.0 | None |
| A-16 | `session_expired` | Authentication | Database (ActiveSession), _finalize_session_dna | user_id, session_token | tier2 | 1.0 | None |
| A-17 | `user_registered` | Authentication | Database (User), Email, Discord (+1) | email, ip, provider (local/google) | tier2 | 1.0 | None |
| A-18 | `google_oauth_success` | Authentication | Database (User, ActiveSession), AuditLog | email, google_id | tier0 | 1.0 | None |
| A-19 | `api_key_created` | Authentication | Database (APIKey), AuditLog | user_id, key_name, permissions | tier2 | 1.0 | None |
| A-20 | `api_key_authenticated` | Authentication | Rate limiter, Database (APIKeyUsage) | key_prefix, endpoint | tier1 | 1.0 | no retry on critical tier |

**Category summary:** 20 events cataloged. All payloads defined in event_graph.json.

### 1.4 BGP Monitor (B-01 – B-05)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| B-01 | `bgp_route_updated` | BGP Monitor | BGP state tracker, Redis (bgp_monitor:route_state) | prefix, origin_as, path, timestamp | tier2 | 0.95 | None |
| B-02 | `bgp_hijack_detected` | BGP Monitor | Database (ImmutableLog), Telegram, Discord (+1) | anomaly_type, prefix, expected_as, obser | tier0 | 0.95 | None |
| B-03 | `bgp_route_change_anomaly` | BGP Monitor | Redis (bgp_monitor:route_changes) | prefix, old_as, new_as, change_count | tier2 | 0.95 | None |
| B-04 | `bgp_cloudflare_poll_completed` | BGP Monitor | BGP analysis engine | prefix, is_hijack, is_leak, is_misorigin | tier3 | 0.95 | None |
| B-05 | `bgp_anomaly_alert_sent` | BGP Monitor | Redis (bgp_alert_sent:{hash}) | anomaly_hash, channels (Telegram, Discor | tier2 | 0.95 | None |

**Category summary:** 5 events cataloged. All payloads defined in event_graph.json.

### 1.7 Canary / Honey Token (C-01 – C-15)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| C-01 | `canary_planted` | Canary / Honey Token | Database (CanaryRecord, ImmutableLog) | table_name, record_id, canary_type | tier2 | 0.97 | None |
| C-02 | `canary_triggered` | Canary / Honey Token | Database (CanaryAlert, ImmutableLog), Telegram, Discord (+1) | canary_id, type, ip, email, access_metho | tier0 | 0.97 | None |
| C-03 | `canary_deactivated` | Canary / Honey Token | Database (CanaryRecord) | canary_id | tier3 | 0.97 | None |
| C-04 | `honey_token_planted` | Canary / Honey Token | Database (HoneyToken, ImmutableLog) | token_type, token_value, severity, respo | tier2 | 0.97 | None |
| C-05 | `honey_token_triggered` | Canary / Honey Token | Database (HoneyTokenEvent, ImmutableLog), Discord | token_type, token_value, attacker_ip, fu | tier2 | 0.97 | None |
| C-06 | `honey_token_deactivated` | Canary / Honey Token | Database (HoneyToken) | token_id, is_active | tier3 | 0.97 | None |
| C-07 | `canary_service_token_minted` | Canary / Honey Token | Database (CanaryServiceToken), Email | public_id, token_type, label, owner | tier2 | 0.97 | None |
| C-08 | `canary_service_hit` | Canary / Honey Token | Database (CanaryServiceHit), Telegram, Discord (+2) | token_id, source_ip, user_agent, method, | tier0 | 0.97 | None |
| C-09 | `canary_subscription_activated` | Canary / Honey Token | Database (CanarySubscription), AuditLog, Email | user_id, plan, processor | tier2 | 0.97 | None |
| C-10 | `canary_subscription_cancelled` | Canary / Honey Token | Database (CanarySubscription), AuditLog | user_id, reason | tier3 | 0.97 | None |
| C-11 | `canary_trial_started` | Canary / Honey Token | Database (CanarySubscription), Telegram, Email | user_id, trial_days | tier2 | 0.97 | None |
| C-12 | `canary_trial_ending` | Canary / Honey Token | Telegram, Email | user_id | tier3 | 0.97 | None |
| C-13 | `canary_trial_expired` | Canary / Honey Token | Database (CanarySubscription), AuditLog, Email | user_id | tier2 | 0.97 | None |
| C-14 | `canary_trial_billed` | Canary / Honey Token | Database (CanarySubscription), AuditLog | user_id, amount, processor | tier2 | 0.97 | None |
| C-15 | `dml_trap_deployed` | Canary / Honey Token | Database (ImmutableLog, CanaryRecord/HoneyToken), Redis | trap_id, trigger_type, path | tier2 | 0.97 | None |

**Category summary:** 15 events cataloged. All payloads defined in event_graph.json.

### 1.10 Session DNA (D-01 – D-08)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| D-01 | `dna_baseline_created` | Session DNA | Database (SessionDNA) | user_id, avg_requests, avg_duration, com | tier2 | 1.0 | None |
| D-02 | `dna_baseline_updated` | Session DNA | Database (SessionDNA) | user_id, session_count, new_avg, new_end | tier2 | 1.0 | None |
| D-03 | `dna_deviation_scored` | Session DNA | In-memory score accumulator | user_id, session_token, endpoint, deviat | tier3 | 1.0 | None |
| D-04 | `dna_alert_created` | Session DNA | Database (DNAAlert), Discord, Telegram | user_id, session_token, deviation_score, | tier0 | 1.0 | None |
| D-05 | `dna_alert_resolved` | Session DNA | Database (DNAAlert) | alert_id, admin_email | tier3 | 1.0 | None |
| D-06 | `dna_actor_identified` | Session DNA | Database (BehavioralActor), Redis | actor_uuid, session_id, confidence | tier2 | 1.0 | None |
| D-07 | `dna_actor_merged` | Session DNA | Database (MergeLog, BehavioralActor) | source_uuid, target_uuid, confidence, tr | tier2 | 1.0 | None |
| D-08 | `dna_fingerprint_registered` | Session DNA | Redis | hash_type, hash_value, actor_uuid | tier3 | 1.0 | None |

**Category summary:** 8 events cataloged. All payloads defined in event_graph.json.

### 1.12 Gateway (G-01 – G-05)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| G-01 | `gateway.challenge_issued` | Gateway | Client, Redis | nonce, difficulty, timestamp | tier2 | 1.0 | None |
| G-02 | `gateway.challenge_solved` | Gateway | Gateway verify, Redis | nonce, solution | tier2 | 1.0 | None |
| G-03 | `gateway.challenge_failed` | Gateway | Redis | nonce, ip | tier3 | 1.0 | None |
| G-04 | `gateway.ip_blocklisted` | Gateway | Gateway, IP blocklist, Redis | ip, reason, score | tier0 | 1.0 | None |
| G-05 | `gateway.verify_rl_hit` | Gateway | Redis | ip | tier3 | 1.0 | None |

**Category summary:** 5 events cataloged. All payloads defined in event_graph.json.

### 1.16 Hall of Mirrors (M-01 – M-03)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| M-01 | `mirror_layer_created` | Hall of Mirrors | Database (ImmutableLog), Redis | depth, attacker_ip, layer_type | tier2 | 0.95 | None |
| M-02 | `mirror_layer_accessed` | Hall of Mirrors | Database (ImmutableLog) | depth, attacker_ip, layer_type | tier2 | 0.95 | None |
| M-03 | `mirror_deep_penetration` | Hall of Mirrors | Discord | ip, depth, layer | tier0 | 0.95 | None |

**Category summary:** 3 events cataloged. All payloads defined in event_graph.json.

### 1.17 Notification (N-01 – N-02)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| N-01 | `dns_canary_planted` | DNS Canary | Database (ImmutableLog) | hostname, ip | tier1 | 0.98 | no retry on critical tier |
| N-02 | `dns_canary_triggered` | DNS Canary | Database (ImmutableLog), Telegram, Discord | resolver_ip, token_id, country, timestam | tier0 | 0.98 | None |

**Category summary:** 2 events cataloged. All payloads defined in event_graph.json.

### 1.20 Quantum Canary (Q-01 – Q-03)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| Q-01 | `quantum_canary_planted` | Quantum Canary | Database (ImmutableLog) | email, months_back, records_created | tier2 | 0.95 | None |
| Q-02 | `quantum_canary_adapted` | Quantum Canary | Database (ImmutableLog) | user_id, email, changed_fields | tier1 | 0.95 | None |
| Q-03 | `quantum_canary_triggered` | Quantum Canary | Database (CanaryAlert) | canary_id, attacker_ip | tier2 | 0.95 | None |

**Category summary:** 3 events cataloged. All payloads defined in event_graph.json.

### 1.21 Request Middleware (R-01 – R-17)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| R-01 | `xhr_origin_enforced` | Request Middleware | Middleware | method, path, ip | tier2 | 1.0 | None |
| R-02 | `request_size_limited` | Request Middleware | Middleware | ip, size | tier3 | 1.0 | None |
| R-03 | `corpus_fingerprint_collected` | Request Middleware | Redis | fp_hash, ja3, headers, techniques | tier2 | 1.0 | None |
| R-04 | `request_id_assigned` | Request Middleware | Request context | uuid4[:8] | tier3 | 1.0 | None |
| R-05 | `session_activity_updated` | Request Middleware | Database | user_id, session_token, last_activity | tier2 | 1.0 | None |
| R-06 | `session_idle_expired` | Request Middleware | Middleware, Background thread (_finalize_session_dna) | user_id, session_token | tier1 | 1.0 | None |
| R-07 | `honey_token_checked` | Request Middleware | Middleware | ip, path, method, headers | tier2 | 1.0 | None |
| R-08 | `sandbox_diverted` | Request Middleware | Attractor Sandbox, ImmutableLog, Redis (+1) | ip, reason, threat_score | tier2 | 1.0 | None |
| R-09 | `api_key_honey_hit` | Request Middleware | Discord, ImmutableLog, Database | ip, key_prefix, path | tier2 | 1.0 | None |
| R-10 | `reverse_canary_hit` | Request Middleware | Discord, ImmutableLog | ip, token_path, narrative | tier0 | 1.0 | None |
| R-11 | `provenance_violation` | Request Middleware | Database (DataProvenance), ImmutableLog | signature, original_ip, current_ip | tier0 | 1.0 | None |
| R-12 | `ip_blocked_access` | Request Middleware | AuditLog | ip, reason, remaining_ttl | tier3 | 1.0 | None |
| R-13 | `sql_pattern_detected` | Request Middleware | AuditLog | ip, pattern | tier2 | 1.0 | None |
| R-14 | `suspicious_technique_detected` | Request Middleware | Redis, Database, Background thread | ip, technique | tier2 | 1.0 | None |
| R-15 | `security_headers_injected` | Request Middleware | Response headers | csp, hsts, xfo, etc | tier2 | 1.0 | None |
| R-16 | `dna_event_recorded` | Request Middleware | Database (SessionEvent), Background thread | user_id, endpoint, method, status_code,  | tier2 | 1.0 | None |
| R-17 | `dna_deviation_detected` | Request Middleware | Database (DNAAlert), Discord, Telegram | user_id, score, deviations | tier0 | 1.0 | None |

**Category summary:** 17 events cataloged. All payloads defined in event_graph.json.

### 1.22 Sandbox / Attractor (S-01 – S-07)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| S-01 | `sandbox_entered` | Attractor Sandbox | Database (SandboxSession, ImmutableLog), Telegram, Discord (+1) | ip, reason, threat_score, attacker_profi | tier0 | 1.0 | None |
| S-02 | `sandbox_request` | Attractor Sandbox | Database (ImmutableLog), SandboxSession.actions | ip, method, path, exfil_attempts | tier2 | 1.0 | None |
| S-03 | `sandbox_shell_command` | Attractor Sandbox | Database (ImmutableLog) | ip, cmd, exfil_attempts | tier2 | 1.0 | None |
| S-04 | `sandbox_exfil` | Attractor Sandbox | Database (ImmutableLog), Telegram, Discord | ip, path, request_count, milestone | tier0 | 1.0 | None |
| S-05 | `sandbox_predictive_canary_deployed` | Attractor Sandbox | Database (ImmutableLog), Discord | ip, technique, paths | tier1 | 1.0 | None |
| S-06 | `sandbox_released` | Attractor Sandbox | Database (ImmutableLog, SandboxSession) | ip, released_by | tier1 | 1.0 | None |
| S-07 | `sandbox_status_changed` | Attractor Sandbox | Email, Telegram | uid, status, reason | tier3 | 1.0 | None |

**Category summary:** 7 events cataloged. All payloads defined in event_graph.json.

### 1.25 Timing Canaries (T-01 – T-03)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| T-01 | `timing_canary_planted` | Timing Canary | Redis | canary_name, ip, delay_ms, user_agent | tier2 | 0.98 | None |
| T-02 | `timing_canary_hit` | Timing Canary | Database (ImmutableLog), Telegram, Discord | canary_name, ip, actual_delay, count | tier0 | 0.98 | None |
| T-03 | `timing_canary_delay_rotated` | Timing Canary | Database (ImmutableLog) | old_delay_ms, new_delay_ms | tier1 | 0.98 | no retry on critical tier |

**Category summary:** 3 events cataloged. All payloads defined in event_graph.json.

### 1.26 Immutable Log Verifier (V-01 – V-02)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| V-01 | `reverse_canary_planted` | Reverse Canary | Database (ImmutableLog) | type, path, tracking_mechanism | tier2 | 0.95 | None |
| V-02 | `reverse_canary_triggered` | Reverse Canary | Database (ImmutableLog), Discord | ip, token_path, narrative | tier0 | 0.95 | None |

**Category summary:** 2 events cataloged. All payloads defined in event_graph.json.

### 1.27 Cowrie Intelligence (W-01 – W-11)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| W-01 | `cowrie_log_line` | Cowrie Pipeline | Internal event_queue | raw JSON: {event, src_ip, session, times | tier2 | 0.92 | None |
| W-02 | `cowrie_connect` | Cowrie Pipeline | Event workers, Redis, Handlers | session_id, src_ip, ssh_version, kex, ha | tier1 | 0.92 | None |
| W-03 | `cowrie_login` | Cowrie Pipeline | Event workers, Redis, Database | session_id, username, password, success | tier2 | 0.92 | None |
| W-04 | `cowrie_command` | Cowrie Pipeline | Event workers, CRYSTAL triage, Campaign enrichment | session_id, cmd, timestamp | tier2 | 0.92 | None |
| W-05 | `cowrie_download` | Cowrie Pipeline | Event workers, File enrichment, Redis (+1) | session_id, url, shasum, filename | tier1 | 0.92 | None |
| W-06 | `cowrie_session_closed` | Cowrie Pipeline | Event workers, Session finalization | session_id, duration, total_commands, th | tier2 | 0.92 | None |
| W-07 | `cowrie_alert_high_risk_command` | Cowrie Pipeline | alert_queue, Telegram, Discord | session_id, cmd, risk_score, src_ip | tier2 | 0.92 | None |
| W-08 | `cowrie_alert_high_threat_session` | Cowrie Pipeline | alert_queue, Telegram, Discord | session_id, threat_score, total_commands | tier0 | 0.92 | None |
| W-09 | `cowrie_alert_suppressed` | Cowrie Pipeline | alert_queue, Summary log | session_id, reason, window_stats | tier3 | 0.92 | None |
| W-10 | `cowrie_session_enriched` | Cowrie Pipeline | Campaign correlator, ASN engine, Redis (+1) | session_id, asn, geo, bgp_status, campai | tier2 | 0.92 | None |
| W-11 | `cowrie_session_labeled` | Cowrie Pipeline | Redis (cowrie:labeled_sessions) | session_id, label, confidence | tier3 | 0.92 | None |

**Category summary:** 11 events cataloged. All payloads defined in event_graph.json.

### 1.2 ASN Intelligence (AI-01 – AI-05)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| AI-01 | `ip_enrichment_requested` | ASN Intelligence | ThreadPoolExecutor | ip | tier3 | 0.95 | None |
| AI-02 | `ip_enriched` | ASN Intelligence | Redis (ip_enrich:{hash}), ASN analytics | ip, asn, country, isp, risk_score, bgp_s | tier2 | 0.95 | None |
| AI-03 | `asn_daily_recorded` | ASN Intelligence | Redis (asn:daily, leaderboards) | asn, attack_count, country, is_hosting | tier2 | 0.95 | None |
| AI-04 | `asn_abuse_report_sent` | ASN Intelligence | Email (Resend), Database (ImmutableLog) | asn, abuse_email, incident_count, eviden | tier1 | 0.95 | None |
| AI-05 | `asn_high_risk_scored` | ASN Intelligence | Redis (asn:high_risk) | asn, risk_score | tier3 | 0.95 | None |

**Category summary:** 5 events cataloged. All payloads defined in event_graph.json.

### 1.3 AI Runtime Security (AR-01 – AR-08)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| AR-01 | `airs_request_received` | AI Runtime Security | Rate limiter, Redis (airs:rl:{key.id}) | api_key, owner, endpoint, input_length | tier2 | 0.95 | None |
| AR-02 | `airs_detector_pipeline` | AI Runtime Security | Pipeline aggregation | endpoint, verdicts: [injection, jailbrea | tier2 | 0.95 | None |
| AR-03 | `airs_detection_high` | AI Runtime Security | Database (AIRSDetection), Database (ImmutableLog), Telegram (+1) | endpoint, verdict, risk_score, technique | tier2 | 0.95 | None |
| AR-04 | `airs_detection_critical` | AI Runtime Security | Database (AIRSDetection), Database (ImmutableLog), Telegram (+1) | endpoint, verdict, risk_score, technique | tier0 | 0.95 | None |
| AR-05 | `airs_detection_flagged` | AI Runtime Security | Database (AIRSDetection) | endpoint, verdict, risk_score, technique | tier3 | 0.95 | None |
| AR-06 | `airs_actor_tracked` | AI Runtime Security | Database (AIRSActor) | owner, fingerprint, client_ip, detection | tier2 | 0.95 | None |
| AR-07 | `airs_actor_blocked` | AI Runtime Security | Database (AIRSActor) | owner, fingerprint, detection_count, max | tier1 | 0.95 | None |
| AR-08 | `airs_policy_applied` | AI Runtime Security | Response headers, Database | owner, mode (allow/flag/block), block_th | tier3 | 0.95 | None |

**Category summary:** 8 events cataloged. All payloads defined in event_graph.json.

### 1.5 Cowrie Behavioral DNA (BD-01 – BD-05)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| BD-01 | `actor_identified` | Behavioral DNA (Cowrie) | Database (BehavioralActor), Redis | actor_uuid, fingerprint_hash, session_id | tier2 | 0.9 | None |
| BD-02 | `actor_created` | Behavioral DNA (Cowrie) | Database (BehavioralActor) | actor_uuid, fingerprint_hash, src_ip | tier2 | 0.9 | None |
| BD-03 | `actor_confidence_updated` | Behavioral DNA (Cowrie) | Database (BehavioralActor) | actor_uuid, new_confidence, session_coun | tier3 | 0.9 | None |
| BD-04 | `actor_merged` | Behavioral DNA (Cowrie) | Database (MergeLog, BehavioralActor) | source_uuid, target_uuid, confidence, tr | tier2 | 0.9 | None |
| BD-05 | `actor_retired` | Behavioral DNA (Cowrie) | Database (BehavioralActor) | actor_uuid, last_seen | tier1 | 0.9 | no retry on critical tier |

**Category summary:** 5 events cataloged. All payloads defined in event_graph.json.

### 1.6 Breach Monitor (BM-01 – BM-04)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| BM-01 | `breach_scan_cycle_started` | Breach Monitor | Breach monitor internal API | assets_scanned, timestamp | tier3 | 0.95 | None |
| BM-02 | `breach_found` | Breach Monitor | Telegram, Discord, Email (+1) | asset, source (pastebin/github/hibp), se | tier1 | 0.95 | None |
| BM-03 | `github_exposure_found` | Breach Monitor | Database (ImmutableLog), Telegram | query, repo, file, url | tier2 | 0.95 | None |
| BM-04 | `paste_monitor_hit` | Breach Monitor | Telegram | query, source, snippet | tier3 | 0.95 | None |

**Category summary:** 4 events cataloged. All payloads defined in event_graph.json.

### 1.8 Campaign Correlator (CM-01 – CM-04)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| CM-01 | `session_fingerprint_ingested` | Campaign Correlator | Redis (recent_fingerprints), Campaign engine | fingerprint (SimHash, n-gram, tool_set,  | tier2 | 0.9 | None |
| CM-02 | `campaign_cluster_found` | Campaign Correlator | Redis (campaign:{id}, active_campaigns) | campaign_id, similarity_score, matched_d | tier0 | 0.9 | None |
| CM-03 | `new_campaign_detected` | Campaign Correlator | Redis (campaign:{id}, campaigns:active), Telegram | campaign_id, session_ids, ip_set, sensor | tier2 | 0.9 | None |
| CM-04 | `campaign_updated` | Campaign Correlator | Redis (campaign:{id}), Telegram | campaign_id, new_session_count, new_ips, | tier2 | 0.9 | None |

**Category summary:** 4 events cataloged. All payloads defined in event_graph.json.

### 1.9 Credential Propagation (CP-01 – CP-03)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| CP-01 | `lure_credential_planted` | Credential Propagation | Redis | lure_id, platform, url, username | tier2 | 0.9 | None |
| CP-02 | `lure_credential_evicted` | Credential Propagation | Redis | lure_id, platform, age | tier3 | 0.9 | None |
| CP-03 | `lure_credential_triggered` | Credential Propagation | Redis, Telegram | lure_id, matched_username, source_ip, se | tier1 | 0.9 | None |

**Category summary:** 3 events cataloged. All payloads defined in event_graph.json.

### 1.11 Detonation Engine (DP-01 – DP-07)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| DP-01 | `detonate_job_enqueued` | Detonation Pipeline | Redis (detonate:queue) | job_id, url, timestamp | tier2 | 0.95 | None |
| DP-02 | `detonate_job_dequeued` | Detonation Pipeline | Worker loop, Redis (detonate:job:{job_id}) | job_id, url | tier3 | 0.95 | None |
| DP-03 | `detonate_job_started` | Detonation Pipeline | Redis (detonate:job:{job_id}) status update | job_id, container_id | tier3 | 0.95 | None |
| DP-04 | `detonate_url_screenshot` | Detonation Pipeline | Report generator | job_id, screenshot_path | tier2 | 0.95 | None |
| DP-05 | `detonate_url_network` | Detonation Pipeline | Report generator | job_id, requests[], domains[] | tier2 | 0.95 | None |
| DP-06 | `detonate_threat_signals` | Detonation Pipeline | Report generator, _pipeline_detonation_signals | job_id, signals[], risk_score | tier1 | 0.95 | None |
| DP-07 | `detonate_job_completed` | Detonation Pipeline | Redis (detonate:job:{job_id}), detonation:recent, detonation:domain:{hash} | job_id, summary, risk_score, domains, ip | tier1 | 0.95 | None |

**Category summary:** 7 events cataloged. All payloads defined in event_graph.json.

### 1.13 Leader Election (LE-01 – LE-04)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| LE-01 | `leader_elected` | Leader Election | All workers (implicit) | hostname, pid, acquired_at | tier2 | 0.98 | None |
| LE-02 | `leader_heartbeat` | Leader Election | Redis (TTL refresh) | hostname, pid, ttl_remaining | tier3 | 0.98 | None |
| LE-03 | `leader_released` | Leader Election | Standby workers | hostname, pid | tier2 | 0.98 | None |
| LE-04 | `leader_failover` | Leader Election | Standby workers, Redis | old_leader, new_leader | tier0 | 0.98 | None |

**Category summary:** 4 events cataloged. All payloads defined in event_graph.json.

### 1.14 LLM Firewall (LF-01 – LF-09)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| LF-01 | `llmfw_request_received` | LLM Firewall | Rate limiter, Redis (llmfw:rl:{ak}:{hour}) | api_key, model, prompt_length | tier2 | 0.97 | None |
| LF-02 | `llmfw_regex_detection` | LLM Firewall | Pipeline (to LLM check) | api_key, category, technique, risk_score | tier2 | 0.97 | None |
| LF-03 | `llmfw_llm_classification` | LLM Firewall | Pipeline (to heuristic) | api_key, prompt_snippet, verdict, confid | tier2 | 0.97 | None |
| LF-04 | `llmfw_heuristic_fallback` | LLM Firewall | Final verdict | api_key, reason, heuristic_score | tier3 | 0.97 | None |
| LF-05 | `llmfw_allowed` | LLM Firewall | Upstream (pass-through), Redis (llmfw:events:{ak}) | api_key, risk_score, latency_ms | tier2 | 0.97 | None |
| LF-06 | `llmfw_blocked` | LLM Firewall | Redis (llmfw:blocks:{ak}), Telegram, Discord (+2) | api_key, category, technique, risk_score | tier0 | 0.97 | None |
| LF-07 | `llmfw_flagged` | LLM Firewall | Redis (llmfw:events:{ak}) | api_key, category, technique, risk_score | tier2 | 0.97 | None |
| LF-08 | `llmfw_rate_limited` | LLM Firewall | Response (429) | api_key, limit, window | tier3 | 0.97 | None |
| LF-09 | `llmfw_daily_stats_updated` | LLM Firewall | Redis (llmfw:stats:{ak}:{day}) | api_key, requests, blocks, flags, catego | tier3 | 0.97 | None |

**Category summary:** 9 events cataloged. All payloads defined in event_graph.json.

### 1.15 LLM Honeypot (LH-01 – LH-06)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| LH-01 | `llm_honeypot_prompt_received` | LLM Honeypot | LLM injection classifier, Redis (llm_rl:*) | ip, prompt, model, user_agent | tier2 | 0.97 | None |
| LH-02 | `llm_injection_classified` | LLM Honeypot | Database (ImmutableLog), Telegram, Discord | ip, technique, threat_level, confidence, | tier0 | 0.97 | None |
| LH-03 | `llm_honeypot_bait_served` | LLM Honeypot | Redis (llm_honeypot:{ip}:{ts}) | ip, bait_type, response_snippet | tier2 | 0.97 | None |
| LH-04 | `llm_honeypot_sandbox_diverted` | LLM Honeypot | Sandbox system (_bg_enter_sandbox), Redis, Database | ip, reason, technique | tier2 | 0.97 | None |
| LH-05 | `llm_embed_accessed` | LLM Honeypot | Database (ImmutableLog) | ip, text_hash | tier3 | 0.97 | None |
| LH-06 | `llm_honeypot_daily_budget_hit` | LLM Honeypot | Rate limiter (silent) | ip, budget_used | tier3 | 0.97 | None |

**Category summary:** 6 events cataloged. All payloads defined in event_graph.json.

### 1.18 Ops Dashboard (external) (OD-01 – OD-05)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| OD-01 | `ops_cowrie_session_broadcast` | Ops-Dashboard | SSE subscribers | session_id, src_ip, timestamp | tier2 | 0.95 | None |
| OD-02 | `ops_action_executed` | Ops-Dashboard | Redis Stream (ops:actions:log) | action, target, success, output | tier2 | 0.95 | None |
| OD-03 | `ops_incident_triggered` | Ops-Dashboard | Redis Stream (ops:incidents:{rule_id}) | rule_id, severity, condition, context | tier2 | 0.95 | None |
| OD-04 | `ops_alert_acknowledged` | Ops-Dashboard | Redis Hash (ops:alerts:acknowledged) | alert_id, operator | tier2 | 0.95 | None |
| OD-05 | `ops_terminal_audit` | Ops-Dashboard | Redis Stream (ops:terminal:audit) | server_id, host, connected_at, disconnec | tier3 | 0.95 | None |

**Category summary:** 5 events cataloged. All payloads defined in event_graph.json.

### 1.19 Public API (PA-01 – PA-03)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| PA-01 | `public_activity_recorded` | Public API / Stats | Redis (public:activity) | type (ip/domain/hash), target, timestamp | tier2 | 0.98 | None |
| PA-02 | `public_stats_requested` | Public API / Stats | API response | total_threats, sessions, canaries, attac | tier2 | 0.98 | None |
| PA-03 | `public_cowrie_stats` | Public API / Stats | Public API | session_count, recent_sessions | tier3 | 0.98 | None |

**Category summary:** 3 events cataloged. All payloads defined in event_graph.json.

### 1.23 Supply Chain Canary (SC-01 – SC-04)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| SC-01 | `supply_chain_canary_planted` | Supply Chain Canary | Redis | token, version, location | tier2 | 0.95 | None |
| SC-02 | `supply_chain_beacon_fired` | Supply Chain Canary | Database (ImmutableLog), Telegram, Discord | token, version, env_hash, ip, user_agent | tier0 | 0.95 | None |
| SC-03 | `supply_chain_lure_planted` | Supply Chain Canary | Redis | lure_id, platform, url | tier1 | 0.95 | no retry on critical tier |
| SC-04 | `supply_chain_lure_triggered` | Supply Chain Canary | Database (ImmutableLog), Telegram | lure_id, source_ip, matched_credential | tier3 | 0.95 | None |

**Category summary:** 4 events cataloged. All payloads defined in event_graph.json.

### 1.24 Scheduler / Maintenance (SCH-01 – SCH-05)

| Event ID | Name | Producer | Consumers | Payload | Criticality | Confidence | Issues |
|----------|------|----------|-----------|---------|-------------|------------|--------|
| SCH-01 | `model_retrained` | Scheduler / Maintenance | Filesystem (joblib models) | user_count, model_sizes | tier2 | 1.0 | None |
| SCH-02 | `mimicry_cycle` | Scheduler / Maintenance | Database (canary activity audit) | canary_count, actions_simulated | tier2 | 1.0 | None |
| SCH-03 | `daily_digest_sent` | Scheduler / Maintenance | Telegram | canary_triggers, sandbox_sessions, ip_bl | tier2 | 1.0 | None |
| SCH-04 | `canarytoken_poll` | Scheduler / Maintenance | Redis (canarytoken_last_hit:*) | poll_count, new_hits | tier3 | 1.0 | None |
| SCH-05 | `trial_billing_cycle` | Scheduler / Maintenance | Database (CanarySubscription), Email, Telegram | trials_charged, trials_expired, trials_r | tier2 | 1.0 | None |

**Category summary:** 5 events cataloged. All payloads defined in event_graph.json.

---

## 2. Event Storm Patterns (ES-01 – ES-05)

These are **attack pattern composites**, not nodes in event_graph.json.

| Pattern ID | Name | Trigger Chain | Risk |
|------------|------|---------------|------|
| ES-01 | Botnet SSH sweep | W-02 → W-06 | CRITICAL — sync enrichment blocks workers |
| ES-02 | Credential brute-force | A-05 rapid fire | HIGH — DB + rate limiter pressure |
| ES-03 | Web scanner | R-03 → R-14 | MEDIUM — Redis fingerprint writes |
| ES-04 | Blocklist bypass probe | G-03 → G-04 | LOW — gateway rate limits cap |
| ES-05 | Canary token scan | C-08 fan-out | MEDIUM — 6 consumers per hit |

---

## 3. Overall Assessment

| Metric | Value |
|--------|-------|
| Total cataloged events | 173 |
| Payload completeness | 100% |
| JSON ↔ MD sync | 100% (173/173) |

### Key Recommendations

1. Split conflated "Canary / Honey Token" producer into Honeytokens, Canary Service, Supply Chain.
2. Mark Ops-Dashboard (OD-*) events as external or remove from production graph.
3. Add retry to tier1 events with `none` policy.
4. Async Cowrie enrichment chain (W-10 → CM-01, BD-01, AI-01) to address ES-01 bottleneck.
