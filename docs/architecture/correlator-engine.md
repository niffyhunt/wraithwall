# Correlator Engine — C++/CUDA Compute Tier for Campaign Correlation

**Status:** Design — awaiting human approval (Phase 0). No scoring logic, kernels, or service code implemented yet.
**Date:** 2026-08-15
**Source of truth:** `campaign_correlator.py` (repo root — imported by `main.py:104` via `from campaign_correlator import campaign_bp, start_campaign_engine`; a vendored mirror exists at `src/wraithwall/campaign_correlator.py` and may drift — see Open Questions).
**Precedent:** `backend-go/` strangler migration — `internal/tenant` (fail-closed tenant scoping), `internal/canaryparity` (transcript parity harness), `README.md` (cutover/rollback discipline).

---

## 1. Executive summary

WraithWall's campaign correlator (`campaign_correlator.py`, 1,412 lines) fingerprints every Cowrie attacker session and computes a weighted, multi-dimensional behavioral similarity between the new session and candidate prior sessions. Today the pairwise scoring is numpy/SciPy in Python, running inside the Flask monolith. This design proposes a **C++17 compute tier with optional CUDA kernels** that takes over only the pairwise similarity computation — the O(N²) core — behind an internal service boundary and a feature flag, following the exact parity discipline already proven by the Go migration (transcript harness, 4-decimal tolerance, fail-closed tenant scoping, explicit cutover, proxy rollback).

**Scope of the compute tier (what moves to C++/CUDA):**

| Component | Python (today) | C++/CUDA engine |
|---|---|---|
| Fingerprint construction (regex normalization, simhash, n-grams, tools, timing, feature vector) | `Fingerprinter` | **stays in Python** (string-heavy, not GPU-shaped; smallest verified surface first) |
| Candidate selection (Redis `LRANGE`, quick filter) | `CampaignCorrelator._find_candidates` / `_quick_filter` | **stays in Python** (Redis-bound) |
| **Pairwise similarity (13 dimensions)** | `SimilarityEngine.compute` | **moves to engine** (the O(N²) core) |
| Identity-graph boost (×1.15), campaign create/update/threat logic | `ingest_session` orchestration | **stays in Python** (graph/DB/Redis-bound) |

The engine is a pure, stateless similarity scorer: it receives explicit fingerprint pairs (or a session-vs-corpus batch) and returns per-dimension scores, the weighted ensemble, confidence, evidence, and `is_match` — byte-compatible with `SimilarityEngine.compute` output.

---

## 2. Source-of-truth inventory (what the Python actually does)

All line numbers refer to the root `campaign_correlator.py` (verified by grep, 2026-08-15).

### 2.1 Configuration (L32–L39)

| Variable | Default | Meaning |
|---|---|---|
| `CAMPAIGN_ALERT_THRESHOLD` | 3 | pattern hits before a new campaign is created |
| `MIN_SIMILARITY_SCORE` | **0.60** | `is_match` weighted-score gate |
| `HIGH_CONFIDENCE_THRESHOLD` | **0.85** | existing-campaign update gate |
| `SESSION_TIMING_WINDOW` | 300 s | pattern-count window |
| `CAMPAIGN_TTL` | 604800 s | campaign key TTL |
| `FINGERPRINT_CACHE_TTL` | 259200 s | fingerprint key TTL |
| `MAX_CANDIDATES` | 50 | candidates per ingest |

> **Note (discrepancy):** the originally proposed weights (SimHash 25%, tool 20%, Jaccard 15%, HASSH 15%, cosine 10%, JA3 10%, credential 8%, timing 7%, geo-velocity 6%, target 5%, payload 4%) **do not match the source**. The code has **13 dimensions** with weights summing to 1.00 (see 2.3), there is **no JA3, geo-velocity, target-selection, or payload-hash dimension**, and the match gate is **0.60** (not 0.70). This doc transcribes the actual code.

### 2.2 Fingerprint model (`BehavioralFingerprint`, L93–121)

Fields (JSON shape from `to_dict`, L118): `fingerprint_id`, `session_id`, `sensor_id`, `timestamp` (ISO-8601), `command_sequence_hash` (16-hex), `command_ngrams` (list of str), `command_entropy`, `command_complexity`, `normalized_commands`, `tool_signatures` ({tool: float}), `tool_sequence_pattern`, `credential_patterns` ([{username, password_complexity, password_length}]), `credential_entropy`, `username_diversity`, `inter_command_timing` (list or `null`), `typing_rhythm_signature` (`'unknown'|'estimated'|16-hex`), `human_confidence` (float or `null`), `session_pacing` (`'unknown'|'estimated'|'burst'|'fast'|'steady'|'slow'`), `src_ip`, `src_port`, `feature_vector` (list of float, **variable length — see 2.3.7**), `anomaly_score`, `tenant_id`.

Key builder behaviors (`Fingerprinter.build`, L128):

- `_normalize_command` (L203): lowercase, strip; regex substitutions in order: `IP_PATTERN`→`IPV4`, `HASH_PATTERN` (32–64 hex)→`HASH`, `URL_PATTERN`→`URL`, `PATH_PATTERN`→`PATH_{depth}`, `PORT_PATTERN`→`:PORT`, `BASE64_PATTERN`→`BASE64_DATA`, then `\b\d+\b`→`N`, whitespace collapse.
- `_simhash(commands, bits=64)` (L216): empty → `'0'*16`. Else per whitespace token: `sha256(token)` hex → first 64 bits → accumulate `+1`/`-1` per bit into a float64 vector; bit = `1` iff `v[i] > 0` (strictly); hex-encode with `zfill(16)`.
- `_generate_ngrams(n=3)` (L231): sliding window joined with `' → '` (spaced arrow). **No cap on count.**
- `_shannon_entropy` (L239): char-frequency entropy over the joined text, `round(..., 4)` (Python banker's rounding).
- `_command_complexity` (L248): per command `min(|*2 + ;*1.5 + &&*2 + $(*3 + \`*3 + (1 if len(split)>8), 20)`, then `np.mean`.
- `_detect_tools` (L259): 14-tool `TOOL_SIGNATURES` (L56) regex corpus (masscan, nmap, zmap, hydra, medusa, ncrack, metasploit, cobalt_strike, mirai, xmrig, gost, chisel, frp, linpeas); score = `round(confidence * matches/len(patterns), 3)`.
- `_analyze_credentials` (L281): **first 20** login attempts → complexity `simple|medium|complex` by length/upper/digit rules.
- `_inter_command_timing` (L305): `None` if <2 commands; real deltas from timestamps (sanity cap 86400 s) when present and length-matching; else single-value `[duration/len(commands)]` **estimate**; else `None`.
- `_typing_signature` (L340): `'unknown'` if no timing; `'estimated'` if single value; else `sha256(np.histogram(timing, bins=[0,0.5,1,2,5,10,30,inf])[0].tobytes()).hexdigest()[:16]` — **numpy histogram semantics and int64 `tobytes` must be replicated exactly.**
- `_human_probability` (L351): `None` if timing absent or single-value; else `min(0.3 + 0.2*(var>2) + 0.2*(any pause>10) + 0.2*(attempts>0) + 0.1*(0<attempts<=5), 0.95)` — **numpy population variance (`ddof=0`).**
- `_session_pacing` (L373): `'unknown'|'estimated'`, then `mean<0.5→burst`, `<2→fast`, `<10→steady`, else `slow`.
- `_build_feature_vector` (L389): **11 dims, no padding** — `[len(commands), complexity, entropy, len(tools), max(tools), mean(tools), len(cred_patterns), mean(timing)|NaN, std(timing)|NaN, duration, cmd_count/duration|NaN]`. NaN appears at dims 7, 8, 10 when timing data is absent.
- `_parse_timestamp` (L412): `fromisoformat` with `Z`→`+00:00`; fallback `utcnow()`.

### 2.3 The 13 similarity dimensions (`SimilarityEngine.WEIGHTS`, L426–440; `compute`, L445)

Exact weights (sum = 1.00):

| # | Dimension | Weight | Formula (source) |
|---|---|---|---|
| 1 | `command_sequence` | **0.15** | SimHash Hamming: `1 - dist/64` over 64-bit binary strings (L447–455). `int(hash,16)` errors → `0.0`. |
| 2 | `ngram_jaccard` | **0.12** | `|A∩B|/|A∪B|` on n-gram sets; `0.0` if union empty (L457–462). |
| 3 | `tool_overlap` | **0.13** | per tool in union: `min(c1,c2)` if both >0 else `max(c1,c2)*0.3`; mean over union (L464–475). |
| 4 | `credential_similarity` | **0.12** | `_credential_sim` (L582): **username counters only** (not passwords); `Σ min / Σ max` over union; `0.0` if both empty. |
| 5 | `behavioral_rhythm` | **0.08** | `_rhythm_sim` (L595): `max(0, 1 - mean(|m1-m2|/max(|m|,1.0)))` over `[mean, std]` of each timing list (**population std**); `0.0` if either empty. |
| 6 | `typing_signature` | **0.04** | `0.0` if either is `'unknown'` **or** `'estimated'`; else `1.0` if equal else `0.0` (L487–494). |
| 7 | `feature_cosine` | **0.08** | `dot/(‖v1‖·‖v2‖)`; `0.0` if norm ≤ 0 (NaN norm → `0.0`). **Mismatched lengths raise (see 2.3.7).** |
| 8 | `operator_consistency` | **0.03** | `1 - |hc1-hc2|` if both non-None, else `0.0` (L506–509). |
| 9 | `pacing_consistency` | **0.02** | `1.0` if equal else **`0.3`** (mismatch is not 0) (L511). |
| 10 | `src_ip_match` | **0.08** | `1.0` iff both non-empty and equal, else `0.0` (L514–516). |
| 11 | `hassh_match` | **0.07** | `getattr(fp,'hassh',None) or ''` — **the dataclass has no `hassh` field; nothing sets it → always `0.0` and always weight-popped** (L519–521). |
| 12 | `timing_proximity` | **0.06** | `1.0` ≤3600 s, `0.7` ≤21600 s, `0.4` ≤86400 s, `0.2` ≤259200 s, else `0.0`; exceptions → `0.0` (L524–533). |
| 13 | `long_horizon_dna` | **0.02** | external `behavioral_dna.get_long_horizon_tracker().find_operator(fp)` — `min(op.confidence,1.0)` if same operator; `0.0` otherwise/on exception (L536–549). |

**Weighted ensemble** (L551–558):

```
active_weights = copy(WEIGHTS)
if not (fp1.src_ip and fp2.src_ip): pop('src_ip_match')
if not (h1 and h2):                  pop('hassh_match')   # always pops today
weight_sum = sum(active_weights.values()) or 1.0          # 0.92 today (0.08+0.07 popped)
weighted   = Σ(score_k · w_k) / weight_sum
confidence = min(count(scores > 0) / len(active_weights), 1.0)   # counts ALL 13 score values
evidence   = [{dimension, score: round(v,4)} for v >= 0.5]
is_match   = (weighted >= MIN_SIMILARITY_SCORE) AND (confidence >= 0.45)
```

Output rounding: `similarity_score` and `confidence` `round(..., 4)`; `dimension_scores` unrounded; `evidence` values rounded to 4.

#### 2.3.7 Feature-vector length edge case (must be pinned)

`_build_feature_vector` always produces **11** dims; but `_deserialize` (L935) defaults a missing `feature_vector` to `[0.0]*64` (legacy). `np.dot(v1, v2)` on mismatched lengths raises `ValueError` **inside `compute` with no try/except** (L497–499) → propagates to `ingest_session`'s catch-all (L868) → `metrics['errors'] += 1`, session silently dropped. This is a real production behavior: **the parity harness must include an 11-vs-64 pair and the C++ engine must replicate the failure (error result), not "fix" it.**

NaN behavior: any NaN in either vector makes `dot` and both norms NaN → `norm > 0` is False → `feature_cosine = 0.0` deterministically.

### 2.4 Ingest orchestration (stays in Python) — L812

1. Reject if no `commands` or invalid strict tenant (L815).
2. Build fingerprint; store to Redis (L897: keys `cowrie_fp:{tenant}:{sid}`, `fingerprint_data:{tenant}:{fid}`, `recent_fingerprints:{tenant}` LRANGE-capped 10,000).
3. Candidates: `LRANGE recent_fingerprints:{tenant} 0 49` → quick filter (L928: skip iff both tool sets non-empty **and** disjoint) → `compute` per candidate → best `is_match` (strict `>` so earliest/latest in list wins ties).
4. Identity-graph boost (L839–856): if both sessions' actors are linked via a `campaign`/`belongs_to` edge → `similarity_score = min(orig * 1.15, 1.0)`, recorded as `graph_boost`. **Not part of `compute`; keep in Python.**
5. `≥ 0.85` → update existing campaign; `≥ 0.60` → maybe create (needs `CAMPAIGN_ALERT_THRESHOLD` pattern hits in `SESSION_TIMING_WINDOW`); else track for future.

### 2.5 Redis key conventions (mirror in engine only where it reads/writes)

`campaign:{tenant}:{cid}`, `active_campaigns:{tenant}` (zset), `campaigns:{tenant}:active` (list, cap 500), `cowrie_fp:{tenant}:{sid}`, `fingerprint_data:{tenant}:{fid}`, `recent_fingerprints:{tenant}`, `deception:correlation:{tenant}:{ip}` (cap 200, TTL 86400), `potential:{tenant}:{simhash[:12]}`, `window:{tenant}:{slot}`. Tenant regex (L652): `^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`; `_strict_tenant_id` never maps to `global`.

---

## 3. Parity spec

### 3.1 Tolerance & measurement

- **Tolerance: 4 decimal places** on every continuous output: each of the 13 `dimension_scores`, `similarity_score`, `confidence`. (Matches Python's own `round(...,4)` contract; float64 compute in both implementations.)
- **Exact match** on: `is_match` (bool), `evidence` (set of `{dimension, rounded score}` — order-insensitive), `typing_signature`/`pacing` string outcomes (these enter scoring only as equality/state, so parity is via the score, not the string), error/failure outcomes (mismatched feature lengths must fail identically).
- **Measurement:** transcript-based harness (canaryparity pattern). Python runner (`scripts/correlator_parity/runner_python.py`) imports the **real** `Fingerprinter`/`SimilarityEngine` with `TESTING=1`, no Redis, stubbed `behavioral_dna` tracker (returns no operator → `long_horizon_dna=0.0`), deterministic aware-UTC timestamps, and writes a JSON transcript of per-pair results. C++ runner computes the same pairs; `compare` reports per-field diffs and exits 1 on any violation. A golden C++ transcript is pinned by a test (drift guard).
- **Corpus:** (a) synthetic edge-case pairs (see 3.2), (b) anonymized real fingerprint pairs exported from `fingerprint_data:{tenant}:*` Redis dumps (IPs hashed, credentials stripped to counts — no raw passwords across the boundary), (c) fuzzed mutations (per-field perturbation) for robustness. Target ≥ 1,000 pairs before Phase 1 is "done".

### 3.2 Edge-case matrix (must match Python exactly)

| Case | Python behavior to replicate |
|---|---|
| Empty command list on both sides | `simhash='0'*16` → Hamming dist 0 → `command_sequence=1.0`; empty n-grams → `ngram_jaccard=0.0`; no tools/creds/timing → 0.0/NaN path; `typing_signature=0.0`; `human_confidence=None` → `operator_consistency=0.0`; pacing `'unknown'` mismatch → `0.3` |
| Single-command session | no n-grams, `inter_command_timing=None` → NaN dims 7/8/10, `typing='unknown'`, `human_confidence=None` |
| Both credential lists empty | `credential_similarity=0.0` |
| Tool overlap one-sided (`c1=0, c2>0`) | `max*0.3` damped term |
| `pacing` mismatch | `0.3` (not 0.0) |
| One `src_ip` empty | weight popped; score `0.0` |
| `hassh` absent both sides | weight popped; score `0.0` (always today) |
| Timing delta exactly 3600 / 21600 / 86400 / 259200 s | ≤ comparisons — boundary goes to the higher tier |
| `timing_proximity` exceptions (naive vs aware datetime) | → `0.0` |
| NaN in either feature vector | `feature_cosine=0.0` (norm NaN → `>0` False) |
| **Legacy 64-dim vs 11-dim feature vectors** | **`ValueError` → compute raises → caller error path (replicate as error result, never "fix")** |
| `typing_signature` single-value (`'estimated'`) | → `0.0` |
| Weighted score exactly 0.60 / 0.85, confidence exactly 0.45 | `>=` comparisons after rounding — boundary counts as match |
| `evidence` threshold | only dims with score ≥ 0.5 (and truthy) |
| Both simhash strings non-hex / empty | `ValueError` → `command_sequence=0.0` |

### 3.3 Numerical-precision notes

- Use **float64** throughout the CPU path (numpy defaults).
- `round()` in Python is banker's rounding (half-to-even) — implement a matching `round4()` (do **not** use `std::round`, which is half-away-from-zero) for: `shannon_entropy`, `tool` scores (`round3`), `similarity_score`, `confidence`, `evidence`.
- `np.var`/`np.std` are **population** (`ddof=0`).
- `np.histogram` with `bins=[0,0.5,1,2,5,10,30,inf]` — right-edge-inclusive binning; counts are int64; `tobytes()` is little-endian platform order (x86-64/ARM64 both little-endian — assert at build).
- `np.linalg.norm` = `sqrt(Σx²)` in float64.
- SimHash accumulation is integer-valued but held in float64 (`np.zeros(bits)`); parity requires exact `>0` comparison, not approximate.

---

## 4. Kernel design (Phase 2 — design only in this phase)

### 4.1 GPU-shaped components

| Component | GPU kernel | Why |
|---|---|---|
| `command_sequence` (SimHash Hamming) | popcount kernel | 64-bit XOR + `__popc` — embarrassingly parallel |
| `feature_cosine` | tiled GEMM-style dot-product | batched dot of 11-dim (pad to 16) vectors |
| `ngram_jaccard` | sorted set-intersection | exact Jaccard needs per-pair merge, not approximate bloom |
| Everything else (1, 4, 5, 6, 8, 9, 10, 11, 12, 13) | **CPU host path** | scalar/string/external lookups — no GPU benefit |

### 4.2 Session-vs-corpus batch layout

- **Input:** `B` new sessions × `C` corpus fingerprints → `B×C` pairs per sweep (a "batch"). Python still selects candidates; the engine computes the full matrix and returns per-pair scores.
- **Packed device layout (SoA):** `simhash: uint64[B×C]` (broadcast A, tile B), `feature: float32[B×C×16]` (padded), `ngram_hash: uint64[B×C×K]` (K = max n-grams, see 4.5), `ngram_len: uint32[B×C]`, plus host-side scalar fields (src_ip hash, hassh hash, pacing enum, epoch seconds, timing stats) in a compact struct.
- **Launch:** grid of `(B/tileB) × (C/tileC)` thread-block tiles; one kernel per sweep. CUDA streams partition the corpus (e.g., 4 streams × 4 chunks) to overlap copy/launch/score; copy-in of packed fingerprints via `cudaMemcpyAsync` on a staging stream.

### 4.3 SimHash Hamming (popcount)

- Thread per pair: `score = 1 - __popc(a[bi] ^ b[bj]) / 64.0`.
- Block tiling: `TILE×TILE` (e.g., 32×32 = 1024 threads) loads `a` and `b` tiles into shared memory (`uint64`), giving coalesced global loads and register-level reuse; write `float` scores to a coalesced row-major output tile.
- Expected: pure compute-bound; ~2 cycles/pair/core. 1.25 B pairs ≈ <10 ms on a T4-class GPU.

### 4.4 Feature cosine (tiled GEMM-style)

- Treat as batched dot products: `A[B×16] × C^T[16×C]` with per-row precomputed norms (host or a tiny reduction kernel). Score = `dot / (normA·normC)`.
- Tiling: 32×32 output tiles, 16-wide K-dim → fits in shared memory with float4 vectorized loads; classic GEMM structure (the K=16 dimension makes this memory-bound — see 4.6).
- NaN policy: replicate Python — if either vector contains NaN, output `0.0` (precompute a NaN flag per vector on host).

### 4.5 N-gram Jaccard (sorted set-intersection)

- Host (Phase 1) pre-processes each session's n-grams into a sorted, deduped `uint64` hash array (FNV-1a 64 of the n-gram string — collision risk addressed in Open Questions; the Python side compares exact strings, so the harness must verify hash-collision parity empirically).
- Kernel: thread per pair runs a two-pointer merge over the two sorted arrays (both resident in shared memory when `K ≤ 64`); count intersection → Jaccard.
- Divergence: variable lengths per pair → expect this to be the slowest kernel; mitigate with length-sorted batching within the sweep.
- **Parity guard:** Python has **no n-gram cap** (2.2). If any session exceeds `K`, the engine must route that pair to the **exact CPU path** (which itself must match Python exactly), never truncate silently.

### 4.6 Complexity & bottleneck analysis

| Scale | Pairs | Notes |
|---|---|---|
| 500 sessions (≈ current daily corpus) | ~125 k pairs | Trivial for CPU; GPU unnecessary — Phase 1 CPU path covers it. |
| 50 k sessions (backfill / scale target) | **1.25 B pairs** | Python numpy: O(minutes–hours) + memory churn; GPU: dominated by **feature-cosine memory traffic** (16 floats × 1.25 B ≈ 80 GB of vector reads before tiling reuse; tiling cuts this ~32×) and **Jaccard divergence**. SimHash popcount is negligible. |

Expected bottleneck order at 50 k: Jaccard kernel (divergence) > cosine memory bandwidth > popcount (compute). Phase 4 must produce `ncu` roofline/occupancy data and a pairs/sec + speedup-vs-numpy report before any cutover discussion.

---

## 5. API contract

### 5.1 Boundary & transport

- **HTTP/JSON** internal service (repo has no gRPC precedent; the Go service uses HTTP/JSON — match it). Listener on `127.0.0.1` (loopback, like Go's default) or a Unix socket; never exposed publicly.
- **Auth:** `X-WraithWall-Internal-Key` (shared secret, constant-time compare, configured `WW_CORRELATOR_INTERNAL_KEY`) + `X-WraithWall-Tenant` (strict-validated, **never** downgrades to `global`). Only `main.py` (or the internal proxy) may call it, after its own session/admin checks — mirroring `backend-go/README.md` §Security boundary.
- `/health` + `/readiness` open for orchestrator probes only; `/readiness` reports dependencies and GPU availability but never changes routing.

### 5.2 Endpoints

**`POST /correlate`** — batch pairwise scoring.

Request:
```json
{
  "pairs": [
    {
      "name": "optional-pair-label",
      "fp_a": { "<BehavioralFingerprint JSON>" },
      "fp_b": { "<BehavioralFingerprint JSON>" }
    }
  ]
}
```
(or `{"sessions": [...], "corpus": [...]}` matrix form for the batch sweep.)

Response:
```json
{
  "ok": true,
  "tenant_id": "acme",
  "results": [
    {
      "name": "optional-pair-label",
      "similarity_score": 0.7234,
      "confidence": 0.6154,
      "dimension_scores": { "command_sequence": 0.8438, "...": 0.0 },
      "evidence": [ { "dimension": "command_sequence", "score": 0.8438 } ],
      "is_match": true,
      "error": null
    }
  ],
  "stats": { "pairs": 128, "engine": "cpu|gpu", "ms": 12.3 }
}
```

Errors: `400` malformed/oversized payload; `401` missing/wrong internal key; `403` invalid tenant (fail closed — no fallback namespace); `413` over resource limits; `503` GPU unavailable **when the flag demands GPU** (see 5.4); per-pair `error` mirrors the Python `ValueError` path for mismatched feature lengths (parity — do not "fix").

### 5.3 Feature flag integration

- `WW_CORRELATOR_ENGINE_ENABLED` (default `false`): when **off**, Python numpy path is untouched (no code path changes, no new dependency).
- When **on**: `main.py` routes similarity compute to the engine for a rollout-scoped slice (by tenant or percentage), keeps `Fingerprinter`/candidate selection/boost/campaign logic in Python.
- GPU mode (`WW_CORRELATOR_ENGINE_DEVICE=gpu|cpu`, default `cpu`): Phase 2+.

### 5.4 Failure semantics (fail closed)

- **GPU unavailable** (no device, driver error, kernel failure) with device=`gpu`: request → `503`, **no scoring fallback to CPU within the request** — silent partial scoring is forbidden (a partially-scored ingest would corrupt campaign state). Operator explicitly flips device=`cpu` (or flag off) to restore service.
- **Partial batch failure:** any pair failure → whole request `500`/`503`, nothing persisted by the caller.
- **Timeout:** per-request deadline (default 10 s, configurable); on expiry → error, never partial results.
- **No silent behavior change:** Python output and engine output must be interchangeable only after the parity harness passes; cutover is a separate operator action.

---

## 6. Security considerations

1. **Tenant isolation:** strict tenant validation on every request (exact `_strict_tenant_id` semantics, L652); tenant comes **only** from the `X-WraithWall-Tenant` header; the engine is stateless (no cross-request cache), so no tenant can observe another's fingerprints; all logs keyed by tenant + fingerprint_id, never raw cross-tenant payloads.
2. **Input validation at the Python→C++ boundary:** max pairs per request (default 10,000, configurable), max sessions per sweep, max commands/ngrams/credential-patterns/timing-values per fingerprint (limits enforced by a per-pair CPU fallback rather than silent truncation — see 4.5), max feature-vector length (accept 11 or 64, mirroring `_deserialize`; anything else → per-pair error), JSON body size cap (e.g., 16 MB), non-finite floats rejected **except** the NaN positions Python itself produces (dims 7/8/10).
3. **Resource exhaustion:** bounded thread pool, bounded request queue with backpressure, per-request deadline, sweep size caps; OOM in host or device → request error, process stays up.
4. **Logging:** never log passwords, usernames, raw credentials, or session command text. Log: tenant, fingerprint_id, pair count, dimension scores, latency, device, error codes. `src_ip` may be logged (attacker metadata, already in campaign alerts) but is scrubbed in the parity corpus.
5. **No secrets in artifacts:** the engine reads config only from env (internal key, limits); nothing written to the repo.

---

## 7. Rollout plan

| Phase | Scope | "Done" criteria | Rollback |
|---|---|---|---|
| **0 (this)** | Design doc + repo scaffold + stub parity harness | Doc traceable to source; scaffold compiles; stub harness loads Python transcript + compares with diff mechanism proven; open questions listed | N/A — no runtime impact |
| **1** | CPU C++ core: fingerprint structs, all 13 dimensions, weighted ensemble, tenant module, round4/numpy-semantics helpers | Parity harness passes on ≥1,000 corpus pairs (4 decimals); golden transcript pinned; `ctest` green; no GPU required | Not wired — nothing to roll back |
| **2** | CUDA kernels (popcount, cosine, Jaccard) + batch sweep + streams | Kernels match CPU C++ ≤ 1e-4 on corpus; benchmark vs numpy published (pairs/sec, speedup); `ncu` profile in docs; CUDA compile-only CI job | Disable device=gpu → cpu |
| **3** | Service: HTTP daemon, internal auth, tenant enforcement, `/health` `/readiness`, flag `WW_CORRELATOR_ENGINE_ENABLED=false` | Flag-gated; readiness reports; parity harness runs over the wire; cutover rehearsal script (mirror `local_cutover_rehearsal.py`) | Set flag off → Python numpy path; Redis remains source of truth |
| **4** | Scale + operator decision: 50 k-session benchmark, production traffic slice, monitoring | Numbers published; operator approves cutover; proxy routing decision documented | Point proxy back to `main.py` (backend-go pattern) |

**Hard rules carried from the Go precedent:** no Python file modified; parity proven before any cutover; Redis shared source of truth; external clients always enter through `main.py`; rollback = flag/proxy change, no data loss.

---

## 8. Open questions & ambiguities (flagged, not assumed)

1. **Stated vs actual weights:** the task brief's weights (SimHash 25%, tool 20%, HASSH 15%, JA3 10%, credential 8%, timing 7%, geo-velocity 6%, target 5%, payload 4%) do **not** exist in source. Resolved to the actual 13-dimension table (2.3). Confirm the intended behavior is parity with **source**, not the brief.
2. **No JA3/geo-velocity/target/payload dimensions exist.** If those are desired features, they are new product work, not a port — out of scope until confirmed.
3. **`hassh_match` is dead code** (dataclass has no `hassh` field; always 0.0, weight always popped). Parity means replicating that. Should `Fingerprinter` start populating `hassh` (from Cowrie SSH client fingerprint data)? That changes scoring — separate decision.
4. **Legacy 64-dim feature vectors crash Python `compute`** (uncaught `ValueError` → session silently dropped, `metrics['errors']+=1`). Engine must replicate the failure for parity. Confirm: keep replicating, or fix Python first (then both sides change together)?
5. **`long_horizon_dna`** depends on the `behavioral_dna` tracker (in-process singleton). Parity harness stubs it as "no operator". Confirm the engine boundary excludes it (recommended) so the engine stays deterministic.
6. **N-gram count is unbounded in Python**; GPU needs a fixed `K`. Plan: exact CPU fallback for oversized pairs. Confirm acceptable.
7. **n-gram hashing for the GPU path** (string → uint64) risks collisions; Python compares exact strings. Harness must empirically validate zero collisions on the corpus before GPU parity is claimed.
8. **Two source copies exist:** root `campaign_correlator.py` (imported by `main.py`) vs `src/wraithwall/campaign_correlator.py` mirror — they differ (`_strict_tenant_id` placement, timing-signature defaults). This doc cites the root. Confirm the deployed artifact is the root copy.
9. **Banker's rounding:** Python `round()` is half-to-even; C++ needs a matching implementation (std::round is not it). Confirmed approach in 3.3.
10. **`is_match` gate is 0.60/0.45**, and campaign-update gate 0.85 — not 0.7/0.85. Confirm thresholds are env-configurable parity inputs (they already are via env in Python).
11. **Transport choice:** HTTP/JSON chosen to match the Go service; if gRPC is preferred for the batch matrix form, say so before Phase 3.

---

## 9. Phase 0 definition of done (this phase)

- [x] `docs/architecture/correlator-engine.md` exists; every formula/behavior claim traceable to `campaign_correlator.py` (line citations above)
- [x] `correlator-engine/` scaffold: CMake (CPU-only default, CUDA gated), dirs for kernels/host/tests, stub parity harness (loads Python reference transcript, compares placeholder output, reports diffs)
- [x] Stub harness runs end-to-end on stub data (diff mechanism proven)
- [x] CI skeleton added matching the existing `.github/workflows/ci.yml` pattern
- [ ] Open questions above answered before Phase 1 begins

**Next step:** await explicit approval, then Phase 1 (CPU core + real parity harness). No scoring logic, kernels, or service code is implemented in this phase.
