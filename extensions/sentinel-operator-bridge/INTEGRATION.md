# Sentinel Operator Bridge — Engine Integration

This document describes how the **MasterAuthenticationEngine** and
**ThreatDetectionEngine** (the behavioral authentication and threat-analysis
engines delivered during the Sentinel Bridge design phase) integrate with the
Sentinel Operator Bridge extension, and how the combined architecture maps onto
an AI active browser extension / proactive security layer.

It is the technical companion to [README.md](README.md) and
[OVERVIEW.md](OVERVIEW.md).

## Why These Engines Exist (Design Context)

Long-running agentic browser sessions — e.g., a sidebar agent running for days
inside a Docker-hosted browser, or an upgraded chatbot prototype whose upstream
model keeps simplifying its behavior — drift. Drift shows up as:

- Changed **typing cadence** (response time, edits, hesitation).
- Changed **vocabulary fingerprint** / syntax patterns.
- Changed **voice signature** (if voice is used).
- Changed threat-relevant content over time.

A **static** security posture cannot absorb that drift. The two engines were
designed to make authentication and threat assessment **continuous** rather than
one-shot.

## Integration Architecture

```
                    ┌─────────────────────────────────────────────┐
                    │             Sentinel Operator Bridge         │
                    │                                             │
  Operator /       │  ┌──────────────────────────────────────┐   │
  Agent input      │  │  MasterAuthenticationEngine         │   │
  (sidebar)        │  │  - behavioral factors              │   │
  ────────────────▶│  │  - confidence >= 70 gate          │   │──▶ Agent action
  Message +        │  │  - 300s session timeout           │   │    (allow/deny)
  response_time    │  │  - continuous_reauth()            │   │
  ────────────────▶│  └──────────────────────────────────────┘   │
                    │                                             │
  Page / Agent     │  ┌──────────────────────────────────────┐   │
  content          │  │  ThreatDetectionEngine              │   │
  (untrusted)      │  │  - jailbreak / social-eng /        │   │
  ────────────────▶│  │    info-harvesting indicators      │   │──▶ Sanitized content
  message          │  │  - threat_score 0..100 + decay     │   │    + verdict (SAFE/UNSAFE)
                    │  └──────────────────────────────────────┘   │
                    └─────────────────────────────────────────────┘
```

### Data Flow (defensive posture)

```
User/agent message + response timing
        │
        ▼
ThreatDetectionEngine.analyze_message()
        │  → threat_score, indicators, severity-weighted, time-decayed (5-min half-life)
        ▼
   ┌────┴────┐
   │         │
 high      │  low
 threat    │  threat
 (≥ θ)      │  (< θ)
   │         │
 hard block / flag / alert      continue →
   │                           MasterAuthenticationEngine.authenticate(...)
   │                           → continuous_reauth() → action
   ▼
Hard enforcement / audit / operator notification
```

## Layer Mapping

| Concern | Engine | Sentinel Bridge component | Enforcement point |
|---|---|---|---|
| Injection / jailbreak detection | `ThreatDetectionEngine` | `src/lib/patterns.js` + `src/lib/sanitize_content.js` | Pre-LLM filter: sanitize → wrap in `⟦UNTRUSTED-INSTRUCTION⟧…⟦/UNTRUSTED-INSTRUCTION⟧` / refuse |
| Behavioral session auth | `MasterAuthenticationEngine` | Operator panel / agent session store | Gate agent actions on `authenticated` + confidence ≥ 70 |
| Session liveness | `MasterAuthenticationEngine` | Capture state (`start_capture` / `stop_capture`) | `auth_timeout` (300s) + `continuous_reauth()` |
| Threat bookkeeping | `ThreatDetectionEngine` | Findings store | Cumulative `threat_score`, decay, `get_threat_report`, `reset` |

## Operating Modes

### 1. Defensive Layer (default)

- Run `ThreatDetectionEngine.analyze_message()` on every inbound agent/page
  message **before** it reaches the LLM reasoning context.
- Use the sanitizer verdict (`SAFE` / `UNSAFE`) as the primary gate.
- High-threat signals produce flags/alerts; content is wrapped or blocked.

### 2. Aggressive Defense Layer ("Angry Dog" posture)

- Hard lockout when:
  - `ThreatDetectionEngine` cumulative `threat_score` crosses the configured
    cutoff, **or**
  - `MasterAuthenticationEngine` returns `authenticated: false` or confidence
    < threshold (70).
- On lockout: context wipe, re-arm `auth_timeout`, operator/Master reset.
- Escalation from flag → block; disable after human/Master review via
  `ThreatDetectionEngine.reset()`.

### 3. Proactive Security Layer

- Continuous re-authentication (`continuous_reauth()`) for long-running agent
  sessions.
- Time-decayed threat scoring so stale threats expire while fresh ones dominate.

## Required Engine Hardening Before In-Browser Use

The pasted engine code is valid as a design/specification and can be used, but
the following gaps must be closed before it is production-grade as an in-browser
extension layer:

1. **Missing imports** — `statistics` (used by `continuous_reauth` /
   `get_auth_report`) and `hashlib` (used by `_hash_signature`) must be imported.
2. **Scoring normalization** — weighted factors (cadence 0.2, vocab 0.3, syntax
   0.3, voice 0.2) must be renormalized when factors are absent before the
   ≥ 70 confidence threshold math.
3. **Detection robustness** — regex/jailbreak heuristics and timing heuristics
   can be evaded (slang, multilingual, adversarial encodings); vocabulary
   fingerprints are brittle by design and should be treated as signals, not
   ground truth.
4. **Enforcement seam** — engines emit signals; the browser/agent runtime must
   consume them (block/allow, session store, UI/audit).

## Recommended Integration Sketch with the Bridge

```
content_script (data-only) ──▶ service_worker (sanitize + threat gate)
                                    │
                                    ▼
                          panel (operator) / agent runtime
                                    │
                                    ▼
                    MasterAuthenticationEngine (session gate)
                    ThreatDetectionEngine (pre-LLM filter)
                    ──▶ agent action (allow) or hard lockout (deny)
```

- Page content: sanitized by the Bridge (`sanitizeContent`) and simultaneously
  screened by the `ThreatDetectionEngine`; injection spans are wrapped with
  `⟦UNTRUSTED-INSTRUCTION⟧…⟦/UNTRUSTED-INSTRUCTION⟧` (Bridge) and scored by the
  engine (defense-in-depth).
- Operator directives: pass through the Bridge paste-fencing/sanitization and
  require a valid authenticated session (`MasterAuthenticationEngine`).
- Captures: only accumulate content that passed sanitization + threat gating.

## Next Steps

- Close engine code gaps (imports, normalization, robustness).
- Add engine verdicts to the extension audit/state surfaces.
- Extend the operator panel with threat/auth status reporting.
- Re-run the full test suite after integration changes.
