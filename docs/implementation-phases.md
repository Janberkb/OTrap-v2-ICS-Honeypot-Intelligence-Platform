# OTrap — Implementation Phases

> Tracks remaining features from the approved improvement plan.
> Each phase is self-contained. Proceed to the next only after confirming the current phase.

---

## ✅ Phase 0 — Core Improvements (DONE)
All items from the original analysis plan, completed in the previous session:
- FAZ A–D: Dashboard stats, session table, session detail, attacker profile
- FAZ E–F: IOC page, report export (PDF via @react-pdf/renderer)
- FAZ G–M: Sensor health, alert rules, SIEM, backup, notifications, admin
- Session grouping fix (HTTP/HTTPS: ip:port:protocol)
- Modbus register drift (anti-fingerprint)
- Kill chain banner on session detail
- Critical event browser notification + tab title flash
- IOC extraction: user_agent + domain types
- HMI host header capture
- GitHub cleanup: deleted internal dev docs, created CONTRIBUTING.md, CHANGELOG.md

---

## ✅ Phase 1 — Global Search (DONE)
**Goal:** SOC analyst can search any IP, IOC value, or session ID from the top bar.

- [x] `manager/api/search.py` — `GET /search?q=...` endpoint (sessions + IOCs)
- [x] Registered in `manager/api/routers.py`
- [x] Search bar in `layout.tsx` top bar with debounced dropdown results
  - Sessions → navigate to `/sessions/{id}`
  - IOCs → navigate to `/iocs?search={value}`

---

## ✅ Phase 2 — Executive Summary in PDF Reports (DONE)
**Goal:** PDF reports include a risk score and top findings section at the top.

Tasks:
- [x] Added `calcRiskScore()` (0–10, derived from severity + CPU stops + IOC count + session volume)
- [x] Added `riskLabel()` (color-coded: Critical/High/Medium/Low/Minimal)
- [x] Added `getRecommendations()` (protocol-aware: S7, Modbus, HTTP/HMI, CPU STOP, MITRE)
- [x] Inserted 3-column block in Page 1: Risk Score dial | Top 3 Findings | Recommendations

---

## ✅ Phase 3 — Alert Rule Correlation (Time-Window) (DONE)
**Goal:** Detect reconnaissance patterns automatically (e.g. 10+ S7_READ_VAR in 60s).

Tasks:
- [x] Added `window_seconds` + `threshold` columns to `AlertRule` model
- [x] `ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS` in `engine.py` migration
- [x] Updated `AlertRuleRequest` schema + `_serialize()` + create/update CRUD
- [x] `_check_correlation()` in `rule_engine.py` — Redis INCR with TTL-based window, fires exactly at threshold, resets counter
- [x] `evaluate_rules()` signature updated to accept `redis=` kwarg
- [x] `worker.py` passes `self._redis_broadcast` to `evaluate_rules`
- [x] UI: correlation inputs in modal (threshold + window_seconds), badge in rule card (⏱ N× / Xs), detail in expanded view

---

## ✅ Phase 4 — GreyNoise / AbuseIPDB Integration (DONE)
**Goal:** Enrich attacker profiles with external threat intelligence.

Tasks:
- [x] `GREYNOISE_API_KEY` + `ABUSEIPDB_API_KEY` added to `.env.example`
- [x] `manager/utils/threat_intel.py` created — async httpx lookups, Redis cache 6h TTL
  - `lookup_greynoise()` → seen/noise/riot/classification/name
  - `lookup_abuseipdb()` → abuse_score/total_reports/last_reported/is_whitelisted
  - `lookup_threat_intel()` — runs both concurrently with asyncio.gather
- [x] `attackers.py` calls `lookup_threat_intel` concurrently with GeoIP, adds `threat_intel` to response
- [x] Attacker detail page: "Threat Intelligence" card with GreyNoise badges (RIOT/Malicious/Benign/noise) and AbuseIPDB score bar + report count; shows placeholder when keys not configured

---

## 🔲 Phase 5 — API Key Management
**Goal:** Allow programmatic access (SIEM pull, CI/CD scripts).

Tasks:
- New DB model: `APIKey` (id, name, key_hash, owner_user_id, scopes, created_at, last_used_at)
- `manager/api/admin/api_keys.py` — CRUD endpoints
- Update auth middleware to accept `Bearer <key>` in addition to session cookie
- Admin UI page: `/admin/api-keys` — create, list, revoke

---

## ✅ Phase 6 — EtherNet/IP Protocol Support (DONE)
**Goal:** Cover Allen-Bradley / Rockwell PLCs (~40% of US manufacturing).

Tasks:
- [x] New sensor protocol handler: `sensor/internal/protocols/enip/server.go`
- [x] Listen on TCP 44818; fake CompactLogix L33ER identity
- [x] Parse CIP encapsulation: ListIdentity, ListServices, RegisterSession, SendRRData
- [x] CIP dispatch: ReadTag, WriteTag, GetAttrAll, SetAttrSingle
- [x] `proto/sensor.proto`: `PROTOCOL_ENIP = 6`, event types 50–59
- [x] `sensor/internal/config/config.go`: `ENIPPort = 44818`
- [x] `sensor/cmd/sensor/main.go`: enip server startup
- [x] `manager/analyzer/mitre_ics.py`: 9 ENIP → MITRE ICS mappings
- [x] `manager/analyzer/worker.py`: PROTOCOL_ENIP normalization, `_event_family`, `_infer_attack_phase`, `_classification`, `HIGH_VALUE_EVENT_TYPES`
- [x] `manager/analyzer/ioc_extractor.py`: enip_write_tag / enip_set_attr → `enip_payload` IOC

---

## ✅ Phase 7 — MITRE ATT&CK for ICS Coverage Expansion (DONE)
**Goal:** Expand from 26 mapped techniques to 60+.

Result: **63 technique-event pairs** (48 primary + 15 secondary via `additional_techniques`)

New techniques added:
- T0813 — Denial of View (session timeouts)
- T0814 — Denial of Control (secondary on WRITE/STOP events)
- T0822 — External Remote Services (HMI login success)
- T0830 — Man in the Middle (malformed COTP/TPKT secondary)
- T0834 — Native API (unknown function codes)
- T0839 — Module Firmware (S7 download secondary)
- T0849 — Masquerading (invalid COTP, HMI scanner)
- T0855 — Unauthorized Command Message (Modbus coil write)
- T0858 — Lateral Tool Transfer (CPU start secondary)
- T0879 — Damage to Property (CPU stop, CIP write secondary)
- T0882 — Theft of Operational Information (SZL read secondary)

Tasks:
- [x] Map all previously unmapped event types (S7_CPU_START, S7_UNKNOWN_FUNCTION, S7_SESSION_TIMEOUT, S7_PARTIAL_PACKET, S7_INVALID_COTP_TYPE, MODBUS_READ_DISCRETE, MODBUS_READ_INPUT, MODBUS_WRITE_SINGLE_COIL, MODBUS_UNKNOWN_FUNCTION, MODBUS_EXCEPTION_RESPONSE, MODBUS_SESSION_TIMEOUT, HMI_ACCESS, HMI_SCANNER_DETECTED, ENIP_SESSION_TIMEOUT)
- [x] Added `additional_techniques` to 10 high-value events for secondary technique correlation
- [x] worker.py: merges primary + secondary techniques (deduplicated by technique_id)
- [x] worker.py: expanded `_infer_attack_phase` and `_classification` for all new events
- [x] Session detail MITRE tab: tactic grouping, coverage header (N techniques across M tactics)

---

## Notes
- Phases 2–5 are **short/medium term** (weeks)
- Phases 6–7 are **long term** (months, need protocol expertise)
- Each phase should be tested end-to-end before moving on
