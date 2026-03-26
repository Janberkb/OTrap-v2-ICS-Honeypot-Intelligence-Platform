# Changelog

All notable changes to OTrap are documented here.

---

## v2.0.0 (2026-03-26)

Initial public release of OTrap v2.0.

### Sensor

- **S7comm honeypot** — full TPKT/COTP/S7 state machine; stateful DB memory map; CPU STOP detection; block download/upload; SZL reads (device identification); SEVERITY_CRITICAL event on CPU STOP
- **Modbus/TCP honeypot** — 8 function codes (FC 0x01–0x10); MEI device identification (FC 0x2B); plausible register values; scanner detection
- **HMI HTTP/HTTPS honeypot** — OWASP classifier (SQLi, XSS, command injection, path traversal, sensitive paths, scanners); brute-force rabbit hole (deceptive login after threshold); fake SCADA dashboard; self-signed TLS cert auto-generation
- Outbound-only gRPC mTLS sensor mesh — sensor never opens an inbound management port
- Single-use join token → Manager-issued CA-signed mTLS cert → AES-256-GCM disk storage
- Graceful shutdown; exponential-backoff reconnect; health checker

### Manager (Backend)

- FastAPI async backend; PostgreSQL (asyncpg); Redis pub/sub event pipeline
- Analyzer worker: session grouping, severity escalation, MITRE ATT&CK for ICS mapping (26 techniques), IOC extraction (7 types)
- GeoIP enrichment: MaxMind GeoLite2-City + ASN + Country with Redis cache
- Session triage workflow: `new / investigating / reviewed / false_positive / escalated`
- Bulk triage API
- Alert rule engine: condition matching (eq/neq/gte/lte/in/not_in/contains), SMTP/SIEM/auto-triage actions, Redis cooldown
- SMTP notifications: AES-256-GCM encrypted credentials, delivery log
- SIEM integration: Splunk HEC, Syslog/CEF, generic webhook
- STIX 2.1 and JSON export
- IOC global view with confidence scoring and session cross-reference
- Attacker intelligence: per-IP profile aggregation
- Reports: snapshot-based PDF generation via `@react-pdf/renderer`
- Sensor management: join token generation, rename, protocol configuration, heartbeat monitor
- CSRF protection (double-submit cookie); login rate limiting; CSP nonce-based headers
- Idempotent database migrations
- Admin: user management, audit log, alert rules, integrations

### UI

- Next.js 14 management console; dark theme
- Dashboard: 7 KPIs with 24h/7d/30d time range; live event feed (WebSocket/SSE); protocol distribution chart; event histogram; top attacker countries; trend comparison
- Sessions: sortable table with 9 filters; bulk triage; CSV/JSON/STIX export; kill-chain phase display
- Session detail: interactive event timeline; IOC tab; artifacts (hex); MITRE ATT&CK techniques; triage panel; related sessions
- Attackers: top-50 index with time range toggle; per-IP profile (severity distribution, protocol breakdown, session history, IOC list)
- IOC Intelligence: global view with confidence slider and STIX 2.1 export
- Reports: generate/save/view/delete with PDF download; history list with bulk delete
- Sensors: onboarding (join token + Docker deploy command); rename; protocol config; linked sessions
- Notification bell: real-time critical event counter
- Admin: user CRUD with reauth gate; alert rules builder; integrations (SMTP + SIEM); audit log with filters + CSV export; system info
