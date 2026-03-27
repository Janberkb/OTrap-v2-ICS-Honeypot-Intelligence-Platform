# OTrap — ICS/OT Honeypot Intelligence Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22-00ADD8?logo=go)](sensor/)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python)](manager/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6?logo=typescript)](ui/)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker)](docker-compose.yml)

OTrap is a distributed ICS/OT honeypot platform that deploys stateful protocol emulators (Siemens S7-300/400, Modbus/TCP, EtherNet/IP, HMI) to detect and profile adversarial activity in industrial networks. A gRPC-based sensor mesh reports to a central FastAPI manager with a Next.js SOC console.

![OTrap Dashboard](docs/screenshots/02-dashboard.png)

---

## ✨ Features

**Honeypot Protocols**
- **Siemens S7comm** — stateful PLC emulation with persistent memory map (CPU STOP, DB read/write, system status)
- **Modbus/TCP** — common read/write function codes plus MEI device identification responses
- **EtherNet/IP** — encapsulation commands, CIP identity, and explicit messaging probes
- **HMI HTTP/HTTPS** — realistic login portal with OWASP probe detection and brute-force logging

**Detection & Intelligence**
- MITRE ATT&CK for ICS tactic/technique mapping per session
- IOC extraction: source IPs, usernames, passwords, S7/EtherNet/IP payloads, SQL injection payloads, path traversal probes, URL paths, HTTP User-Agent strings, Modbus function codes and write values, C2 domains
- GeoIP enrichment with country, city, and ASN/ISP data (offline, MaxMind GeoLite2)
- Threat intelligence integration (GreyNoise, AbuseIPDB)
- Kill chain phase detection: Initial Access → Discovery → Collection → Execution → Persistence → Lateral Movement → C2 → Impair Process Control → Inhibit Response Function → Impact
- STIX 2.1 export per session and per attacker

**Attacker Profiles**
- Per-IP aggregated view: GeoIP location, ASN, GreyNoise/AbuseIPDB reputation
- Full session history for the IP with MITRE techniques observed across all sessions
- Complete IOC inventory attributed to that attacker
- Consolidated kill chain view across all observed interactions

**Sensor Mesh**
- Go binary sensor with gRPC + mTLS communication
- Sensors dial out to manager — no inbound management-plane ports required on the sensor host
- Per-sensor dynamic certificate issuance via internal CA
- Single-use join tokens with configurable TTL
- Real-time CPU, memory, and event buffer telemetry

**SOC Management Console**
- Live event feed with Server-Sent Events streaming
- Sessions, attacker profiles, IOC inventory, sensor health
- AI-powered session analysis and triage assist (Ollama / LM Studio)
- PDF report generation
- Multi-operator RBAC with full audit log

**Integrations**
- SMTP alert emails with severity filtering and cooldown
- SIEM forwarding: Splunk HEC, Generic Webhook, Syslog/CEF
- Local LLM backends: Ollama and LM Studio

---

## 📸 Screenshots

| | |
|:---:|:---:|
| ![Login](docs/screenshots/01-login.png) | ![Sessions](docs/screenshots/03-sessions.png) |
| *Login* | *Sessions* |
| ![Session Detail](docs/screenshots/04-session-detail.png) | ![Attacker Profile](docs/screenshots/05-attacker-profile.png) |
| *Session Detail & Kill Chain* | *Attacker Profile* |
| ![IOCs](docs/screenshots/06-iocs.png) | ![Sensors](docs/screenshots/07-sensors.png) |
| *IOC Inventory* | *Sensor Health* |
| ![Reports](docs/screenshots/08-reports.png) | ![LLM Config](docs/screenshots/09-admin-llm.png) |
| *PDF Report Generation* | *Local LLM Configuration* |

---

## 🏗️ Architecture

```
OT Network                           Management Network
────────────────────                 ──────────────────────────────────────
OTrap Sensor (Go)   ──gRPC/mTLS──▶  OTrap Manager (FastAPI)
  :102   S7comm                        :8080  REST API + SSE
  :502   Modbus/TCP                    :9443  gRPC (sensor mesh)
  :44818 EtherNet/IP                 PostgreSQL 16    (sessions, IOCs, audit)
  :80    HMI HTTP                    Redis 7          (pub/sub, caching, health)
  :443   HMI HTTPS                   Next.js UI :3000 (SOC console)
                                     Optional local LLM backend
                                       (Ollama / LM Studio over HTTP)
```

**Key design decisions:**
- Sensors initiate all management-plane connections outbound; only the OT-facing protocol ports need inbound reachability
- Per-sensor mTLS certificates issued at join time; CA private key never leaves the manager
- Stateful S7 memory map: attacker writes are readable back, producing convincing PLC behavior
- CPU STOP returns a plausible ACK (never RST) to preserve the deception

---

## 🚀 Quick Start

```bash
git clone https://github.com/Janberkb/OTrap-v2-ICS-Honeypot-Intelligence-Platform.git otrap
cd otrap
cp .env.example .env
./scripts/install_manager.sh
```

The installer generates all secrets, starts the management stack (`postgres`, `redis`, `manager`, `ui`), and prints the admin credentials. Open the management UI (`http://localhost:3000` on a local install), then create sensors from **Sensors → Add Sensor**. The detailed flow below covers same-host installs, remote sensor hosts, and optional private-registry deployments.

---

## 📦 Installation

### Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Docker Engine | 24+ | `docker --version` |
| Docker Compose | v2 | `docker compose version` (note: no dash) |
| Git | Any | For cloning |
| Python 3 | 3.8+ | Used by the manager installer and helper scripts |

**Ports that must be free on the management server:** `3000` (UI), `8080` (API), `9443` (gRPC)

**Ports that must be free on the sensor host:** `102` (S7comm), `502` (Modbus), `80` (HMI HTTP), `443` (HMI HTTPS), and `44818` if you plan to expose EtherNet/IP externally

---

#### Installing Docker

<details>
<summary><b>Ubuntu / Debian</b></summary>

```bash
# Remove old versions
sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Install prerequisites
sudo apt update
sudo apt install -y ca-certificates curl gnupg

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
  sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add the repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine + Compose plugin
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Add your user to the docker group (log out and back in after this)
sudo usermod -aG docker $USER
```

</details>

<details>
<summary><b>macOS</b></summary>

Install [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/).

Docker Desktop includes both the engine and the Compose plugin. After installation, ensure `docker compose version` works in your terminal.

</details>

<details>
<summary><b>Windows (WSL2)</b></summary>

1. Install [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/) with WSL2 backend enabled.
2. In Docker Desktop → Settings → Resources → WSL Integration: enable your WSL2 distro.
3. Open a WSL2 terminal (Ubuntu recommended) and verify:
   ```bash
   docker compose version
   ```
4. Continue with the Linux instructions inside WSL2.

</details>

---

### Recommended Installation Flow

This expands the Quick Start above. If you already ran those commands, you can continue from **Step 2**.

This single flow covers:

- Manager + sensor on the same machine
- One manager with one or many remote sensor hosts

Use `./scripts/install_manager.sh` as the canonical install command. `make install-manager` only wraps the same script, so the README uses the script directly and avoids requiring `make`.

**Step 1 — Prepare `.env` and install the manager**

```bash
git clone https://github.com/Janberkb/OTrap-v2-ICS-Honeypot-Intelligence-Platform.git otrap
cd otrap
cp .env.example .env
# Optional: edit .env first if you want to set your own admin password
./scripts/install_manager.sh
```

For a quick start you can leave all `CHANGE_ME` values as-is because the installer auto-generates strong secrets. If you want to set your own admin password before installing, edit `.env` and set:

```dotenv
INITIAL_ADMIN_PASSWORD=YourStrongPasswordHere
```

The installer:
1. Verifies Docker + Compose are available
2. Generates all missing secrets in `.env`
3. Checks that ports 3000, 8080, 9443 are free
4. Starts `postgres`, `redis`, `manager`, and `ui`
5. Waits up to 3 minutes for the manager to become healthy
6. Extracts and persists the gRPC CA (`GRPC_CA_KEY_B64`, `GRPC_CA_CERT_B64`) into `.env`
7. Prints admin credentials and the management URL

At the end you will see:
```
✓ Manager install complete
  Management UI:  http://localhost:3000
  Manager API:    http://localhost:8080/api/v1
  Admin user:     admin
  Admin password: <generated>
```

**Step 2 — Verify the manager address used in sensor onboarding**

Fresh installs usually auto-fill these values for you. Before generating sensor commands, verify that the address in `.env` matches how sensor hosts will actually reach the manager.

- If the sensor will run on the same machine as the manager, the auto-detected value is usually fine.
- If sensors will run on other hosts, `SENSOR_PUBLIC_MANAGER_ADDR` must be a real IP or DNS name reachable from those hosts.
- Override these values only if the auto-detected address is wrong, the host IP changed, or the manager sits behind NAT / non-default routing.

Example for a manager reachable at `192.168.1.10`:

```dotenv
GRPC_HOST=0.0.0.0
SENSOR_PUBLIC_MANAGER_ADDR=192.168.1.10:9443
```

Then restart the manager:

```bash
docker compose up -d manager
```

The UI warns you if `SENSOR_PUBLIC_MANAGER_ADDR` still points to loopback or an unusable wildcard host.

**Step 3 — Log into the UI and create sensors**

1. Open the management UI (`http://localhost:3000` on a local install) and log in as the superadmin.
2. Go to **Sensors → Add Sensor**.
3. Enter a sensor name such as `local-sensor`, `ot-segment-a`, or `ot-segment-b`.
4. Click **Generate**.
5. Copy one of the generated onboarding commands and run it in a terminal on the target host.

The UI generates:

- **Install Command** — recommended for most deployments; downloads a generated installer from the manager, clones the repo on the target host, builds the sensor image locally, and starts the container
- **Docker run** — advanced path for operators who publish their own sensor image
- **`.env.sensor` + Compose** — advanced path using `docker-compose.sensor.yml` and your own sensor image

This is the recommended sensor onboarding flow for both a single local sensor and multiple remote sensors. Repeat the same UI flow for every additional host.

**Step 4 — Verify the sensor**

The sensor should appear as **active** on the Sensors page within seconds. On the target host you can also check:

```bash
docker logs <sensor-container-name>
```

Expected output includes a successful join message.

**Optional — Pre-built image workflow for many hosts**

Use this only if you manage your own registry. The default `ghcr.io/otrap/sensor:latest` value is a placeholder and is not published publicly.

If you do not want each target host to clone the repo and build locally, build and push the sensor image once:

```bash
# Single-arch (amd64)
docker build -t your-registry/otrap-sensor:latest ./sensor
docker push your-registry/otrap-sensor:latest

# Multi-arch (amd64 + arm64)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t your-registry/otrap-sensor:latest \
  --push ./sensor
```

Update `.env` on the manager:

```dotenv
SENSOR_IMAGE_REF=your-registry/otrap-sensor:latest
```

Restart the manager so newly generated onboarding commands use the updated image:

```bash
docker compose up -d manager
```

Then return to **Sensors → Add Sensor**, generate a new onboarding payload, and use the generated **Docker run** or **`.env.sensor` + Compose** output on each target host.

> `SENSOR_INSECURE_JOIN=true` skips TLS verification for the initial join only. After a successful join the sensor stores a signed mTLS certificate; all subsequent connections are fully verified.

> The generated `docker run` flow publishes `102/502/80/443` by default. If you also want the EtherNet/IP decoy reachable from outside the container, add `-p 44818:44818`.

> `docker-compose.sensor.yml` uses `network_mode: host`, so all sensor listeners, including EtherNet/IP on `44818`, bind directly on the host.

---

## ⚙️ Configuration Reference

All configuration is managed via environment variables in `.env`. The installer generates secure values for all required secrets automatically.

### Database

| Variable | Default | Description |
|---|---|---|
| `POSTGRES_DB` | `otrap` | Database name |
| `POSTGRES_USER` | `otrap` | Database user |
| `POSTGRES_PASSWORD` | — | **Required.** Strong password |

### Security

| Variable | Description |
|---|---|
| `API_SECRET_KEY` | 64-char hex for session cookie signing. Auto-generated. |
| `ENCRYPTION_KEY` | 32-char key for AES-256-GCM encryption of SMTP/SIEM tokens at rest. Auto-generated. |
| `SESSION_SECURE` | `false` for HTTP, `true` when behind HTTPS |
| `INITIAL_ADMIN_PASSWORD` | First superadmin password. Auto-generated if left as placeholder. |

### gRPC / Sensor Mesh

| Variable | Description |
|---|---|
| `GRPC_HOST` | IP to bind the gRPC port. Leave empty for auto-detect. |
| `GRPC_CA_KEY_B64` | Base64-encoded CA private key. Auto-generated and persisted by installer. |
| `GRPC_CA_CERT_B64` | Base64-encoded CA certificate. Auto-generated. |
| `JOIN_TOKEN_TTL_HOURS` | Join token validity period. Default: `24` |
| `SENSOR_PUBLIC_MANAGER_ADDR` | `host:port` embedded in generated sensor commands. |
| `INSTALLER_BASE_URL_OVERRIDE` | Optional HTTP base URL used only in generated `curl | bash` installer commands. |
| `SENSOR_IMAGE_REF` | Docker image used in pre-built-image onboarding commands. The default `ghcr.io/otrap/sensor:latest` is a placeholder; build and push your own image first. |
| `SENSOR_CERT_ENC_KEY` | 64-char hex for encrypting sensor certs at rest. Auto-generated. |
| `SENSOR_INSECURE_JOIN` | `true` for initial join. Set `false` after all sensors have joined. |

### Networking

| Variable | Default | Description |
|---|---|---|
| `MANAGEMENT_HOST` | `0.0.0.0` | API bind address |
| `UI_HOST` | `0.0.0.0` | UI bind address |
| `CORS_ORIGINS` | `http://localhost:3000` | Comma-separated allowed origins |
| `NEXT_PUBLIC_API_URL` | `http://localhost:8080` | Browser-facing API URL |

### Optional Integrations

| Variable | Description |
|---|---|
| `GREYNOISE_API_KEY` | GreyNoise Community API key. Free tier: 1,000 checks/day. |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key. Free tier: 1,000 checks/day. |
| `LLM_ENABLED` | `true` to enable AI analysis features |
| `LLM_BACKEND` | `ollama` or `lmstudio` |
| `OLLAMA_BASE_URL` | Ollama endpoint. Use LAN IP for Docker deployments. |
| `LM_STUDIO_BASE_URL` | LM Studio endpoint (OpenAI-compatible API) |
| `LLM_DEFAULT_MODEL` | Default model pre-selected in the UI (e.g. `llama3.1:8b`) |

---

## 🔌 Integrations

### GeoIP Enrichment (MaxMind GeoLite2)

OTrap resolves attacker IPs to country, city, and ASN/ISP data using MaxMind's free GeoLite2 databases. All lookups are done offline — no external API calls, fully air-gap compatible. Results are cached in Redis for 24 hours.

**Step 1 — Register for a free MaxMind account**

Go to [maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup), create a free account, and generate a license key from your account dashboard.

**Step 2 — Add your license key to `.env`**

```dotenv
MAXMIND_LICENSE_KEY=your_license_key_here
```

**Step 3 — Download the databases**

```bash
source .env && ./scripts/download_geoip.sh
```

This downloads three files to `manager/data/`:

| File | Used for |
|---|---|
| `GeoLite2-City.mmdb` | Country and city resolution |
| `GeoLite2-ASN.mmdb` | ASN number and ISP/org name |
| `GeoLite2-Country.mmdb` | Lightweight country-only fallback |

**Step 4 — Restart the manager**

```bash
docker compose restart manager
```

GeoIP data appears immediately in attacker profiles, session detail views, the live event feed, and PDF reports. Private-range IPs (RFC1918, loopback) always resolve to "Private Network" regardless of database availability.

> **Without databases:** OTrap works normally but attacker IPs will show no geographic data. You can add databases at any time without losing existing event data.

> **License note:** GeoLite2 databases are subject to [MaxMind's EULA](https://www.maxmind.com/en/geolite2/eula) and are excluded from this repository (`.gitignore`). Do not redistribute the `.mmdb` files.

---

### Threat Intelligence (GreyNoise, AbuseIPDB)

Set API keys in `.env` and restart the manager. Enrichment happens automatically on every new source IP — no UI action needed. Free tiers are sufficient for most honeypot deployments.

```dotenv
GREYNOISE_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
```

### Email Alerts (SMTP)

Configure in **Admin → Notifications**:

- SMTP host, port, TLS mode, From/To addresses
- Minimum severity threshold (low / medium / high / critical)
- Rule actions in **Alert Rules** can force SMTP delivery or auto-triage matching sessions

Use [Mailhog](https://github.com/mailhog/MailHog) for local testing:

```bash
docker run -d -p 1025:1025 -p 8025:8025 mailhog/mailhog
# Set SMTP host=localhost, port=1025, TLS=none in the UI
# Check emails at http://localhost:8025
```

### SIEM Forwarding

Configure in **Admin → SIEM Integration**:

| Type | Format | Auth |
|---|---|---|
| Splunk HEC | JSON (HEC event) | HEC token |
| Generic Webhook | JSON (ECS-compatible) | Optional Bearer token |
| Syslog/CEF | CEF over UDP | None (host:port) |

Delivery logs are visible in the UI with HTTP status and error details.

### Local AI Analysis (Ollama / LM Studio)

OTrap uses locally-running LLMs for session analysis, attacker profiling, and triage assistance. No data leaves your network.

**Recommended models (8B range):**

| Model | Pull command | Notes |
|---|---|---|
| Llama 3.1 8B | `ollama pull llama3.1:8b` | 8B text model with 128K context on Ollama |
| Gemma 2 9B | `ollama pull gemma2:9b` | 9B text model with 8K context on Ollama |
| Qwen 2.5 7B | `ollama pull qwen2.5:7b` | 7B text model with 32K context on Ollama |

**Setup with Ollama:**

```bash
# Install Ollama: https://ollama.com
ollama pull llama3.1:8b

# In .env (use LAN IP, not localhost, for Docker access):
LLM_ENABLED=true
LLM_BACKEND=ollama
OLLAMA_BASE_URL=http://192.168.1.10:11434
LLM_DEFAULT_MODEL=llama3.1:8b
```

Then configure in **Admin → Local LLM Configuration** and test the connection.

**Setup with LM Studio:**

Load a model in LM Studio, enable the local server (port 1234), and set:

```dotenv
LLM_ENABLED=true
LLM_BACKEND=lmstudio
LM_STUDIO_BASE_URL=http://192.168.1.10:1234
```

---

## 🛡️ Protocol Coverage

| Protocol | Port | Emulated Behaviors |
|---|---|---|
| **Siemens S7comm** | TCP/102 | TPKT/COTP/S7 handshake, CPU status, DB read/write (persistent memory), system info, CPU STOP |
| **Modbus/TCP** | TCP/502 | FC1–FC4 (read coils/registers), FC5–FC6 (write single), FC15–FC16 (write multiple), MEI device identification (0x2B), exception responses |
| **EtherNet/IP** | TCP/44818 | ListServices, ListIdentity, Register/Unregister Session, and SendRRData/CIP explicit messaging probes |
| **HMI HTTP** | TCP/80 | Login portal, session cookies, OWASP probe detection, path traversal logging |
| **HMI HTTPS** | TCP/443 | Same as HTTP with auto-generated self-signed TLS certificate |

> Note: the sensor process listens on TCP/44818 for EtherNet/IP by default, but the generated `docker run` examples publish only `102/502/80/443`. Add `-p 44818:44818` if you need EtherNet/IP reachable from outside the container, or use `docker-compose.sensor.yml` with host networking.

---

## 🔒 Security Hardening

For production deployments:

1. **Change all secrets** — never run with `CHANGE_ME` defaults in production
2. **Bind management ports to internal IPs:**
   ```dotenv
   MANAGEMENT_HOST=10.0.0.1
   UI_HOST=10.0.0.1
   GRPC_HOST=10.0.0.1
   ```
3. **Enable secure cookies** when serving the UI over HTTPS:
   ```dotenv
   SESSION_SECURE=true
   ```
4. **Do not expose port 9443** (gRPC) to the internet — sensor hosts only
5. **Sensor ports 102/502/80/443** and optionally `44818` should be reachable from OT segments only — not from the internet
6. **Keep `GRPC_CA_KEY_B64` secret** — it is the root signing key for all sensor certificates
7. **Set `SENSOR_INSECURE_JOIN=false`** after all sensors have completed their initial join
8. **Rotate sensor tokens** — each token is single-use; revoke unused sensors from the Sensors page
9. **Use a private registry** if you adopt the pre-built-image workflow — do not assume the placeholder image is public

---

## 👥 User Management & RBAC

OTrap supports two roles:

| Role | Access |
|---|---|
| **Superadmin** | Full access: all operator views + Admin panel (users, integrations, alert rules, audit log, backup, system) |
| **Operator** | Read access to dashboard, sessions, attackers, IOCs, sensors, health, and reports. Can triage sessions and generate PDF reports. |

Manage users at **Admin → Users**:
- Create users with username, email, and role assignment
- Update email/role, set a new password, or deactivate accounts
- Delete accounts after re-authentication when needed

The initial superadmin account is created automatically on first startup using `INITIAL_ADMIN_USERNAME` and `INITIAL_ADMIN_PASSWORD` from `.env`. Self-service password reset is available from the login page when SMTP is configured.

### Audit Log

All administrative actions are recorded and viewable at **Admin → Audit**. The screen supports:
- Username, action, and date-range filtering
- CSV export of the currently loaded audit rows
- Configurable retention in days
- Manual purge of older records after re-authentication

Recorded events include user management, integration changes, alert rule updates, session triage actions, and sensor enrollment or revocation.

---

## 🔔 Alert Rules

Alert rules define condition-based automation for SMTP, SIEM, and session triage. Configure them at **Admin → Alert Rules**.

Each rule specifies:
- **Name** — a human-readable label for the rule
- **Optional description** — operator-facing context for the rule
- **Conditions** — zero or more ANDed predicates across `severity`, `protocol`, `event_type`, `source_ip`, and `sensor_id`
- **Operators** — `eq`, `neq`, `gte`, `lte`, `in`, `not_in`, `contains`
- **Actions** — force SMTP notification, force SIEM forwarding, and/or auto-triage matching sessions
- **Threshold + window** — optional correlation logic such as "fire after 3 matches in 60 seconds"
- **Enabled** toggle — pause a rule without deleting it

Rules are evaluated by the analyzer worker immediately after each event is processed. Rules with no conditions act as catch-all rules. SMTP delivery still uses the global settings in **Admin → Notifications**, and SIEM forwarding still uses **Admin → SIEM Integration**.

---

## 📊 Reports

PDF reports are generated on-demand at **Reports → Generate**. Each report includes:
- Executive summary: sessions, attackers, events, CPU STOP count, actionable sessions, and risk summary
- Severity distribution, protocol breakdown, event histogram, top findings, and recommendations
- Top attacker summary with GeoIP context and session counts
- Session inventory with severity, triage, IOC counts, duration, and timestamps
- IOC table with confidence scores and cross-session counts
- MITRE ATT&CK for ICS observed techniques
- Geographic distribution snapshot

Generated report snapshots are saved in the manager database, listed in report history, and can later be viewed, downloaded as PDF, or deleted from the UI.

---

## 💾 Backup & Restore

### CLI Backup

```bash
./scripts/backup.sh
# or:
make backup
```

Creates a timestamped PostgreSQL dump in the `backups/` directory. The dump includes all sessions, events, IOCs, attacker data, sensors, users, alert rules, and integration configuration.

### Scheduled Backups

Add a cron job on the management server:

```bash
# Daily backup at 2:00 AM
0 2 * * * cd /opt/otrap && ./scripts/backup.sh >> /var/log/otrap-backup.log 2>&1
```

### CLI Restore

```bash
./scripts/restore.sh backups/otrap_20260325_120000.sql.gz
# or:
make restore FILE=backups/otrap_20260325_120000.sql.gz
```

The restore script asks for confirmation, drops and recreates the PostgreSQL database, restores the selected `.sql.gz` dump, and then tells you to restart the manager.

### UI Backup & Restore

Backups can also be created, downloaded, deleted, and restored from **Admin → Backup** in the management console. The same screen supports uploading a `.sql.gz` file and restoring from it. These UI actions require re-authentication.

---

## 🔄 Updating

```bash
git pull
docker compose build
docker compose up -d
```

Database schema bootstrap and idempotent compatibility updates are applied automatically on manager startup. No separate migration command is required for normal updates.

---

## 🧪 Verification

**Full smoke test (40+ checks):**

```bash
pip install requests
ADMIN_PASS=<admin-password> python3 scripts/smoke_test.py
```

**S7comm exploit simulation:**

```bash
python3 scripts/verify_s7_exploit.py --host 127.0.0.1 --api http://localhost:8080
```

**HMI brute-force + OWASP probe:**

```bash
python3 scripts/verify_hmi.py --host http://127.0.0.1:80
```

**Modbus:**

```bash
python3 scripts/verify_modbus.py --host 127.0.0.1
```

**Browser UI smoke test:**

```bash
ADMIN_PASS=<admin-password> make ui-smoke
```

---

## 📄 License

MIT — see [LICENSE](LICENSE)
