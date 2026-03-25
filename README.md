# OTrap v2.0 — Enterprise OT Deception Platform

Distributed, production-ready ICS/OT Honeypot with stateful S7-300/400 emulation,
gRPC-based sensor mesh, and a Next.js SOC management console.

---

## Architecture

```
OT Network                     Management Network
─────────────                  ──────────────────
OTrap Sensor (Go)   ──gRPC──▶  OTrap Manager (FastAPI)
  :102  S7comm        mTLS       :8080 REST + SSE
  :502  Modbus                   :9443 gRPC (management network)
  :80   HMI HTTP               Postgres 16
  :443  HMI HTTPS              Redis 7
                                Next.js UI  :3000
                                LLM Engine  :8001 (optional)
```

**Key design decisions:**
- Sensors initiate all connections (outbound-only) — no management port on sensor
- mTLS via per-sensor certificates issued by internal CA at join time
- S7 stateful memory map: attacker writes are readable back → convincing PLC emulation
- CPU STOP returns plausible ACK (never RST) to maintain deception

---

## Quick Start

### 1. Prerequisites
- Docker Engine 24+ and Docker Compose v2
- Ports 8080, 3000, 9443 available on the management server
- This zip already includes `sensor/go.sum` and generated gRPC stubs. No Claude Code or pre-build code generation step is required for first run.

### 2. Install the Manager
```bash
./scripts/install_manager.sh
# Or:
make install-manager
```

What the installer does:
- Verifies Docker + Compose availability
- Creates `.env` from `.env.example` if needed
- Auto-generates missing secrets
- Applies local-safe defaults like `SESSION_SECURE=false` and `CORS_ORIGINS=http://localhost:3000`
- Starts `postgres`, `redis`, `manager`, and `ui`
- Waits for Manager health
- Persists `GRPC_CA_KEY_B64` and `GRPC_CA_CERT_B64` back into `.env`

If you want remote sensors on other hosts, edit `.env` before or after install and set:
- `GRPC_HOST=0.0.0.0` or `GRPC_HOST=<management_server_ip>`
- `SENSOR_PUBLIC_MANAGER_ADDR=<management_server_ip>:9443`

Then rerun:
```bash
docker compose up -d manager ui
```

If you are reinstalling locally with a different `POSTGRES_PASSWORD`, or reusing
another `otrap` checkout on the same machine, clear old named volumes first:

```bash
docker compose down -v
```

### 3. Access Management UI
- URL: `http://localhost:3000`
- Login with `INITIAL_ADMIN_USERNAME` / `INITIAL_ADMIN_PASSWORD`

### 4. Add a Sensor from the Manager

The primary onboarding flow is now:
1. Install the Manager with `./scripts/install_manager.sh`
2. Log into `http://localhost:3000`
3. Open the `Sensors` page
4. Generate a sensor onboarding payload
5. Copy the one-line `docker run` command onto the sensor host and execute it

The generated command includes:
- the single-use join token
- the sensor cert encryption key
- the canonical manager gRPC address from `SENSOR_PUBLIC_MANAGER_ADDR`
- the sensor image from `SENSOR_IMAGE_REF`

The CLI helper uses the same API and prints the same onboarding data:
```bash
ADMIN_PASS=yourpassword SENSOR_NAME=field-sensor-01 make sensor-token
```

For an advanced/manual path, the UI also shows a `.env.sensor` snippet plus the
`docker-compose.sensor.yml` command.

---

## Development Mode

```bash
# Start with hot-reload and exposed DB/Redis ports
docker compose -f docker-compose.yml -f docker-compose.dev.yml up

# Run UI in host (faster iteration)
cd ui && npm install && INTERNAL_API_BASE=http://localhost:8080 npm run dev
```

---

## Verification

### Full smoke test
```bash
pip install requests
ADMIN_PASS=yourpassword python3 scripts/smoke_test.py
```

### Browser login smoke test
```bash
ADMIN_PASS=yourpassword make ui-smoke
```

The first run downloads a local Chromium build via Playwright.

### S7 exploit simulation
```bash
python3 scripts/verify_s7_exploit.py --host 127.0.0.1 --api http://localhost:8080
```

### HMI brute-force + OWASP classification
```bash
python3 scripts/verify_hmi.py --host http://127.0.0.1:80
```

---

## Maintainer Notes

If you change `proto/sensor.proto`, regenerate the committed stubs with:

```bash
make proto
```

The `make proto` target bootstraps a local helper venv under `.tools/proto-venv` for `grpcio-tools` if needed.

## Sensor Image Publishing

The default remote onboarding flow is registry-first. Publish the sensor image
for both `linux/amd64` and `linux/arm64`, and keep both a versioned tag and
`latest` available:

```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/otrap/sensor:v2.0.0 \
  -t ghcr.io/otrap/sensor:latest \
  --push ./sensor
```

---

## Sensor Deployment (Standalone on Industrial Hardware)

The primary path is the onboarding command generated inside the Manager UI.
That command is a one-line `docker run` using host networking and a persistent
cert volume on the sensor host.

If you prefer the advanced/manual path, keep using `docker-compose.sensor.yml`:

```bash
cat > .env.sensor <<'EOF'
SENSOR_MANAGER_URL=manager.internal:9443
SENSOR_JOIN_TOKEN=<token from Manager>
SENSOR_NAME=ot-segment-a
SENSOR_CERT_ENC_KEY=<64-char hex>
SENSOR_INSECURE_JOIN=true
SENSOR_IMAGE_REF=ghcr.io/otrap/sensor:latest
EOF

docker compose -f docker-compose.sensor.yml --env-file .env.sensor up -d
```

The sensor will:
1. Connect to Manager and exchange the join token for a signed mTLS cert
2. Save the cert encrypted to `SENSOR_CERT_DIR` (default: `/etc/otrap/sensor/certs`)
3. Start all protocol listeners (S7 :102, Modbus :502, HMI :80/:443)
4. Stream all events to Manager via gRPC — no inbound management ports

---

## With LLM Engine (Optional)

```bash
# Add OpenAI key to .env
OPENAI_API_KEY=sk-...
LLM_ENABLED=true

# Start with LLM profile
docker compose --profile llm up -d
```

---

## Security Hardening for Production

1. **Change all default passwords** in `.env` before first run
2. **Bind management ports to internal IPs**: `MANAGEMENT_HOST=10.0.0.1`, `GRPC_HOST=10.0.0.1`
3. **Set `SESSION_SECURE=true`** when the management UI/API is behind HTTPS
4. **Rotate sensor tokens** after each sensor joins (tokens are single-use)
5. **Keep `GRPC_HOST` and `SENSOR_PUBLIC_MANAGER_ADDR` on an internal management IP**
6. **Do not expose port 9443** outside the management network
7. **Sensor ports (102/502/80/443)** should only be accessible from OT network segments

---

## Architecture Deviations from Original

| Area | Original | Rebuilt | Justification |
|---|---|---|---|
| Sensor language | Python | Go | Native binary, stateful TCP, ARM support |
| Sensor comms | None (monolith) | gRPC + mTLS | Distributed architecture, stealth |
| UI framework | Previous stack | Next.js 14 App Router | Rebuilt from scratch per spec |
| Session management | Redis sessions | Redis sessions + in-memory cache | Performance |
| S7 memory | Stateless | Stateful per-session map | Higher deception fidelity |
| HMI TLS | Manual | Auto-generated self-signed | Operational simplicity |

## Known Gaps / Follow-up Work

- [ ] Modbus handler fully functional but minimal response variety (extend with more function codes)
- [ ] Alembic incremental migration scripts (currently using `create_all` in dev)
- [ ] Next.js `next-intl` TR/EN translation strings (scaffolding present, strings need population)
- [ ] Health page sensors heatmap (map component — placeholder in current build)
- [ ] Admin SIEM delivery log UI table (API complete, UI skeleton only)
- [ ] LLM rule/report generation UI (API stubs complete, full UX not implemented)
- [ ] Rate limiting on gRPC Join endpoint (mitigates token brute-force at network level)
- [ ] CRL (Certificate Revocation List) enforcement on gRPC — currently revocation is DB-status-only
