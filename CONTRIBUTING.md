# Contributing to OTrap

Thank you for your interest in contributing to OTrap!

---

## Development Setup

### Prerequisites

- Docker 24+ and Docker Compose v2
- Go 1.22+ (for sensor development)
- Python 3.11+ (for manager development)
- Node.js 18+ (for UI development)

### First Run

```bash
cp .env.example .env
# Edit .env — set strong passwords before running
docker compose build
docker compose up -d
```

The platform will be available at `http://localhost:3000`.

### Running Tests

```bash
make smoke          # Full integration test suite (requires running stack)
make s7-test        # S7comm protocol tests
make hmi-test       # HMI HTTP honeypot tests
```

### Local Development Tips

- `SESSION_SECURE=false` is required when running on localhost (HTTP).
- `SENSOR_INSECURE_JOIN=true` is required for local sensor join without a signed cert.
- Pre-generated gRPC stubs are committed — see [docs/maintainer-notes.md](docs/maintainer-notes.md) if you need to regenerate them.

---

## Architecture Overview

```
OT Network (Sensor)                    Management Network (Manager)
─────────────────────                  ────────────────────────────
Go Binary (~12 MB)                     FastAPI + Postgres + Redis
  :102  S7comm honeypot   ──gRPC──▶    :8080  REST API + SSE
  :502  Modbus decoy        mTLS       :9443  gRPC (sensor mesh)
  :80   HMI HTTP           outbound   :3000  Next.js UI
  :443  HMI HTTPS
  No inbound management port
```

Key design decisions:

- **Sensor → Manager only**: The sensor never opens an inbound management port. All communication is outbound gRPC over mTLS.
- **Join flow**: single-use bcrypt token → Manager-issued CA-signed mTLS cert → AES-256-GCM disk storage.
- **Stateful S7 memory**: values written by an attacker are readable back within the same session.
- **Session severity**: monotonically increasing — never decreases once elevated.
- **SMTP/SIEM secrets**: AES-256-GCM encrypted at rest in the database.

---

## Project Structure

```
sensor/     Go honeypot sensor (S7comm, Modbus, HMI protocols)
manager/    Python/FastAPI backend, gRPC server, analyzer pipeline
  api/      REST API routers
  analyzer/ Event processing pipeline (worker, MITRE mapping, IOC extraction)
  db/       SQLAlchemy models and migrations
  grpc/     gRPC server and protobuf stubs
  notifications/ Alert dispatchers (SMTP, SIEM, webhook, rule engine)
  utils/    GeoIP lookup, encryption helpers
ui/         Next.js 14 management console
proto/      Protobuf definitions (sensor ↔ manager)
scripts/    Installation, backup, and utility scripts
tests/      Integration test suite
```

---

## Pull Request Guidelines

- Open an issue first for non-trivial changes.
- Keep PRs focused — one feature or fix per PR.
- Ensure `make smoke` passes before submitting.
- Follow existing code style (no new linters introduced).

---

## Reporting Security Issues

Please **do not** open a public GitHub issue for security vulnerabilities. Contact the maintainers directly.
