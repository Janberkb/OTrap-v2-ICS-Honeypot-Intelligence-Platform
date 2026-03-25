# OTrap Context Notes

## Current Setup Baseline
- Repo is expected to be self-contained for first run. Generated gRPC stubs are committed under `sensor/proto/sensorv1/` and `manager/grpc/`.
- `make proto` is now a maintainer-only regeneration path; first-time users should not need Claude Code or manual codegen.
- Localhost management flow assumes `SESSION_SECURE=false`.
- First local sensor join assumes `SENSOR_INSECURE_JOIN=true`.
- Manager, UI, and sensor Docker images build from their own subdirectories without parent-context proto access.

## Fresh-Run Success Criteria
- `docker compose build manager sensor ui`
- `docker compose up -d postgres redis manager ui`
- `http://localhost:8080/api/v1/health` returns healthy
- `ADMIN_PASS=... SENSOR_NAME=... make sensor-token` works
- `docker compose up -d sensor`
- `make smoke`
- `make s7-test`
- `make hmi-test`

## Important Implementation Notes
- Python gRPC server does not expose client cert details to the app when join is allowed on the same port, so authenticated sensor RPCs currently fall back to claimed `sensor_id` plus active-sensor validation.
- Sensor healthcheck is implemented via `--health-check` and probes local HMI `/health`.
- Sensor identity persistence now stores Manager-issued config alongside cert material so restarts keep the same runtime config.

## Last Verified State
- Full smoke test passed: `40 passed, 0 failed`
- `make s7-test` passed, including stateful read-back and CPU STOP session flag
- `make hmi-test` passed
- Fresh-clone retest passed on 2026-03-24 from a temp copy with a unique `COMPOSE_PROJECT_NAME`, including `docker compose build manager sensor ui`, UI browser login via `make ui-smoke`, sensor join, and all verification commands.
- Manager installer retest passed on 2026-03-24 from a temp copy with `./scripts/install_manager.sh`, including automatic secret generation, automatic CA persistence, idempotent re-run, UI onboarding generation, remote-ready manager reconfiguration, generated `docker run` sensor join, sensor restart with persisted identity, `make smoke` (`44 passed, 0 failed`), `make s7-test`, `make hmi-test`, and `make sensor-token`.

## Fresh-Clone Findings
- Fresh-clone stack was validated from a clean copy under `/tmp`, including `.env` creation, CA persistence, token generation, sensor join, and all three verification commands.
- The main first-run UX blocker is the UI/API cross-origin setup. The UI ships with `NEXT_PUBLIC_API_URL=http://localhost:8080`, many client pages call that absolute origin directly, and `ui/next.config.js` currently sends `Content-Security-Policy: connect-src 'self' ws: wss:`. On `http://localhost:3000/login`, the CSRF fetch is blocked by CSP before login can start.
- Local quick start also needs `CORS_ORIGINS=http://localhost:3000` when the UI talks to the API cross-origin. Without that, browser auth requests fail even if CSP is relaxed.
- Re-extracting or recloning the project into another local `otrap` directory reuses the same Docker Compose named volumes because the project name still resolves to `otrap`. If `POSTGRES_PASSWORD` changes between runs, Postgres auth fails until the old volumes are removed.
- `make sensor-token` works, but its output format is awkward for machine parsing and copy/paste because it emits escaped newlines from a one-line Python command.
- Updating `.env` and then running `docker compose up -d sensor` can recreate `manager` because Compose detects service config drift. This is survivable now that the CA can be persisted, but it is surprising during first-run docs flow.

## Next-Fix Priorities
- The UI quick-start path is now same-origin on the browser side via `/api/...`, while rewrites and middleware use `INTERNAL_API_BASE` for the server-side hop to Manager.
- Local defaults/docs now explicitly keep `CORS_ORIGINS=http://localhost:3000`, and browser smoke is covered by `make ui-smoke`.
- Repeated-local-install volume reuse is still a Docker Compose behavior; current mitigation is documentation plus optional `COMPOSE_PROJECT_NAME` guidance.
- Updating `.env` and then running `docker compose up -d sensor` still recreates `manager` because Compose detects config drift. This is expected and survivable now that first-run docs persist the Manager CA.
- `npm install` and the UI Docker build warn that `next@14.2.3` has a published security vulnerability; plan a focused framework upgrade separately from first-run DX work.
- Login rate limiting now clears on successful auth; without that fix, repeated onboarding flows could lock out `make sensor-token` and other operator login helpers from the same IP.

## Admin UX Notes
- Sidebar wording is now `Log in` / `Log out`, not `Sign in` / `Sign out`.
- Admin information architecture is now enterprise-style: `System`, `Users`, `Integrations`, `Audit Log`.
- `Notifications` and `SIEM` remain as detailed configuration pages, but the primary navigation entry is `Integrations`.
- `/admin` is now a real System page backed by `/api/v1/admin/system`, showing version/build, CA/bootstrap state, token/session defaults, diagnostics, jobs, retention placeholder, and backup/cluster status.
- Sidebar active-state logic now treats `System` as exact `/admin` only, and `Integrations` as the umbrella item for `/admin/integrations`, `/admin/notifications`, and `/admin/siem`.
- UI branding now lives in `ui/public/brand/` with `icon`, `wordmark`, and `lockup` SVG assets plus a shared `BrandMark` component.
- Theme colors are CSS-variable driven with two presets: `brand` and `legacy`. Rollback is a one-line change of `activeTheme` in `ui/app/layout.tsx`.
