#!/usr/bin/env bash
# backup.sh — Dump the OTrap PostgreSQL database to backups/<timestamp>.sql.gz
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${ROOT_DIR}/backups"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTPUT="${BACKUP_DIR}/otrap_${TIMESTAMP}.sql.gz"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null 2>&1 || fail "docker not found"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"

cd "$ROOT_DIR"

# Resolve DB name and user from .env
DB_NAME="$(python3 - "${ROOT_DIR}/.env" <<'PY'
import pathlib, sys
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if line.startswith("POSTGRES_DB="):
        print(line.split("=", 1)[1]); raise SystemExit(0)
print("otrap")
PY
)"

DB_USER="$(python3 - "${ROOT_DIR}/.env" <<'PY'
import pathlib, sys
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    if line.startswith("POSTGRES_USER="):
        print(line.split("=", 1)[1]); raise SystemExit(0)
print("otrap")
PY
)"

mkdir -p "$BACKUP_DIR"
printf '→ Backing up database "%s" as user "%s"...\n' "$DB_NAME" "$DB_USER"

docker compose exec -T postgres \
  pg_dump -U "$DB_USER" "$DB_NAME" | gzip > "$OUTPUT"

printf '✓ Backup saved: %s\n' "$OUTPUT"
