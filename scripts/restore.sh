#!/usr/bin/env bash
# restore.sh — Restore the OTrap PostgreSQL database from a .sql.gz backup file.
# Usage: ./scripts/restore.sh backups/otrap_20260325_120000.sql.gz
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

BACKUP_FILE="${1:-}"
[ -n "$BACKUP_FILE" ] || fail "Usage: $0 <backup_file.sql.gz>"
[ -f "$BACKUP_FILE" ] || fail "File not found: $BACKUP_FILE"

command -v docker >/dev/null 2>&1 || fail "docker not found"
docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required"

cd "$ROOT_DIR"

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

printf 'WARNING: This will DROP and recreate database "%s".\n' "$DB_NAME"
printf 'All existing data will be lost. Type "yes" to continue: '
read -r CONFIRM
[ "$CONFIRM" = "yes" ] || { printf 'Aborted.\n'; exit 0; }

printf '→ Dropping and recreating database "%s"...\n' "$DB_NAME"
docker compose exec -T postgres \
  psql -U "$DB_USER" -c "DROP DATABASE IF EXISTS \"${DB_NAME}\";" postgres
docker compose exec -T postgres \
  psql -U "$DB_USER" -c "CREATE DATABASE \"${DB_NAME}\";" postgres

printf '→ Restoring from %s...\n' "$BACKUP_FILE"
gunzip -c "$BACKUP_FILE" | docker compose exec -T postgres \
  psql -U "$DB_USER" "$DB_NAME"

printf '✓ Restore complete. Restart manager to re-apply any schema changes:\n'
printf '  docker compose restart manager\n'
