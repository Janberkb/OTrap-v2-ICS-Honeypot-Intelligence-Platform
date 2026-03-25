#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"
ENV_EXAMPLE="${ROOT_DIR}/.env.example"

info() {
  printf '→ %s\n' "$*"
}

ok() {
  printf '✓ %s\n' "$*"
}

warn() {
  printf 'WARN: %s\n' "$*" >&2
}

fail() {
  printf 'ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Required command not found: $1"
}

service_running() {
  docker compose ps --status running --services 2>/dev/null | grep -qx "$1"
}

get_env_value() {
  python3 - "$ENV_FILE" "$1" <<'PY'
import pathlib
import sys

env_path = pathlib.Path(sys.argv[1])
key = sys.argv[2]

for line in env_path.read_text().splitlines():
    if not line or line.lstrip().startswith("#") or "=" not in line:
        continue
    current_key, value = line.split("=", 1)
    if current_key == key:
        print(value)
        break
PY
}

check_bindable() {
  local host="$1"
  local port="$2"
  local label="$3"

  python3 - "$host" "$port" "$label" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
label = sys.argv[3]

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
except OSError as exc:
    print(f"{label} cannot bind to {host}:{port}: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
}

bootstrap_env() {
  local summary_file="$1"

  python3 - "$ENV_FILE" "$summary_file" <<'PY'
import json
import pathlib
import secrets
import string
import sys

env_path = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
lines = env_path.read_text().splitlines()

data = {}
for line in lines:
    if not line or line.lstrip().startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    data[key] = value

def generate_password(length: int = 20) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))

def missing(value: str | None) -> bool:
    if value is None:
        return True
    value = value.strip()
    return value == "" or "CHANGE_ME" in value

defaults = {
    "SESSION_SECURE": "false",
    "CORS_ORIGINS": "http://localhost:3000",
    "MANAGEMENT_HOST": "127.0.0.1",
    "UI_HOST": "127.0.0.1",
    "GRPC_HOST": "127.0.0.1",
    "SENSOR_INSECURE_JOIN": "true",
    "NEXT_PUBLIC_API_URL": "http://localhost:8080",
    "SENSOR_IMAGE_REF": "ghcr.io/otrap/sensor:latest",
}

for key, value in defaults.items():
    if missing(data.get(key)):
        data[key] = value

if missing(data.get("SENSOR_PUBLIC_MANAGER_ADDR")):
    public_host = data["GRPC_HOST"]
    if public_host in {"0.0.0.0", "::", "*"}:
        public_host = "127.0.0.1"
    data["SENSOR_PUBLIC_MANAGER_ADDR"] = f"{public_host}:9443"

generated = {}
generators = {
    "POSTGRES_PASSWORD": lambda: secrets.token_urlsafe(24),
    "API_SECRET_KEY": lambda: secrets.token_hex(32),
    "ENCRYPTION_KEY": lambda: secrets.token_hex(16),
    "INITIAL_ADMIN_PASSWORD": lambda: generate_password(),
    "SENSOR_CERT_ENC_KEY": lambda: secrets.token_hex(32),
}

for key, generator in generators.items():
    if missing(data.get(key)):
        data[key] = generator()
        generated[key] = data[key]

rewritten = []
seen = set()
for line in lines:
    if not line or line.lstrip().startswith("#") or "=" not in line:
        rewritten.append(line)
        continue
    key, _ = line.split("=", 1)
    if key in data:
        rewritten.append(f"{key}={data[key]}")
        seen.add(key)
    else:
        rewritten.append(line)

append_order = [
    "SESSION_SECURE",
    "CORS_ORIGINS",
    "MANAGEMENT_HOST",
    "UI_HOST",
    "GRPC_HOST",
    "SENSOR_PUBLIC_MANAGER_ADDR",
    "SENSOR_IMAGE_REF",
]
for key in append_order:
    if key not in seen and key in data:
        rewritten.append(f"{key}={data[key]}")

env_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
summary_path.write_text(json.dumps({
    "generated": generated,
    "admin_user": data.get("INITIAL_ADMIN_USERNAME", "admin"),
    "admin_password": data.get("INITIAL_ADMIN_PASSWORD", ""),
    "grpc_host": data.get("GRPC_HOST", "127.0.0.1"),
    "public_manager_addr": data.get("SENSOR_PUBLIC_MANAGER_ADDR", ""),
}), encoding="utf-8")
PY
}

persist_ca_from_logs() {
  local logs
  logs="$(docker compose logs manager --no-color 2>/dev/null || true)"

  LOG_INPUT="$logs" python3 - "$ENV_FILE" <<'PY'
import os
import pathlib
import re
import sys

env_path = pathlib.Path(sys.argv[1])
logs = os.environ.get("LOG_INPUT", "")

key_match = re.search(r"GRPC_CA_KEY_B64=([A-Za-z0-9+/=]+)", logs)
cert_match = re.search(r"GRPC_CA_CERT_B64=([A-Za-z0-9+/=]+)", logs)
if not key_match or not cert_match:
    raise SystemExit(2)

values = {
    "GRPC_CA_KEY_B64": key_match.group(1),
    "GRPC_CA_CERT_B64": cert_match.group(1),
}

lines = env_path.read_text().splitlines()
rewritten = []
seen = set()
for line in lines:
    if not line or line.lstrip().startswith("#") or "=" not in line:
        rewritten.append(line)
        continue
    key, _ = line.split("=", 1)
    if key in values:
        rewritten.append(f"{key}={values[key]}")
        seen.add(key)
    else:
        rewritten.append(line)

for key, value in values.items():
    if key not in seen:
        rewritten.append(f"{key}={value}")

env_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
PY
}

wait_for_manager() {
  python3 - <<'PY'
import json
import sys
import time
import urllib.error
import urllib.request

url = "http://localhost:8080/api/v1/health"
deadline = time.time() + 180
last_error = None

while time.time() < deadline:
    try:
        with urllib.request.urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if resp.status == 200 and data.get("status") in {"healthy", "degraded"}:
                raise SystemExit(0)
            last_error = f"unexpected health payload: {data}"
    except Exception as exc:
        last_error = str(exc)
    time.sleep(2)

print(f"Manager health check failed: {last_error}", file=sys.stderr)
raise SystemExit(1)
PY
}

main() {
  cd "$ROOT_DIR"

  require_cmd docker
  require_cmd python3
  docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required."
  docker info >/dev/null 2>&1 || fail "Docker daemon is not reachable for the current user."

  if [ ! -f "$ENV_FILE" ]; then
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    info "Created .env from .env.example"
  fi

  local summary_file
  summary_file="$(mktemp)"
  trap 'rm -f "${summary_file:-}"' EXIT

  info "Bootstrapping .env"
  bootstrap_env "$summary_file"

  local management_host ui_host grpc_host
  management_host="$(get_env_value MANAGEMENT_HOST)"
  ui_host="$(get_env_value UI_HOST)"
  grpc_host="$(get_env_value GRPC_HOST)"

  if ! service_running manager; then
    info "Checking manager ports"
    check_bindable "${management_host:-127.0.0.1}" 8080 "Manager API"
    check_bindable "${grpc_host:-127.0.0.1}" 9443 "Manager gRPC"
  fi

  if ! service_running ui; then
    info "Checking UI port"
    check_bindable "${ui_host:-127.0.0.1}" 3000 "Management UI"
  fi

  info "Starting postgres, redis, manager, and ui"
  docker compose up -d postgres redis manager ui

  info "Waiting for Manager health"
  wait_for_manager

  local ca_key ca_cert
  ca_key="$(get_env_value GRPC_CA_KEY_B64)"
  ca_cert="$(get_env_value GRPC_CA_CERT_B64)"
  if [ -z "$ca_key" ] || [ -z "$ca_cert" ]; then
    info "Persisting Manager gRPC CA into .env"
    local attempt
    for attempt in $(seq 1 30); do
      if persist_ca_from_logs; then
        ca_key="$(get_env_value GRPC_CA_KEY_B64)"
        ca_cert="$(get_env_value GRPC_CA_CERT_B64)"
        break
      fi
      sleep 2
    done
    [ -n "$ca_key" ] && [ -n "$ca_cert" ] || fail "Could not extract GRPC_CA_* from manager logs."

    info "Restarting manager with persisted CA"
    docker compose up -d manager
    wait_for_manager
  fi

  ok "Manager install complete"
  echo "  Management UI:  http://localhost:3000"
  echo "  Manager API:    http://localhost:8080/api/v1"
  echo "  Admin user:     $(python3 - "$summary_file" <<'PY'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["admin_user"])
PY
)"
  echo "  Admin password: $(python3 - "$summary_file" <<'PY'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["admin_password"])
PY
)"

  local public_addr
  public_addr="$(python3 - "$summary_file" <<'PY'
import json
import pathlib
import sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["public_manager_addr"])
PY
)"
  if [[ "$public_addr" =~ ^(127\.0\.0\.1|localhost): ]]; then
    warn "SENSOR_PUBLIC_MANAGER_ADDR is set to loopback (${public_addr})."
    warn "Remote sensors on other hosts will not reach this Manager until you set GRPC_HOST and SENSOR_PUBLIC_MANAGER_ADDR to the management server IP."
  elif [[ "$public_addr" =~ ^(0\.0\.0\.0|\[::\]|::): ]]; then
    warn "SENSOR_PUBLIC_MANAGER_ADDR is set to a wildcard host (${public_addr})."
    warn "Change it to the management server IP or DNS name before generating remote sensor commands."
  fi
}

main "$@"
