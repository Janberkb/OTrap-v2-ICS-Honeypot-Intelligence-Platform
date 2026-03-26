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

def get_outbound_ip() -> str:
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return ""

defaults = {
    "SESSION_SECURE": "false",
    "CORS_ORIGINS": "http://localhost:3000",
    "MANAGEMENT_HOST": "0.0.0.0",
    "UI_HOST": "0.0.0.0",
    "GRPC_HOST": "0.0.0.0",
    "SENSOR_INSECURE_JOIN": "true",
    "NEXT_PUBLIC_API_URL": "http://localhost:8080",
    "SENSOR_IMAGE_REF": "ghcr.io/otrap/sensor:latest",
}

for key, value in defaults.items():
    if missing(data.get(key)):
        data[key] = value

import re as _re

def is_plain_ip(s: str) -> bool:
    return bool(_re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s))

detected_ip = get_outbound_ip()

existing_addr = data.get("SENSOR_PUBLIC_MANAGER_ADDR", "")
if missing(existing_addr):
    # Fresh install — set from detected IP
    public_host = detected_ip if detected_ip and not detected_ip.startswith("127.") else "127.0.0.1"
    data["SENSOR_PUBLIC_MANAGER_ADDR"] = f"{public_host}:9443"
else:
    # Re-run — if the stored host is a plain IP and differs from current outbound IP, update it
    stored_host = existing_addr.rsplit(":", 1)[0]
    stored_port = existing_addr.rsplit(":", 1)[1] if ":" in existing_addr else "9443"
    if is_plain_ip(stored_host) and detected_ip and stored_host != detected_ip:
        print(f"[install_manager] Network IP changed: {stored_host} → {detected_ip}  (updating .env)", flush=True)
        data["SENSOR_PUBLIC_MANAGER_ADDR"] = f"{detected_ip}:{stored_port}"
        # Also refresh INSTALLER_BASE_URL_OVERRIDE if it contained the old IP
        existing_installer = data.get("INSTALLER_BASE_URL_OVERRIDE", "")
        if stored_host in existing_installer:
            data["INSTALLER_BASE_URL_OVERRIDE"] = existing_installer.replace(stored_host, detected_ip)

if missing(data.get("INSTALLER_BASE_URL_OVERRIDE")):
    try:
        public_host = data["SENSOR_PUBLIC_MANAGER_ADDR"].rsplit(":", 1)[0]
    except Exception:
        public_host = "127.0.0.1"
    data["INSTALLER_BASE_URL_OVERRIDE"] = f"http://{public_host}:8080"

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
    "INSTALLER_BASE_URL_OVERRIDE",
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
    "grpc_host": data.get("GRPC_HOST", "0.0.0.0"),
    "public_manager_addr": data.get("SENSOR_PUBLIC_MANAGER_ADDR", ""),
    "installer_base_url": data.get("INSTALLER_BASE_URL_OVERRIDE", ""),
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

  local public_addr installer_url
  public_addr="$(python3 - "$summary_file" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text())["public_manager_addr"])
PY
)"
  installer_url="$(python3 - "$summary_file" <<'PY'
import json, pathlib, sys
print(json.loads(pathlib.Path(sys.argv[1]).read_text()).get("installer_base_url", ""))
PY
)"
  if [[ -n "$installer_url" ]] && ! [[ "$installer_url" =~ ://localhost|://127\. ]]; then
    echo "  Sensor installer: ${installer_url}/api/v1/sensors/install/<sensor-id>"
    echo "  (Generate a token from the UI → copy the curl command → run on the target host)"
  fi
  if [[ "$public_addr" =~ ^(127\.0\.0\.1|localhost): ]]; then
    warn "SENSOR_PUBLIC_MANAGER_ADDR is set to loopback (${public_addr})."
    warn "Remote sensors cannot reach this Manager. Edit GRPC_HOST=0.0.0.0 and SENSOR_PUBLIC_MANAGER_ADDR=<this-server-ip>:9443 in .env, then re-run make install-manager."
  elif [[ "$public_addr" =~ ^(0\.0\.0\.0|\[::\]|::): ]]; then
    warn "SENSOR_PUBLIC_MANAGER_ADDR is set to a wildcard host (${public_addr})."
    warn "Change it to the management server IP or DNS name before generating remote sensor commands."
  fi
}

main "$@"
