#!/usr/bin/env bash
# update_ip.sh — Update SENSOR_PUBLIC_MANAGER_ADDR and INSTALLER_BASE_URL_OVERRIDE
# in .env to the current outbound LAN IP without restarting services.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ -f "$ENV_FILE" ] || fail ".env not found at ${ENV_FILE}. Run make install-manager first."

python3 - "$ENV_FILE" <<'PY'
import pathlib
import re
import socket
import sys

env_path = pathlib.Path(sys.argv[1])
lines = env_path.read_text().splitlines()

def get_outbound_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return ""

def is_plain_ip(s: str) -> bool:
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", s))

detected_ip = get_outbound_ip()
if not detected_ip or detected_ip.startswith("127."):
    print("Could not detect a non-loopback outbound IP.", file=sys.stderr)
    raise SystemExit(1)

data = {}
for line in lines:
    if not line or line.lstrip().startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    data[key] = value

current_addr = data.get("SENSOR_PUBLIC_MANAGER_ADDR", "")
if not current_addr:
    print(f"SENSOR_PUBLIC_MANAGER_ADDR not set in .env. Run make install-manager first.", file=sys.stderr)
    raise SystemExit(1)

stored_host = current_addr.rsplit(":", 1)[0]
stored_port = current_addr.rsplit(":", 1)[1] if ":" in current_addr else "9443"

if stored_host == detected_ip:
    print(f"✓ IP is already up-to-date: {detected_ip}")
    raise SystemExit(0)

print(f"→ Updating IP: {stored_host} → {detected_ip}")

new_addr = f"{detected_ip}:{stored_port}"
data["SENSOR_PUBLIC_MANAGER_ADDR"] = new_addr

existing_installer = data.get("INSTALLER_BASE_URL_OVERRIDE", "")
if is_plain_ip(stored_host) and stored_host in existing_installer:
    data["INSTALLER_BASE_URL_OVERRIDE"] = existing_installer.replace(stored_host, detected_ip)

rewritten = []
for line in lines:
    if not line or line.lstrip().startswith("#") or "=" not in line:
        rewritten.append(line)
        continue
    key, _ = line.split("=", 1)
    if key in data:
        rewritten.append(f"{key}={data[key]}")
    else:
        rewritten.append(line)

env_path.write_text("\n".join(rewritten) + "\n", encoding="utf-8")
print(f"✓ SENSOR_PUBLIC_MANAGER_ADDR={new_addr}")
print(f"✓ INSTALLER_BASE_URL_OVERRIDE={data.get('INSTALLER_BASE_URL_OVERRIDE', '')}")
print("  (No services restarted — changes take effect on next sensor token generation)")
PY
