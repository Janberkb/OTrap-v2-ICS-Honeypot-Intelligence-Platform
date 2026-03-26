#!/usr/bin/env bash
# download_geoip.sh — Download MaxMind GeoLite2 databases
#
# Usage:
#   MAXMIND_LICENSE_KEY=your_key ./scripts/download_geoip.sh
#
# Or set the key in your .env file and run:
#   source .env && ./scripts/download_geoip.sh
#
# Get a free license key at: https://www.maxmind.com/en/geolite2/signup
#
set -euo pipefail

DEST="${GEOIP_DB_PATH:-$(dirname "$0")/../manager/data}"
mkdir -p "$DEST"

if [ -z "${MAXMIND_LICENSE_KEY:-}" ]; then
  echo "ERROR: MAXMIND_LICENSE_KEY is not set."
  echo "  Get a free key at: https://www.maxmind.com/en/geolite2/signup"
  echo "  Then run: MAXMIND_LICENSE_KEY=your_key $0"
  exit 1
fi

BASE_URL="https://download.maxmind.com/app/geoip_download"

download_db() {
  local edition="$1"
  local file="$DEST/${edition}.mmdb"

  echo "Downloading ${edition}..."
  curl -fsSL \
    "${BASE_URL}?edition_id=${edition}&license_key=${MAXMIND_LICENSE_KEY}&suffix=tar.gz" \
    -o "/tmp/${edition}.tar.gz"

  tar -xzf "/tmp/${edition}.tar.gz" -C /tmp
  mv "/tmp/${edition}_"*"/${edition}.mmdb" "$file"
  rm -rf "/tmp/${edition}_"* "/tmp/${edition}.tar.gz"
  echo "  Saved: $file"
}

download_db "GeoLite2-City"
download_db "GeoLite2-ASN"
download_db "GeoLite2-Country"

echo ""
echo "GeoIP databases downloaded to: $DEST"
echo "Restart the manager container to apply: docker compose restart manager"
