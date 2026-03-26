"""
manager/utils/geoip.py — Local GeoIP lookup via MaxMind GeoLite2 MMDB files.

Database files expected at /app/data/ (mounted via Docker volume):
  GeoLite2-City.mmdb  — country, city
  GeoLite2-ASN.mmdb   — ASN number, org/ISP name

Results are cached in Redis for 24h to avoid repeated disk reads for
the same IP during burst activity.

No external HTTP calls are made — fully air-gap compatible.
"""

from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Optional

logger = logging.getLogger("otrap.geoip")

_DATA_DIR   = os.environ.get("GEOIP_DATA_DIR", "/app/data")
_CITY_DB    = os.path.join(_DATA_DIR, "GeoLite2-City.mmdb")
_ASN_DB     = os.path.join(_DATA_DIR, "GeoLite2-ASN.mmdb")
_CACHE_TTL  = 86400  # 24 hours

_SKIP_PREFIXES = ("10.", "192.168.", "127.", "0.", "169.254.", "::1", "fc", "fd")


def _is_private(ip: str) -> bool:
    if not ip:
        return True
    if any(ip.startswith(p) for p in _SKIP_PREFIXES):
        return True
    try:
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            return True
    except (ValueError, IndexError):
        pass
    return False


def is_private_ip(ip: str) -> bool:
    """Public alias for the private-range check."""
    return _is_private(ip)


def _country_flag(code: str) -> str:
    """Convert 2-letter ISO country code to emoji flag (e.g. 'TR' → '🇹🇷')."""
    if not code or len(code) != 2:
        return ""
    return (
        chr(0x1F1E6 + ord(code[0].upper()) - ord("A")) +
        chr(0x1F1E6 + ord(code[1].upper()) - ord("A"))
    )


@lru_cache(maxsize=1)
def _city_reader():
    """Lazy-load the City database reader (cached for process lifetime)."""
    try:
        import geoip2.database
        if os.path.exists(_CITY_DB):
            return geoip2.database.Reader(_CITY_DB)
        logger.warning("GeoLite2-City.mmdb not found at %s", _CITY_DB)
    except Exception as e:
        logger.warning("Failed to open City MMDB: %s", e)
    return None


@lru_cache(maxsize=1)
def _asn_reader():
    """Lazy-load the ASN database reader (cached for process lifetime)."""
    try:
        import geoip2.database
        if os.path.exists(_ASN_DB):
            return geoip2.database.Reader(_ASN_DB)
        logger.warning("GeoLite2-ASN.mmdb not found at %s", _ASN_DB)
    except Exception as e:
        logger.warning("Failed to open ASN MMDB: %s", e)
    return None


def _lookup_local(ip: str) -> dict:
    """Perform local MMDB lookup. Returns {} on any error."""
    result: dict = {}

    city_r = _city_reader()
    if city_r:
        try:
            city = city_r.city(ip)
            result["country_code"] = city.country.iso_code or ""
            result["country_name"] = city.country.name or ""
            result["city"]         = city.city.name or ""
            result["flag"]         = _country_flag(result["country_code"])
        except Exception:
            pass

    asn_r = _asn_reader()
    if asn_r:
        try:
            asn = asn_r.asn(ip)
            org = asn.autonomous_system_organization or ""
            asn_num = asn.autonomous_system_number
            result["org"] = f"AS{asn_num} {org}".strip() if asn_num else org
        except Exception:
            pass

    return result


async def lookup(ip: str, redis) -> dict:
    """Return GeoIP dict for *ip*, using Redis cache.

    Keys: country_code, country_name, city, org, flag
    Returns {} for private IPs or if databases are unavailable.
    """
    if _is_private(ip):
        return {}

    cache_key = f"geoip:{ip}"
    try:
        cached = await redis.get(cache_key)
        if cached:
            return json.loads(cached)
    except Exception:
        pass

    result = _lookup_local(ip)

    if result:
        try:
            await redis.setex(cache_key, _CACHE_TTL, json.dumps(result))
        except Exception:
            pass

    return result


async def lookup_many(ips: list[str], redis) -> dict[str, dict]:
    """Batch GeoIP lookup for a list of IPs. Returns {ip: geo_dict}."""
    import asyncio
    unique = list(dict.fromkeys(ip for ip in ips if not _is_private(ip)))
    if not unique:
        return {}
    results = await asyncio.gather(*(lookup(ip, redis) for ip in unique))
    return dict(zip(unique, results))
