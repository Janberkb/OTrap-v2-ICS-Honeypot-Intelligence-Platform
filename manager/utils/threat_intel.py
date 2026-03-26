"""
manager/utils/threat_intel.py — External threat intelligence enrichment.

Supported sources:
  - GreyNoise Community API (api.greynoise.io)
  - AbuseIPDB (api.abuseipdb.com)

Both require API keys (GREYNOISE_API_KEY, ABUSEIPDB_API_KEY).
Results are cached in Redis for 6 hours to stay within free-tier limits.
When keys are absent or the upstream API is unreachable, returns None gracefully.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import httpx

logger = logging.getLogger("otrap.threat_intel")

_GREYNOISE_KEY = os.environ.get("GREYNOISE_API_KEY", "").strip()
_ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
_CACHE_TTL     = 6 * 3600  # 6 hours
_HTTP_TIMEOUT  = 5.0        # seconds per request

_SKIP_PREFIXES = ("10.", "192.168.", "127.", "0.", "169.254.", "::1", "fc", "fd")


def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _SKIP_PREFIXES)


async def _cache_get(redis, key: str) -> Any | None:
    try:
        raw = await redis.get(key)
        return json.loads(raw) if raw else None
    except Exception:
        return None


async def _cache_set(redis, key: str, value: Any) -> None:
    try:
        await redis.setex(key, _CACHE_TTL, json.dumps(value))
    except Exception:
        pass


async def lookup_greynoise(ip: str, redis) -> dict | None:
    """
    Query GreyNoise Community API.

    Returns:
      None — key not configured, private IP, or request failed
      {"seen": False} — IP not in GreyNoise database
      {"seen": True, "noise": bool, "riot": bool, "classification": str, "name": str, "link": str}
    """
    if not _GREYNOISE_KEY or _is_private(ip):
        return None

    cache_key = f"ti:greynoise:{ip}"
    cached = await _cache_get(redis, cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            r = await client.get(
                f"https://api.greynoise.io/v3/community/{ip}",
                headers={"key": _GREYNOISE_KEY},
            )
        if r.status_code == 404:
            result: dict = {"seen": False}
        elif r.status_code == 200:
            d = r.json()
            result = {
                "seen":           True,
                "noise":          bool(d.get("noise", False)),
                "riot":           bool(d.get("riot", False)),
                "classification": d.get("classification", "unknown"),
                "name":           d.get("name"),
                "link":           d.get("link"),
            }
        else:
            logger.debug("GreyNoise HTTP %s for %s", r.status_code, ip)
            return None
    except Exception as exc:
        logger.debug("GreyNoise lookup failed for %s: %s", ip, exc)
        return None

    await _cache_set(redis, cache_key, result)
    return result


async def lookup_abuseipdb(ip: str, redis) -> dict | None:
    """
    Query AbuseIPDB v2 check endpoint.

    Returns:
      None — key not configured, private IP, or request failed
      {"abuse_score": int, "total_reports": int, "last_reported": str|None, "is_whitelisted": bool}
    """
    if not _ABUSEIPDB_KEY or _is_private(ip):
        return None

    cache_key = f"ti:abuseipdb:{ip}"
    cached = await _cache_get(redis, cache_key)
    if cached is not None:
        return cached

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            r = await client.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": _ABUSEIPDB_KEY, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90},
            )
        if r.status_code != 200:
            logger.debug("AbuseIPDB HTTP %s for %s", r.status_code, ip)
            return None
        d = r.json().get("data", {})
        result = {
            "abuse_score":    int(d.get("abuseConfidenceScore", 0)),
            "total_reports":  int(d.get("totalReports", 0)),
            "last_reported":  d.get("lastReportedAt"),
            "is_whitelisted": bool(d.get("isWhitelisted", False)),
        }
    except Exception as exc:
        logger.debug("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None

    await _cache_set(redis, cache_key, result)
    return result


async def lookup_threat_intel(ip: str, redis) -> dict:
    """Run all lookups concurrently and return a combined result dict."""
    greynoise, abuseipdb = await asyncio.gather(
        lookup_greynoise(ip, redis),
        lookup_abuseipdb(ip, redis),
    )
    return {
        "greynoise": greynoise,
        "abuseipdb": abuseipdb,
    }
