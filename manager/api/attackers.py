"""
manager/api/attackers.py — Attacker IP profile (aggregated view).
"""

from __future__ import annotations

import json
import uuid as uuid_mod
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user
from manager.security.audit import write_audit

router = APIRouter(prefix="/attackers", tags=["attackers"])


def build_network_context(ip: str, geo: dict | None) -> dict:
    from manager.utils.geoip import is_private_ip

    geo = geo or {}
    is_private = bool(geo.get("is_private")) or is_private_ip(ip)
    if is_private:
        summary = (
            "This source is in private-network space. Treat activity as internal pivoting, "
            "NATed traffic, lab validation, or a sensor-placement issue until attribution is confirmed."
        )
    else:
        country = geo.get("country_name") or "an unknown country"
        org = geo.get("org") or "an unknown network"
        summary = f"GeoIP attributes this source to {country} via {org}."

    return {
        "scope": "internal" if is_private else "external",
        "is_private": is_private,
        "threat_intel_applicable": not is_private,
        "summary": summary,
    }


async def fetch_attacker_ioc_page(
    db,
    ip: str,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    base = (
        select(
            models.IOC.ioc_type,
            models.IOC.value,
            func.max(models.IOC.confidence).label("confidence"),
            func.min(models.IOC.first_seen_at).label("first_seen_at"),
            func.max(models.IOC.last_seen_at).label("last_seen_at"),
            func.count(models.IOC.session_id.distinct()).label("session_count"),
        )
        .join(models.Session, models.IOC.session_id == models.Session.id)
        .where(models.Session.source_ip == ip)
        .group_by(models.IOC.ioc_type, models.IOC.value)
    )

    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()
    rows = (
        await db.execute(
            base.order_by(
                func.max(models.IOC.last_seen_at).desc(),
                func.count(models.IOC.session_id.distinct()).desc(),
                func.max(models.IOC.confidence).desc(),
            )
            .offset(offset)
            .limit(limit)
        )
    ).all()

    return {
        "total": total,
        "offset": offset,
        "limit": limit,
        "items": [
            {
                "ioc_type": r.ioc_type,
                "value": r.value,
                "confidence": round(r.confidence, 3),
                "session_count": int(r.session_count or 0),
                "first_seen_at": r.first_seen_at,
                "last_seen_at": r.last_seen_at,
            }
            for r in rows
        ],
    }


async def fetch_attacker_ioc_type_distribution(db, ip: str) -> list[dict]:
    dedup = (
        select(
            models.IOC.ioc_type.label("ioc_type"),
            models.IOC.value.label("value"),
        )
        .join(models.Session, models.IOC.session_id == models.Session.id)
        .where(models.Session.source_ip == ip)
        .group_by(models.IOC.ioc_type, models.IOC.value)
        .subquery()
    )

    rows = await db.execute(
        select(dedup.c.ioc_type, func.count().label("cnt"))
        .group_by(dedup.c.ioc_type)
        .order_by(func.count().desc(), dedup.c.ioc_type.asc())
    )
    return [{"ioc_type": r.ioc_type, "count": int(r.cnt)} for r in rows]


@router.get("/{ip}/export/stix")
async def export_attacker_stix(
    ip: str,
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> StreamingResponse:
    """Export a STIX 2.1 bundle aggregating all IOCs observed from this attacker IP."""
    # Fetch all deduplicated IOCs for this IP across all sessions
    rows = (
        await db.execute(
            select(
                models.IOC.ioc_type,
                models.IOC.value,
                func.max(models.IOC.confidence).label("confidence"),
                func.min(models.IOC.first_seen_at).label("first_seen_at"),
                func.max(models.IOC.context).label("context"),
            )
            .join(models.Session, models.IOC.session_id == models.Session.id)
            .where(models.Session.source_ip == ip)
            .group_by(models.IOC.ioc_type, models.IOC.value)
            .order_by(func.min(models.IOC.first_seen_at).asc())
        )
    ).all()

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    stix_objects = []
    for ioc in rows:
        if ioc.ioc_type == "ip":
            pattern = f"[ipv4-addr:value = '{ioc.value}']"
        elif ioc.ioc_type == "domain":
            pattern = f"[domain-name:value = '{ioc.value}']"
        elif ioc.ioc_type == "url":
            pattern = f"[url:value = '{ioc.value}']"
        elif ioc.ioc_type == "hash_md5":
            pattern = f"[file:hashes.MD5 = '{ioc.value}']"
        elif ioc.ioc_type == "hash_sha256":
            pattern = f"[file:hashes.'SHA-256' = '{ioc.value}']"
        else:
            pattern = f"[artifact:payload_bin = '{ioc.value}']"

        valid_from = ioc.first_seen_at
        if valid_from:
            valid_from = valid_from.isoformat().replace("+00:00", "Z")
            if not valid_from.endswith("Z"):
                valid_from += "Z"
        else:
            valid_from = now_iso

        stix_objects.append({
            "type":         "indicator",
            "spec_version": "2.1",
            "id":           f"indicator--{uuid_mod.uuid4()}",
            "created":      now_iso,
            "modified":     now_iso,
            "name":         f"OTrap: {ioc.ioc_type} IOC from attacker {ip}",
            "description":  ioc.context or f"Observed {ioc.ioc_type}: {ioc.value}",
            "pattern":      pattern,
            "pattern_type": "stix",
            "valid_from":   valid_from,
            "confidence":   ioc.confidence or 75,
            "labels":       ["malicious-activity"],
        })

    bundle = {
        "type":         "bundle",
        "id":           f"bundle--{uuid_mod.uuid4()}",
        "spec_version": "2.1",
        "objects":      stix_objects,
    }

    safe_ip = ip.replace(":", "_")
    await write_audit(
        db, user, "export_attacker_stix",
        detail={"ip": ip, "ioc_count": len(stix_objects)},
        source_ip=request.client.host if request.client else None,
    )

    return StreamingResponse(
        iter([json.dumps(bundle, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=attacker-{safe_ip}-stix.json"},
    )


@router.get("/{ip}/iocs")
async def list_attacker_iocs(
    ip: str,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    return await fetch_attacker_ioc_page(db, ip, limit=limit, offset=offset)


@router.get("/{ip}")
async def get_attacker_profile(
    ip: str,
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    """Return an aggregated threat profile for a given source IP."""

    # Session stats
    sess_rows = await db.execute(
        select(
            func.count(models.Session.id).label("session_count"),
            func.sum(models.Session.event_count).label("event_count"),
            func.sum(models.Session.ioc_count).label("ioc_count"),
            func.min(models.Session.started_at).label("first_seen"),
            func.max(models.Session.started_at).label("last_seen"),
            func.bool_or(models.Session.cpu_stop_occurred).label("cpu_stop_ever"),
        ).where(models.Session.source_ip == ip)
    )
    row = sess_rows.one()

    # Severity distribution
    sev_rows = await db.execute(
        select(models.Session.severity, func.count(models.Session.id).label("cnt"))
        .where(models.Session.source_ip == ip)
        .group_by(models.Session.severity)
        .order_by(func.count(models.Session.id).desc())
    )
    severity_dist = {r.severity: int(r.cnt) for r in sev_rows}

    # Protocol distribution
    proto_rows = await db.execute(
        select(models.Session.primary_protocol, func.count(models.Session.id).label("cnt"))
        .where(models.Session.source_ip == ip)
        .group_by(models.Session.primary_protocol)
        .order_by(func.count(models.Session.id).desc())
    )
    protocol_dist = [{"protocol": r.primary_protocol or "unknown", "count": int(r.cnt)} for r in proto_rows]

    # Unique attack phases
    phase_rows = await db.execute(
        select(models.Session.attack_phase, func.count(models.Session.id).label("cnt"))
        .where(models.Session.source_ip == ip)
        .group_by(models.Session.attack_phase)
        .order_by(func.count(models.Session.id).desc())
    )
    phases = [r.attack_phase for r in phase_rows if r.attack_phase]
    ioc_type_dist = await fetch_attacker_ioc_type_distribution(db, ip)
    ioc_page = await fetch_attacker_ioc_page(db, ip, limit=10, offset=0)

    # GeoIP + Threat Intelligence (run concurrently)
    from manager.utils.geoip import lookup
    from manager.utils.threat_intel import lookup_threat_intel
    import asyncio

    redis = request.app.state.redis
    geo, threat_intel = await asyncio.gather(
        lookup(ip, redis),
        lookup_threat_intel(ip, redis),
    )
    network_context = build_network_context(ip, geo)

    return {
        "ip":             ip,
        "geo":            geo,
        "threat_intel":   threat_intel,
        "network_context": network_context,
        "session_count":  int(row.session_count or 0),
        "event_count":    int(row.event_count or 0),
        "ioc_count":      int(row.ioc_count or 0),
        "distinct_ioc_count": int(ioc_page["total"]),
        "first_seen":     row.first_seen,
        "last_seen":      row.last_seen,
        "cpu_stop_ever":  bool(row.cpu_stop_ever),
        "severity_dist":  severity_dist,
        "protocol_dist":  protocol_dist,
        "attack_phases":  phases,
        "ioc_type_dist":  ioc_type_dist,
    }
