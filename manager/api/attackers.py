"""
manager/api/attackers.py — Attacker IP profile (aggregated view).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import func, select

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user

router = APIRouter(prefix="/attackers", tags=["attackers"])


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

    # GeoIP
    from manager.utils.geoip import lookup
    geo = await lookup(ip, request.app.state.redis)

    return {
        "ip":             ip,
        "geo":            geo,
        "session_count":  int(row.session_count or 0),
        "event_count":    int(row.event_count or 0),
        "ioc_count":      int(row.ioc_count or 0),
        "first_seen":     row.first_seen,
        "last_seen":      row.last_seen,
        "cpu_stop_ever":  bool(row.cpu_stop_ever),
        "severity_dist":  severity_dist,
        "protocol_dist":  protocol_dist,
        "attack_phases":  phases,
    }
