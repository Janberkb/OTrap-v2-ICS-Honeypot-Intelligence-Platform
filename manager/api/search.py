"""
manager/api/search.py — Global search across sessions, IOCs, and attackers.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, or_, func, Text
from sqlalchemy.sql.expression import cast

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user

router = APIRouter(prefix="/search", tags=["search"])


@router.get("")
async def global_search(
    q:      str = Query(..., min_length=1, max_length=200),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    """Search sessions (by source IP or session ID) and IOCs (by value).

    Returns up to 5 results per category, ordered by most recent first.
    """
    term = q.strip()
    if not term:
        return {"sessions": [], "iocs": [], "total": 0}

    pat = f"%{term}%"

    # Sessions: match source_ip or session id (cast to text)
    session_rows = (await db.execute(
        select(
            models.Session.id,
            models.Session.source_ip,
            models.Session.primary_protocol,
            models.Session.severity,
            models.Session.started_at,
        )
        .where(or_(
            models.Session.source_ip.ilike(pat),
            cast(models.Session.id, Text).ilike(pat),
        ))
        .order_by(models.Session.started_at.desc())
        .limit(5)
    )).all()

    # IOCs: match value, deduplicated by (type, value)
    ioc_rows = (await db.execute(
        select(
            models.IOC.ioc_type,
            models.IOC.value,
            func.max(models.IOC.last_seen_at).label("last_seen_at"),
        )
        .where(models.IOC.value.ilike(pat))
        .group_by(models.IOC.ioc_type, models.IOC.value)
        .order_by(func.max(models.IOC.last_seen_at).desc())
        .limit(5)
    )).all()

    sessions = [
        {
            "id":         str(r.id),
            "source_ip":  r.source_ip,
            "protocol":   r.primary_protocol or "unknown",
            "severity":   r.severity or "info",
            "started_at": r.started_at,
        }
        for r in session_rows
    ]

    iocs = [
        {"ioc_type": r.ioc_type, "value": r.value}
        for r in ioc_rows
    ]

    return {
        "sessions": sessions,
        "iocs":     iocs,
        "total":    len(sessions) + len(iocs),
    }
