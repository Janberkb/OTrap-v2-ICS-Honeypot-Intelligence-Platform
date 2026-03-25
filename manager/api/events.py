"""
manager/api/events.py — Recent events and top attackers.
"""

from fastapi import APIRouter, Depends, Query
from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user

router = APIRouter(prefix="/events", tags=["events"])


@router.get("")
async def list_events(
    limit: int = Query(50, ge=1, le=500),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    events = await models.Event.list_recent(db, limit=limit)
    return {"items": [_ev(e) for e in events]}


@router.get("/top-attackers")
async def top_attackers(
    limit: int = Query(10, ge=1, le=50),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    rows = await models.Event.top_attackers(db, limit=limit)
    return {"items": rows}


@router.get("/histogram")
async def events_histogram(
    hours: int = Query(24, ge=1, le=168),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import text as sa_text

    since = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    result = await db.execute(sa_text("""
        SELECT
            date_trunc('hour', timestamp::timestamptz) AS bucket,
            COUNT(*) AS count
        FROM events
        WHERE timestamp >= :since
        GROUP BY bucket
        ORDER BY bucket
    """), {"since": since})

    buckets = []
    for r in result:
        dt = r.bucket
        label = dt.strftime("%H:%M") if hasattr(dt, "strftime") else str(r.bucket)[:16]
        buckets.append({"hour": label, "count": int(r.count)})

    return {"buckets": buckets, "hours": hours}


def _ev(e: models.Event) -> dict:
    return {
        "id":            str(e.id),
        "session_id":    str(e.session_id) if e.session_id else None,
        "source_ip":     e.source_ip,
        "event_type":    e.event_type,
        "severity":      e.severity,
        "protocol":      e.protocol,
        "dst_port":      e.dst_port,
        "raw_summary":   e.raw_summary,
        "classification": e.classification,
        "timestamp":     e.timestamp,
    }
