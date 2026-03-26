"""
manager/api/events.py — Recent events and top attackers.
"""

from fastapi import APIRouter, Depends, Query, Request
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
    request: Request,
    limit: int = Query(10, ge=1, le=50),
    hours: int = Query(24, ge=1, le=720),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    rows = await models.Event.top_attackers(db, limit=limit, hours=hours)
    from manager.utils.geoip import lookup_many
    ips = [r["source_ip"] for r in rows]
    geo_map = await lookup_many(ips, request.app.state.redis)
    items = []
    for r in rows:
        geo = geo_map.get(r["source_ip"], {})
        items.append({
            **r,
            "country_name": geo.get("country_name"),
            "flag":         geo.get("flag"),
            "org":          geo.get("org"),
            "cpu_stop_ever": bool(r.get("cpu_stop_ever")),
            "last_seen":    r.get("last_seen"),
        })
    return {"items": items}


@router.get("/histogram")
async def events_histogram(
    hours: int = Query(24, ge=1, le=720),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    from datetime import datetime, timezone, timedelta
    from sqlalchemy import text as sa_text

    since    = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    # Group by day for ranges > 48h, by hour otherwise
    use_days = hours > 48

    trunc    = "day" if use_days else "hour"
    result   = await db.execute(sa_text(f"""
        SELECT
            date_trunc('{trunc}', timestamp::timestamptz) AS bucket,
            COUNT(*) AS count
        FROM events
        WHERE timestamp >= :since
        GROUP BY bucket
        ORDER BY bucket
    """), {"since": since})

    buckets = []
    for r in result:
        dt = r.bucket
        if hasattr(dt, "strftime"):
            label = dt.strftime("%b %d") if use_days else dt.strftime("%H:%M")
        else:
            label = str(r.bucket)[:10] if use_days else str(r.bucket)[:16]
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
