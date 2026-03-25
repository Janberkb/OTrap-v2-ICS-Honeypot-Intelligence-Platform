"""
manager/api/sessions.py — Session list, detail, export, and IOC/artifact endpoints.
"""

from __future__ import annotations

import csv
import io
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user

router = APIRouter(prefix="/sessions", tags=["sessions"])


@router.get("")
async def list_sessions(
    severity:     str | None = Query(None),
    signal_tier:  str | None = Query(None),
    protocol:     str | None = Query(None),
    source_ip:    str | None = Query(None),
    cpu_stop:     bool | None = Query(None),
    has_iocs:     bool | None = Query(None),
    is_actionable: bool | None = Query(None),
    from_dt:      str | None = Query(None),
    to_dt:        str | None = Query(None),
    limit:        int = Query(100, ge=1, le=1000),
    offset:       int = Query(0, ge=0),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    sessions, total = await models.Session.list_filtered(
        db,
        severity=severity, signal_tier=signal_tier,
        protocol=protocol, source_ip=source_ip,
        cpu_stop=cpu_stop, has_iocs=has_iocs,
        is_actionable=is_actionable,
        from_dt=from_dt, to_dt=to_dt,
        limit=limit, offset=offset,
    )
    return {
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "items":  [_session_summary(s) for s in sessions],
    }


@router.get("/export/csv")
async def export_sessions_csv(
    columns: str = Query("id,source_ip,severity,signal_tier,primary_protocol,cpu_stop_occurred,event_count,started_at"),
    severity: str | None = Query(None),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> StreamingResponse:
    sessions, _ = await models.Session.list_filtered(db, severity=severity, limit=10000)
    cols = [c.strip() for c in columns.split(",")]

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(cols)
    for s in sessions:
        row = [str(getattr(s, col, "")) for col in cols]
        writer.writerow(row)

    buf.seek(0)
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=sessions.csv"},
    )


@router.get("/{session_id}")
async def get_session(
    session_id: str,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    s = await models.Session.get_recent_open(db, session_id)
    if s is None:
        # Also try closed sessions
        from sqlalchemy import select
        result = await db.execute(
            select(models.Session).where(models.Session.id == session_id)
        )
        s = result.scalar_one_or_none()
    if s is None:
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND"})
    return _session_detail(s)


@router.get("/{session_id}/events")
async def get_session_events(
    session_id: str,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    events = await models.Event.list_for_session(db, session_id)
    return {"items": [_event_summary(e) for e in events]}


@router.get("/{session_id}/iocs")
async def get_session_iocs(
    session_id: str,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    iocs = await models.IOC.list_for_session(db, session_id)
    return {"items": [
        {
            "id":           str(i.id),
            "ioc_type":     i.ioc_type,
            "value":        i.value,
            "context":      i.context,
            "confidence":   i.confidence,
            "first_seen_at": i.first_seen_at,
            "last_seen_at": i.last_seen_at,
        }
        for i in iocs
    ]}


@router.get("/{session_id}/artifacts")
async def get_session_artifacts(
    session_id: str,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    arts = await models.Artifact.list_for_session(db, session_id)
    return {"items": [
        {
            "id":            str(a.id),
            "artifact_type": a.artifact_type,
            "value":         a.value,
            "encoding":      a.encoding,
            "created_at":    a.created_at,
        }
        for a in arts
    ]}


@router.get("/{session_id}/timeline")
async def get_session_timeline(
    session_id: str,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    events = await models.Event.list_for_session(db, session_id)
    return {
        "session_id": session_id,
        "timeline": [
            {
                "timestamp":     e.timestamp,
                "event_type":    e.event_type,
                "severity":      e.severity,
                "classification": e.classification,
                "raw_summary":   e.raw_summary,
                "dst_port":      e.dst_port,
            }
            for e in events
        ],
    }


# ─── Serializers ─────────────────────────────────────────────────────────────

def _session_summary(s: models.Session) -> dict:
    return {
        "id":                 str(s.id),
        "source_ip":          s.source_ip,
        "primary_protocol":   s.primary_protocol,
        "severity":           s.severity,
        "signal_tier":        s.signal_tier,
        "attack_phase":       s.attack_phase,
        "is_actionable":      s.is_actionable,
        "cpu_stop_occurred":  s.cpu_stop_occurred,
        "has_iocs":           s.has_iocs,
        "ioc_count":          s.ioc_count,
        "artifact_count":     s.artifact_count,
        "event_count":        s.event_count,
        "duration_seconds":   s.duration_seconds,
        "started_at":         s.started_at,
        "updated_at":         s.updated_at,
        "mitre_techniques":   s.mitre_techniques or [],
    }


def _session_detail(s: models.Session) -> dict:
    d = _session_summary(s)
    d.update({
        "sensor_id":  str(s.sensor_id) if s.sensor_id else None,
        "source_port": s.source_port,
        "metadata":    s.session_metadata or {},
        "closed_at":   s.closed_at,
    })
    return d


def _event_summary(e: models.Event) -> dict:
    return {
        "id":             str(e.id),
        "event_type":     e.event_type,
        "event_family":   e.event_family,
        "severity":       e.severity,
        "classification": e.classification,
        "raw_summary":    e.raw_summary,
        "protocol":       e.protocol,
        "dst_port":       e.dst_port,
        "source_port":    e.source_port,
        "artifact_count": e.artifact_count,
        "timestamp":      e.timestamp,
        "metadata":       e.event_metadata or {},
    }
