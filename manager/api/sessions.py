"""
manager/api/sessions.py — Session list, detail, export, and IOC/artifact endpoints.
"""

from __future__ import annotations

import csv
import io
import json
import uuid as uuid_mod
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user
from manager.security.audit import write_audit
from manager.analyzer.mitre_ics import MITRE_ICS_MAPPING

# technique_id → description (first match wins when multiple events share a technique)
_MITRE_DESC: dict[str, str] = {}
for _entry in MITRE_ICS_MAPPING.values():
    _tid = _entry.get("technique_id", "")
    if _tid and _tid not in _MITRE_DESC:
        _MITRE_DESC[_tid] = _entry.get("description", "")

router = APIRouter(prefix="/sessions", tags=["sessions"])

_VALID_TRIAGE = {"new", "investigating", "reviewed", "false_positive", "escalated"}


class TriageRequest(BaseModel):
    triage_status: str
    triage_note: str | None = None


@router.get("")
async def list_sessions(
    severity:      str | None = Query(None),
    signal_tier:   str | None = Query(None),
    protocol:      str | None = Query(None),
    source_ip:     str | None = Query(None),
    cpu_stop:      bool | None = Query(None),
    has_iocs:      bool | None = Query(None),
    is_actionable: bool | None = Query(None),
    from_dt:       str | None = Query(None),
    to_dt:         str | None = Query(None),
    triage_status: str | None = Query(None),
    sort_by:       str | None = Query(None),
    sort_dir:      str | None = Query(None),
    limit:         int = Query(100, ge=1, le=1000),
    offset:        int = Query(0, ge=0),
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
        triage_status=triage_status,
        sort_by=sort_by, sort_dir=sort_dir,
        limit=limit, offset=offset,
    )
    return {
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "items":  [_session_summary(s) for s in sessions],
    }


@router.get("/stats")
async def sessions_stats(
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    from datetime import date, datetime, timezone, timedelta
    from sqlalchemy import text as sa_text

    today   = date.today().isoformat()          # "2026-03-25"
    ago_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()

    proto_rows = await db.execute(sa_text("""
        SELECT primary_protocol, COUNT(*) AS count
        FROM sessions
        GROUP BY primary_protocol
        ORDER BY count DESC
        LIMIT 10
    """))
    protocols = [
        {"protocol": r.primary_protocol or "unknown", "count": int(r.count)}
        for r in proto_rows
    ]

    sessions_today = (await db.execute(
        sa_text("SELECT COUNT(*) FROM sessions WHERE started_at >= :today"),
        {"today": today},
    )).scalar_one()

    unique_ips = (await db.execute(
        sa_text("SELECT COUNT(DISTINCT source_ip) FROM events WHERE timestamp >= :ago"),
        {"ago": ago_24h},
    )).scalar_one()

    return {
        "protocols":      protocols,
        "sessions_today": int(sessions_today),
        "unique_ips_24h": int(unique_ips),
    }


@router.get("/export/json")
async def export_sessions_json(
    request: Request,
    severity: str | None = Query(None),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> StreamingResponse:
    sessions, _ = await models.Session.list_filtered(db, severity=severity, limit=10000)
    data = json.dumps([_session_summary(s) for s in sessions], default=str, indent=2)

    await write_audit(db, user, "export_sessions",
                      detail={"format": "json", "row_count": len(sessions), "severity_filter": severity},
                      source_ip=request.client.host if request.client else None)

    return StreamingResponse(
        iter([data]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=sessions.json"},
    )


@router.get("/export/csv")
async def export_sessions_csv(
    request: Request,
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

    await write_audit(db, user, "export_sessions",
                      detail={"row_count": len(sessions), "severity_filter": severity},
                      source_ip=request.client.host if request.client else None)

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


@router.patch("/{session_id}/triage")
async def triage_session(
    session_id: str,
    payload: TriageRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    if payload.triage_status not in _VALID_TRIAGE:
        raise HTTPException(status_code=400, detail={"error": "INVALID_TRIAGE_STATUS"})
    from sqlalchemy import select
    result = await db.execute(select(models.Session).where(models.Session.id == session_id))
    s = result.scalar_one_or_none()
    if s is None:
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND"})
    s.triage_status = payload.triage_status
    if payload.triage_note is not None:
        s.triage_note = payload.triage_note[:500]
    await db.commit()
    await write_audit(db, user, "triage_session",
                      target_type="session", target_id=session_id,
                      detail={"triage_status": payload.triage_status},
                      source_ip=request.client.host if request.client else None)
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


@router.get("/{session_id}/export/stix")
async def export_session_stix(
    session_id: str,
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> StreamingResponse:
    """Export a STIX 2.1 bundle for all IOCs in the session."""
    from sqlalchemy import select
    result = await db.execute(select(models.Session).where(models.Session.id == session_id))
    sess = result.scalar_one_or_none()
    if not sess:
        raise HTTPException(404, {"error": "NOT_FOUND"})

    iocs = await models.IOC.list_for_session(db, session_id)
    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    started = (sess.started_at or now_iso)

    stix_objects = []
    for ioc in iocs:
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

        stix_objects.append({
            "type":          "indicator",
            "spec_version":  "2.1",
            "id":            f"indicator--{uuid_mod.uuid4()}",
            "created":       now_iso,
            "modified":      now_iso,
            "name":          f"OTrap: {ioc.ioc_type} IOC from session {session_id[:8]}",
            "description":   ioc.context or f"Observed {ioc.ioc_type}: {ioc.value}",
            "pattern":       pattern,
            "pattern_type":  "stix",
            "valid_from":    started if started.endswith("Z") else started.replace("+00:00", "Z"),
            "confidence":    ioc.confidence or 75,
            "labels":        ["malicious-activity"],
        })

    bundle = {
        "type":         "bundle",
        "id":           f"bundle--{uuid_mod.uuid4()}",
        "spec_version": "2.1",
        "objects":      stix_objects,
    }

    await write_audit(db, user, "export_sessions",
                      detail={"format": "stix", "session_id": session_id, "ioc_count": len(stix_objects)},
                      source_ip=request.client.host if request.client else None)

    return StreamingResponse(
        iter([json.dumps(bundle, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=session-{session_id[:8]}-stix.json"},
    )


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
                "metadata":      e.event_metadata or {},
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
        "triage_status":      getattr(s, "triage_status", None) or "new",
        "mitre_techniques":   [
            {**t, "description": _MITRE_DESC.get(t.get("technique_id", ""), "")}
            for t in (s.mitre_techniques or [])
        ],
    }


def _session_detail(s: models.Session) -> dict:
    d = _session_summary(s)
    d.update({
        "sensor_id":    str(s.sensor_id) if s.sensor_id else None,
        "source_port":  s.source_port,
        "metadata":     s.session_metadata or {},
        "closed_at":    s.closed_at,
        "triage_note":  getattr(s, "triage_note", None),
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
