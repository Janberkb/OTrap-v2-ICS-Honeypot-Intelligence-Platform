"""
manager/api/iocs.py — Global IOC list with dedup, filtering, and STIX export.
"""

from __future__ import annotations

import json
import uuid as uuid_mod
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user

router = APIRouter(prefix="/iocs", tags=["iocs"])

_IOC_TYPES = {"ip", "domain", "url", "hash_md5", "hash_sha256"}


@router.get("")
async def list_iocs(
    ioc_type:       str | None = Query(None),
    search:         str | None = Query(None),
    min_confidence: float | None = Query(None, ge=0.0, le=1.0),
    limit:          int = Query(100, ge=1, le=1000),
    offset:         int = Query(0, ge=0),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    """Return deduplicated IOCs across all sessions.

    Dedup key: (ioc_type, value) — keeps the row with the highest confidence
    and aggregates session_count.
    """
    base = (
        select(
            models.IOC.ioc_type,
            models.IOC.value,
            func.max(models.IOC.confidence).label("confidence"),
            func.min(models.IOC.first_seen_at).label("first_seen_at"),
            func.max(models.IOC.last_seen_at).label("last_seen_at"),
            func.count(models.IOC.session_id.distinct()).label("session_count"),
        )
        .group_by(models.IOC.ioc_type, models.IOC.value)
    )

    if ioc_type:
        base = base.where(models.IOC.ioc_type == ioc_type)
    if search:
        base = base.where(models.IOC.value.ilike(f"%{search}%"))
    if min_confidence is not None:
        base = base.having(func.max(models.IOC.confidence) >= min_confidence)

    # Total (count over the grouped subquery)
    total = (await db.execute(select(func.count()).select_from(base.subquery()))).scalar_one()

    # Paginated rows ordered by most-recently-seen first
    rows = (
        await db.execute(
            base.order_by(func.max(models.IOC.last_seen_at).desc())
                .offset(offset)
                .limit(limit)
        )
    ).all()

    return {
        "total":  total,
        "offset": offset,
        "limit":  limit,
        "items": [
            {
                "ioc_type":      r.ioc_type,
                "value":         r.value,
                "confidence":    round(r.confidence, 3),
                "session_count": r.session_count,
                "first_seen_at": r.first_seen_at,
                "last_seen_at":  r.last_seen_at,
            }
            for r in rows
        ],
    }


@router.get("/export/stix")
async def export_iocs_stix(
    ioc_type: str | None = Query(None),
    search:   str | None = Query(None),
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> StreamingResponse:
    """Export all (optionally filtered) IOCs as a STIX 2.1 bundle."""
    q = (
        select(
            models.IOC.ioc_type,
            models.IOC.value,
            func.max(models.IOC.confidence).label("confidence"),
            func.min(models.IOC.first_seen_at).label("first_seen_at"),
        )
        .group_by(models.IOC.ioc_type, models.IOC.value)
    )
    if ioc_type:
        q = q.where(models.IOC.ioc_type == ioc_type)
    if search:
        q = q.where(models.IOC.value.ilike(f"%{search}%"))
    q = q.order_by(func.max(models.IOC.last_seen_at).desc()).limit(10_000)

    rows = (await db.execute(q)).all()

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    stix_objects = []
    for r in rows:
        t = r.ioc_type
        v = r.value
        if t == "ip":
            pattern = f"[ipv4-addr:value = '{v}']"
        elif t == "domain":
            pattern = f"[domain-name:value = '{v}']"
        elif t == "url":
            pattern = f"[url:value = '{v}']"
        elif t == "hash_md5":
            pattern = f"[file:hashes.MD5 = '{v}']"
        elif t == "hash_sha256":
            pattern = f"[file:hashes.'SHA-256' = '{v}']"
        else:
            pattern = f"[artifact:payload_bin = '{v}']"

        valid_from = r.first_seen_at or now_iso
        if not valid_from.endswith("Z"):
            valid_from = valid_from.replace("+00:00", "Z") if "+00:00" in valid_from else valid_from + "Z"

        stix_objects.append({
            "type":         "indicator",
            "spec_version": "2.1",
            "id":           f"indicator--{uuid_mod.uuid4()}",
            "created":      now_iso,
            "modified":     now_iso,
            "name":         f"OTrap: {t} IOC",
            "description":  f"Observed {t}: {v}",
            "pattern":      pattern,
            "pattern_type": "stix",
            "valid_from":   valid_from,
            "confidence":   int((r.confidence or 0.75) * 100),
            "labels":       ["malicious-activity"],
        })

    bundle = {
        "type":         "bundle",
        "id":           f"bundle--{uuid_mod.uuid4()}",
        "spec_version": "2.1",
        "objects":      stix_objects,
    }

    return StreamingResponse(
        iter([json.dumps(bundle, indent=2)]),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=otrap-iocs-stix.json"},
    )
