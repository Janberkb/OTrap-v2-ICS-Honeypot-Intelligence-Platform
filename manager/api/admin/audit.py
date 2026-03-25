"""
manager/api/admin/audit.py — Audit log viewer and retention management (superadmin only).
"""

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import require_admin, require_reauth
from manager.security.audit import write_audit

router = APIRouter(prefix="/audit", tags=["admin-audit"])


@router.get("")
async def get_audit_log(
    limit:    int = Query(100, ge=1, le=1000),
    offset:   int = Query(0, ge=0),
    username: str | None = Query(None),
    action:   str | None = Query(None),
    from_dt:  str | None = Query(None),
    to_dt:    str | None = Query(None),
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    logs = await models.AuditLog.list_recent(
        db, limit=limit, offset=offset,
        username=username, action=action,
        from_dt=from_dt, to_dt=to_dt,
    )
    return {"items": [
        {
            "id":          str(l.id),
            "username":    l.username,
            "action":      l.action,
            "target_type": l.target_type,
            "target_id":   l.target_id,
            "detail":      l.detail,
            "source_ip":   l.source_ip,
            "timestamp":   l.timestamp,
        }
        for l in logs
    ]}


@router.delete("")
async def purge_audit_log(
    before: str = Query(..., description="ISO-8601 datetime — delete all entries before this point"),
    request: Request = None,
    db=Depends(get_db),
    user=Depends(require_reauth),
) -> dict:
    """Delete all audit log entries with timestamp < before. Requires recent reauth."""
    deleted = await models.AuditLog.purge_before(db, before)
    await write_audit(db, user, "purge_audit_log",
                      detail={"before": before, "deleted": deleted},
                      source_ip=request.client.host if request and request.client else None)
    await db.commit()
    return {"deleted": deleted}


@router.get("/retention")
async def get_retention(
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    cfg = await models.AppConfig.get(db)
    return {"audit_retention_days": cfg.audit_retention_days}


class RetentionRequest(BaseModel):
    audit_retention_days: int  # 0 = disabled


@router.put("/retention")
async def set_retention(
    payload: RetentionRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    if payload.audit_retention_days < 0:
        raise HTTPException(status_code=400, detail="audit_retention_days must be >= 0")
    await models.AppConfig.upsert(db, audit_retention_days=payload.audit_retention_days)
    await write_audit(db, user, "update_audit_retention",
                      detail={"days": payload.audit_retention_days},
                      source_ip=request.client.host if request.client else None)
    await db.commit()
    return {"ok": True, "audit_retention_days": payload.audit_retention_days}
