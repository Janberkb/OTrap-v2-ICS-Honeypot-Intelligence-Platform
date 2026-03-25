"""
manager/api/admin/audit.py — Audit log viewer (superadmin only).
"""

from fastapi import APIRouter, Depends, Query
from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import require_admin

router = APIRouter(prefix="/audit", tags=["admin-audit"])


@router.get("")
async def get_audit_log(
    limit:  int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    logs = await models.AuditLog.list_recent(db, limit=limit, offset=offset)
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
