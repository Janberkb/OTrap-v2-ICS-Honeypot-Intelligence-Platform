"""
manager/security/audit.py — Audit log writer helper.
"""

from __future__ import annotations
from manager.db import models


async def write_audit(
    db,
    user: models.User | None,
    action: str,
    target_type: str | None = None,
    target_id: str | None = None,
    detail: dict | None = None,
    source_ip: str | None = None,
) -> None:
    await models.AuditLog.write(
        db,
        user_id=str(user.id) if user else None,
        username=user.username if user else None,
        action=action,
        target_type=target_type,
        target_id=target_id,
        detail=detail,
        source_ip=source_ip,
    )
    await db.commit()
