"""
manager/api/admin/alert_rules.py — Alert rule CRUD endpoints.

Rules let superadmins define fine-grained conditions for triggering
notifications independently of the global severity threshold.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from sqlalchemy import select, delete as sa_delete

from manager.api.auth import require_admin
from manager.db import models
from manager.db.engine import get_db
from manager.security.audit import write_audit

router = APIRouter(prefix="/alert-rules", tags=["admin-alert-rules"])

VALID_FIELDS    = {"severity", "protocol", "event_type", "source_ip", "sensor_id"}
VALID_OPERATORS = {"eq", "neq", "gte", "lte", "in", "not_in", "contains"}
VALID_TRIAGES   = {None, "new", "investigating", "reviewed", "false_positive", "escalated"}


class ConditionItem(BaseModel):
    field:    str
    operator: str
    value:    Any


class AlertRuleRequest(BaseModel):
    name:           str
    description:    str | None = None
    enabled:        bool = True
    conditions:     list[ConditionItem] = []
    notify_smtp:    bool = False
    notify_siem:    bool = False
    auto_triage:    str | None = None
    window_seconds: int | None = None   # correlation window length in seconds
    threshold:      int | None = None   # minimum matching events to fire


def _validate(payload: AlertRuleRequest) -> None:
    if not payload.name.strip():
        raise HTTPException(status_code=400, detail="Rule name is required")
    if payload.auto_triage not in VALID_TRIAGES:
        raise HTTPException(status_code=400, detail=f"Invalid auto_triage value: {payload.auto_triage}")
    if (payload.window_seconds is not None) != (payload.threshold is not None):
        raise HTTPException(status_code=400, detail="window_seconds and threshold must both be set or both be null")
    if payload.window_seconds is not None and payload.window_seconds < 10:
        raise HTTPException(status_code=400, detail="window_seconds must be at least 10")
    if payload.threshold is not None and payload.threshold < 2:
        raise HTTPException(status_code=400, detail="threshold must be at least 2")
    for cond in payload.conditions:
        if cond.field not in VALID_FIELDS:
            raise HTTPException(status_code=400, detail=f"Invalid condition field: {cond.field}")
        if cond.operator not in VALID_OPERATORS:
            raise HTTPException(status_code=400, detail=f"Invalid condition operator: {cond.operator}")
        if cond.value is None or cond.value == "":
            raise HTTPException(status_code=400, detail="Condition value must not be empty")


def _serialize(rule: models.AlertRule) -> dict:
    return {
        "id":             str(rule.id),
        "name":           rule.name,
        "description":    rule.description,
        "enabled":        rule.enabled,
        "conditions":     rule.conditions or [],
        "notify_smtp":    rule.notify_smtp,
        "notify_siem":    rule.notify_siem,
        "auto_triage":    rule.auto_triage,
        "window_seconds": rule.window_seconds,
        "threshold":      rule.threshold,
        "created_at":     rule.created_at,
        "updated_at":     rule.updated_at,
    }


@router.get("")
async def list_alert_rules(db=Depends(get_db), user=Depends(require_admin)) -> dict:
    rules = await models.AlertRule.list_all(db)
    return {"items": [_serialize(r) for r in rules]}


@router.post("", status_code=201)
async def create_alert_rule(
    payload: AlertRuleRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    _validate(payload)
    rule = models.AlertRule(
        name=payload.name.strip(),
        description=payload.description,
        enabled=payload.enabled,
        conditions=[c.model_dump() for c in payload.conditions],
        notify_smtp=payload.notify_smtp,
        notify_siem=payload.notify_siem,
        auto_triage=payload.auto_triage or None,
        window_seconds=payload.window_seconds,
        threshold=payload.threshold,
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    await write_audit(db, user, "create_alert_rule",
                      detail={"name": rule.name},
                      source_ip=request.client.host if request.client else None)
    return _serialize(rule)


@router.patch("/{rule_id}")
async def update_alert_rule(
    rule_id: str,
    payload: AlertRuleRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    _validate(payload)
    try:
        rid = uuid.UUID(rule_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid rule ID")

    result = await db.execute(select(models.AlertRule).where(models.AlertRule.id == rid))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    rule.name           = payload.name.strip()
    rule.description    = payload.description
    rule.enabled        = payload.enabled
    rule.conditions     = [c.model_dump() for c in payload.conditions]
    rule.notify_smtp    = payload.notify_smtp
    rule.notify_siem    = payload.notify_siem
    rule.auto_triage    = payload.auto_triage or None
    rule.window_seconds = payload.window_seconds
    rule.threshold      = payload.threshold
    rule.updated_at     = datetime.now(timezone.utc).isoformat()

    await db.commit()
    await write_audit(db, user, "update_alert_rule",
                      detail={"name": rule.name},
                      source_ip=request.client.host if request.client else None)
    return _serialize(rule)


@router.delete("/{rule_id}")
async def delete_alert_rule(
    rule_id: str,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> Response:
    try:
        rid = uuid.UUID(rule_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid rule ID")

    result = await db.execute(select(models.AlertRule).where(models.AlertRule.id == rid))
    rule = result.scalar_one_or_none()
    if not rule:
        raise HTTPException(status_code=404, detail="Alert rule not found")

    name = rule.name
    await db.execute(sa_delete(models.AlertRule).where(models.AlertRule.id == rid))
    await db.commit()
    await write_audit(db, user, "delete_alert_rule",
                      detail={"name": name},
                      source_ip=request.client.host if request.client else None)
    return Response(status_code=204)
