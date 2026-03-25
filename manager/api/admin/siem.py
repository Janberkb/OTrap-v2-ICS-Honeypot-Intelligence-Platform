"""
manager/api/admin/siem.py — SIEM configuration, test, and delivery log.
"""

from __future__ import annotations

import json
import logging

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import require_admin, require_reauth
from manager.security.hashing import encrypt_secret, decrypt_secret
from manager.security.audit import write_audit

router = APIRouter(prefix="/siem", tags=["admin-siem"])
logger = logging.getLogger("otrap.siem")


class SIEMConfigRequest(BaseModel):
    siem_type: str = "splunk_hec"    # splunk_hec | webhook
    url: str
    token: str | None = None         # None = keep existing
    min_severity: str = "medium"
    enabled: bool = True


@router.get("")
async def get_siem(db=Depends(get_db), user=Depends(require_admin)) -> dict:
    cfg = await models.SIEMConfig.get(db)
    if not cfg:
        return {"configured": False}
    return {
        "configured":   True,
        "siem_type":    cfg.siem_type,
        "url":          cfg.url,
        "min_severity": cfg.min_severity,
        "enabled":      cfg.enabled,
        # token_enc is NEVER returned
    }


@router.put("")
async def update_siem(
    payload: SIEMConfigRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_reauth),
) -> dict:
    kwargs = payload.model_dump(exclude={"token"})

    if payload.token:
        kwargs["token_enc"] = encrypt_secret(payload.token)
    elif payload.token is None:
        existing = await models.SIEMConfig.get(db)
        if existing and existing.token_enc:
            kwargs["token_enc"] = existing.token_enc

    await models.SIEMConfig.upsert(db, **kwargs)
    await db.commit()

    await write_audit(db, user, "update_siem_config",
                       source_ip=request.client.host if request.client else None)
    return {"ok": True}


@router.post("/test")
async def test_siem(
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    cfg = await models.SIEMConfig.get(db)
    if not cfg or not cfg.url:
        raise HTTPException(status_code=400, detail={"error": "SIEM_NOT_CONFIGURED"})

    token = None
    if cfg.token_enc:
        try:
            token = decrypt_secret(cfg.token_enc)
        except Exception:
            raise HTTPException(status_code=500, detail={"error": "SIEM_DECRYPT_FAILED"})

    test_payload = _build_test_event()
    try:
        status_code = await _deliver(cfg.siem_type, cfg.url, token, test_payload)

        log = models.SIEMDeliveryLog(
            siem_type=cfg.siem_type,
            status="success" if status_code < 400 else "failed",
            http_status=status_code,
            payload_preview=test_payload,
        )
        db.add(log)
        await db.commit()

        await write_audit(db, user, "test_siem",
                          detail={"siem_type": cfg.siem_type, "http_status": status_code,
                                  "result": "success" if status_code < 400 else "failed"})
        return {"ok": status_code < 400, "http_status": status_code}
    except Exception as e:
        log = models.SIEMDeliveryLog(
            siem_type=cfg.siem_type,
            status="failed",
            error_detail=str(e),
            payload_preview=test_payload,
        )
        db.add(log)
        await db.commit()
        await write_audit(db, user, "test_siem",
                          detail={"siem_type": cfg.siem_type, "result": "failed", "error": str(e)})
        raise HTTPException(status_code=400, detail={"error": "SIEM_DELIVERY_FAILED", "detail": str(e)})


@router.get("/delivery-log")
async def get_delivery_log(
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    logs = await models.SIEMDeliveryLog.list_recent(db)
    return {"items": [
        {
            "id":            str(l.id),
            "siem_type":     l.siem_type,
            "status":        l.status,
            "http_status":   l.http_status,
            "error_detail":  l.error_detail,
            "delivered_at":  l.delivered_at,
        }
        for l in logs
    ]}


async def _deliver(siem_type: str, url: str, token: str | None, payload: dict) -> int:
    headers = {"Content-Type": "application/json"}
    if token:
        if siem_type == "splunk_hec":
            headers["Authorization"] = f"Splunk {token}"
        else:
            headers["Authorization"] = f"Bearer {token}"

    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(url, headers=headers, content=json.dumps(payload))
        return r.status_code


def _build_test_event() -> dict:
    from datetime import datetime, timezone
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "kind":     "alert",
            "category": ["intrusion_detection"],
            "type":     ["indicator"],
            "dataset":  "otrap.honeypot",
            "severity": 1,
        },
        "source": {"ip": "192.0.2.1", "port": 12345},
        "destination": {"port": 102},
        "network": {"protocol": "s7comm", "transport": "tcp"},
        "otrap": {
            "event_type":    "TEST_EVENT",
            "signal_tier":   "noise",
            "cpu_stop":      False,
        },
        "message": "OTrap SIEM test delivery",
    }
