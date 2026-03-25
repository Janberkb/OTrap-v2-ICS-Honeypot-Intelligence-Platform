"""
manager/api/admin/smtp.py — SMTP configuration and test delivery.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import require_admin, require_reauth
from manager.security.hashing import encrypt_secret, decrypt_secret
from manager.security.audit import write_audit

router = APIRouter(prefix="/smtp", tags=["admin-smtp"])
logger = logging.getLogger("otrap.smtp")


class SMTPConfigRequest(BaseModel):
    host: str
    port: int = 587
    username: str
    password: str | None = None      # None = keep existing
    from_address: str
    to_addresses: list[str]
    use_tls: bool = True
    use_starttls: bool = False
    min_severity: str = "high"
    health_alerts: bool = True
    cooldown_seconds: int = 300
    enabled: bool = True


@router.get("")
async def get_smtp(db=Depends(get_db), user=Depends(require_admin)) -> dict:
    cfg = await models.SMTPConfig.get(db)
    if not cfg:
        return {"configured": False}
    return {
        "configured":      True,
        "host":            cfg.host,
        "port":            cfg.port,
        "username":        cfg.username,
        "from_address":    cfg.from_address,
        "to_addresses":    cfg.to_addresses,
        "use_tls":         cfg.use_tls,
        "use_starttls":    cfg.use_starttls,
        "min_severity":    cfg.min_severity,
        "health_alerts":   cfg.health_alerts,
        "cooldown_seconds": cfg.cooldown_seconds,
        "enabled":         cfg.enabled,
        # password_enc is NEVER returned to the UI
    }


@router.put("")
async def update_smtp(
    payload: SMTPConfigRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_reauth),    # Requires recent reauth (password in payload)
) -> dict:
    kwargs = payload.model_dump(exclude={"password"})

    if payload.password:
        kwargs["password_enc"] = encrypt_secret(payload.password)
    elif payload.password is None:
        # Keep existing password
        existing = await models.SMTPConfig.get(db)
        if existing and existing.password_enc:
            kwargs["password_enc"] = existing.password_enc

    await models.SMTPConfig.upsert(db, **kwargs)
    await db.commit()

    await write_audit(db, user, "update_smtp_config",
                       source_ip=request.client.host if request.client else None)
    return {"ok": True}


@router.post("/test")
async def test_smtp(
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    cfg = await models.SMTPConfig.get(db)
    if not cfg or not cfg.host:
        raise HTTPException(status_code=400, detail={"error": "SMTP_NOT_CONFIGURED"})

    password = None
    if cfg.password_enc:
        try:
            password = decrypt_secret(cfg.password_enc)
        except Exception:
            raise HTTPException(status_code=500, detail={"error": "SMTP_DECRYPT_FAILED"})

    try:
        _send_test_email(cfg, password)
        await write_audit(db, user, "test_smtp",
                          detail={"host": cfg.host, "result": "success"})
        return {"ok": True, "message": "Test email sent successfully"}
    except Exception as e:
        logger.error("SMTP test failed", exc_info=True)
        await write_audit(db, user, "test_smtp",
                          detail={"host": cfg.host, "result": "failed", "error": str(e)})
        raise HTTPException(status_code=400, detail={"error": "SMTP_SEND_FAILED", "detail": str(e)})


def _send_test_email(cfg: models.SMTPConfig, password: str | None) -> None:
    msg = MIMEMultipart("alternative")
    msg["Subject"] = "[OTrap] SMTP Test Notification"
    msg["From"]    = cfg.from_address
    msg["To"]      = ", ".join(cfg.to_addresses)

    body = MIMEText(
        "<h2>OTrap SMTP Test</h2>"
        "<p>This is a test notification from your OTrap Manager. "
        "If you received this, SMTP is configured correctly.</p>",
        "html",
    )
    msg.attach(body)

    if cfg.use_tls and not cfg.use_starttls:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(cfg.host, cfg.port, context=ctx) as server:
            if password:
                server.login(cfg.username, password)
            server.sendmail(cfg.from_address, cfg.to_addresses, msg.as_string())
    else:
        with smtplib.SMTP(cfg.host, cfg.port) as server:
            if cfg.use_starttls:
                server.starttls()
            if password:
                server.login(cfg.username, password)
            server.sendmail(cfg.from_address, cfg.to_addresses, msg.as_string())
