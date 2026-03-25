"""
manager/notifications/smtp_sender.py — SMTP alert delivery with cooldown/dedup.
"""

from __future__ import annotations

import logging
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from manager.db import models
from manager.security.hashing import decrypt_secret

logger = logging.getLogger("otrap.smtp")

SEVERITY_ORDER = {"noise": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


async def maybe_send_smtp(db, ev: dict, session: models.Session) -> None:
    cfg = await models.SMTPConfig.get(db)
    if not cfg or not cfg.enabled or not cfg.host:
        return

    severity = ev.get("severity", "SEVERITY_NOISE").replace("SEVERITY_", "").lower()
    min_sev   = cfg.min_severity.lower()

    # CPU STOP always bypasses min_severity filter
    is_cpu_stop = ev.get("event_type") == "S7_CPU_STOP"
    if not is_cpu_stop and SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(min_sev, 0):
        return

    # Cooldown check (Redis key per source_ip)
    try:
        import redis.asyncio as aioredis, os
        r = aioredis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"))
        cooldown_key = f"smtp.cooldown:{session.source_ip}"
        if await r.exists(cooldown_key) and not is_cpu_stop:
            return
        await r.setex(cooldown_key, cfg.cooldown_seconds, "1")
        await r.aclose()
    except Exception as e:
        logger.warning("Cooldown check failed", extra={"error": str(e)})

    # Build and send email
    try:
        password = decrypt_secret(cfg.password_enc) if cfg.password_enc else None
        _send_alert_email(cfg, password, ev, session)
    except Exception as e:
        logger.error("SMTP send failed", exc_info=True)


def _send_alert_email(
    cfg: models.SMTPConfig, password: str | None,
    ev: dict, session: models.Session,
) -> None:
    severity  = ev.get("severity", "SEVERITY_NOISE").replace("SEVERITY_", "").lower()
    event_type = ev.get("event_type", "UNKNOWN")
    source_ip  = ev.get("source_ip", "unknown")
    is_cpu_stop = event_type == "S7_CPU_STOP"

    subject = f"[OTrap] {'🚨 CPU STOP EXPLOIT' if is_cpu_stop else severity.upper() + ' Alert'}: {event_type} from {source_ip}"

    html = f"""
    <html><body style="font-family:Arial,sans-serif;background:#f5f5f5;padding:20px;">
    <div style="background:white;border-radius:8px;padding:24px;max-width:600px;margin:0 auto;">
      <h2 style="color:{'#dc2626' if is_cpu_stop else '#ea580c'}">
        {'🚨 CRITICAL: CPU STOP Exploit Detected' if is_cpu_stop else f'OTrap Alert — {severity.title()}'}
      </h2>
      <table style="width:100%;border-collapse:collapse;">
        <tr><td style="padding:8px;color:#666;width:140px;">Event Type</td><td style="padding:8px;font-weight:bold;">{event_type}</td></tr>
        <tr style="background:#f9f9f9"><td style="padding:8px;color:#666;">Source IP</td><td style="padding:8px;">{source_ip}</td></tr>
        <tr><td style="padding:8px;color:#666;">Severity</td><td style="padding:8px;">{severity.upper()}</td></tr>
        <tr style="background:#f9f9f9"><td style="padding:8px;color:#666;">Protocol</td><td style="padding:8px;">{ev.get('protocol','')}</td></tr>
        <tr><td style="padding:8px;color:#666;">Session ID</td><td style="padding:8px;font-size:12px;">{str(session.id)}</td></tr>
        <tr style="background:#f9f9f9"><td style="padding:8px;color:#666;">Summary</td><td style="padding:8px;">{ev.get('raw_summary','')}</td></tr>
        <tr><td style="padding:8px;color:#666;">Timestamp</td><td style="padding:8px;">{ev.get('timestamp','')}</td></tr>
      </table>
      <p style="margin-top:20px;font-size:12px;color:#999;">
        Sent by OTrap Manager | Login to your console for full session details.
      </p>
    </div></body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = cfg.from_address
    msg["To"]      = ", ".join(cfg.to_addresses)
    msg.attach(MIMEText(html, "html"))

    if cfg.use_tls and not cfg.use_starttls:
        ctx = ssl.create_default_context()
        with smtplib.SMTP_SSL(cfg.host, cfg.port, context=ctx) as srv:
            if password:
                srv.login(cfg.username, password)
            srv.sendmail(cfg.from_address, cfg.to_addresses, msg.as_string())
    else:
        with smtplib.SMTP(cfg.host, cfg.port) as srv:
            if cfg.use_starttls:
                srv.starttls()
            if password:
                srv.login(cfg.username, password)
            srv.sendmail(cfg.from_address, cfg.to_addresses, msg.as_string())
