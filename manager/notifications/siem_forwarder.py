"""
manager/notifications/siem_forwarder.py — SIEM delivery (Splunk HEC / Webhook / Syslog CEF).
"""

from __future__ import annotations

import json
import logging
import socket
import uuid
from datetime import datetime, timezone

import httpx
from manager.db import models
from manager.security.hashing import decrypt_secret

logger = logging.getLogger("otrap.siem")
SEVERITY_ORDER = {"noise": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NUM   = {"noise": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
# OTrap severity → CEF severity (0-10)
SEVERITY_CEF   = {"noise": 0, "low": 3, "medium": 5, "high": 7, "critical": 10}


async def maybe_forward_siem(db, ev: dict, session: models.Session, *, force: bool = False) -> None:
    cfg = await models.SIEMConfig.get(db)
    if not cfg or not cfg.enabled or not cfg.url:
        return

    severity  = ev.get("severity", "SEVERITY_NOISE").replace("SEVERITY_", "").lower()
    min_sev   = cfg.min_severity.lower()
    is_cpu_stop = ev.get("event_type") == "S7_CPU_STOP"

    # force=True (rule-triggered) bypasses severity filter
    if not is_cpu_stop and not force and SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(min_sev, 0):
        return

    # Rate-limit — skipped when force=True (rule-triggered) or CPU STOP
    if not force and not is_cpu_stop:
        try:
            import redis.asyncio as aioredis, os
            r = aioredis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"))
            throttle_key = f"siem.throttle:{ev.get('source_ip', '')}:{severity}"
            if await r.exists(throttle_key):
                await r.aclose()
                return
            await r.setex(throttle_key, 900, "1")
            await r.aclose()
        except Exception as e:
            logger.warning("SIEM throttle check failed: %s", e)

    token = None
    if cfg.token_enc:
        try:
            token = decrypt_secret(cfg.token_enc)
        except Exception as e:
            logger.error("SIEM token decrypt failed", extra={"error": str(e)})
            return

    payload = _build_ecs_payload(ev, session)
    try:
        status_code = await _deliver(cfg.siem_type, cfg.url, token, payload)
        log = models.SIEMDeliveryLog(
            session_id=session.id,
            siem_type=cfg.siem_type,
            status="success" if status_code < 400 else "failed",
            http_status=status_code,
            payload_preview={k: v for k, v in payload.items() if k != "otrap"},
        )
        db.add(log)
        await db.commit()
    except Exception as e:
        logger.error("SIEM delivery failed", exc_info=True)
        log = models.SIEMDeliveryLog(
            session_id=session.id,
            siem_type=cfg.siem_type,
            status="failed",
            error_detail=str(e),
        )
        db.add(log)
        await db.commit()


async def _deliver(siem_type: str, url: str, token: str | None, payload: dict) -> int:
    if siem_type == "syslog_cef":
        return _deliver_syslog_cef(url, payload)

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Splunk {token}" if siem_type == "splunk_hec" else f"Bearer {token}"

    # Splunk HEC wraps in {"event": ...}
    body = json.dumps({"event": payload} if siem_type == "splunk_hec" else payload)

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        r = await client.post(url, headers=headers, content=body)
        return r.status_code


def _deliver_syslog_cef(url: str, payload: dict) -> int:
    """Send a CEF-formatted event via UDP syslog. url format: host:port (default port 514)."""
    try:
        if ":" in url:
            host, port_str = url.rsplit(":", 1)
            port = int(port_str) if port_str.isdigit() else 514
        else:
            host, port = url, 514

        cef_msg = _build_cef(payload)
        # RFC 3164 syslog header: <PRI>TIMESTAMP HOSTNAME MSG
        ts  = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")
        msg = f"<134>{ts} otrap-manager {cef_msg}\n"

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5.0)
        sock.sendto(msg.encode("utf-8"), (host, port))
        sock.close()
        return 200
    except Exception as e:
        logger.error("Syslog/CEF delivery failed: %s", e)
        raise


def _build_cef(payload: dict) -> str:
    src      = payload.get("source", {}).get("ip", "")
    ot       = payload.get("otrap", {}) or {}
    event_type = ot.get("event_type", "UNKNOWN")
    sev_num  = payload.get("event", {}).get("severity", 1)
    dpt      = payload.get("destination", {}).get("port")
    proto    = payload.get("network", {}).get("protocol", "")
    msg      = (payload.get("message", "") or "")[:200].replace("|", "/").replace("=", ":")
    session_id = ot.get("session_id", "")

    # CEF severity (0-10)
    cef_sev = {1: 0, 2: 3, 3: 5, 4: 7, 5: 10}.get(sev_num, 5)

    ext = f"src={src}"
    if dpt:
        ext += f" dpt={dpt}"
    if proto:
        ext += f" proto={proto}"
    if session_id:
        ext += f" cs1={session_id} cs1Label=sessionId"
    ext += f" msg={msg}"

    return f"CEF:0|OTrap|Honeypot Manager|1.0|{event_type}|{event_type}|{cef_sev}|{ext}"


def _build_ecs_payload(ev: dict, session: models.Session) -> dict:
    """Build ECS-compatible event payload."""
    severity     = ev.get("severity", "SEVERITY_NOISE").replace("SEVERITY_", "").lower()
    event_type   = ev.get("event_type", "UNKNOWN")
    source_ip    = ev.get("source_ip", "")
    is_cpu_stop  = event_type == "S7_CPU_STOP"

    from manager.analyzer.mitre_ics import MITRE_ICS_MAPPING
    mitre = MITRE_ICS_MAPPING.get(event_type, {})

    return {
        "@timestamp": ev.get("timestamp"),
        "event": {
            "kind":     "alert",
            "category": ["intrusion_detection"],
            "type":     ["indicator"],
            "severity": SEVERITY_NUM.get(severity, 1),
            "dataset":  "otrap.honeypot",
            "id":       ev.get("event_id", str(uuid.uuid4())),
        },
        "source": {
            "ip":   source_ip,
            "port": ev.get("source_port"),
        },
        "destination": {"port": ev.get("dst_port")},
        "network": {
            "protocol":  ev.get("protocol", "").lower().replace("protocol_", ""),
            "transport": "tcp",
        },
        "otrap": {
            "session_id":        str(session.id),
            "event_type":        event_type,
            "event_family":      _event_family(event_type),
            "signal_tier":       session.signal_tier,
            "cpu_stop_occurred": is_cpu_stop,
            "mitre_technique":   mitre.get("technique_id"),
            "mitre_tactic":      mitre.get("tactic"),
            "iocs":              [{"type": "ip", "value": source_ip}] if is_cpu_stop else [],
            "sensor_id":         ev.get("sensor_id"),
        },
        "message": ev.get("raw_summary", f"OTrap: {event_type} from {source_ip}"),
    }


def _event_family(event_type: str) -> str:
    if "CPU_STOP" in event_type or "DOWNLOAD" in event_type:
        return "ics_exploit"
    if event_type.startswith("S7_"):
        return "ics_recon"
    if event_type.startswith("MODBUS_"):
        return "ics_modbus"
    return "web_attack"
