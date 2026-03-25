"""
manager/notifications/siem_forwarder.py — SIEM delivery (Splunk HEC / webhook).
"""

from __future__ import annotations

import json
import logging
import uuid

import httpx
from manager.db import models
from manager.security.hashing import decrypt_secret

logger = logging.getLogger("otrap.siem")
SEVERITY_ORDER = {"noise": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NUM   = {"noise": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}


async def maybe_forward_siem(db, ev: dict, session: models.Session) -> None:
    cfg = await models.SIEMConfig.get(db)
    if not cfg or not cfg.enabled or not cfg.url:
        return

    severity  = ev.get("severity", "SEVERITY_NOISE").replace("SEVERITY_", "").lower()
    min_sev   = cfg.min_severity.lower()
    is_cpu_stop = ev.get("event_type") == "S7_CPU_STOP"

    if not is_cpu_stop and SEVERITY_ORDER.get(severity, 0) < SEVERITY_ORDER.get(min_sev, 0):
        return

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
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Splunk {token}" if siem_type == "splunk_hec" else f"Bearer {token}"

    # Splunk HEC wraps in {"event": ...}
    body = json.dumps({"event": payload} if siem_type == "splunk_hec" else payload)

    async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
        r = await client.post(url, headers=headers, content=body)
        return r.status_code


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
