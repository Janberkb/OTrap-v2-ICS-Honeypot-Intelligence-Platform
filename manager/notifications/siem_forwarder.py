"""
manager/notifications/siem_forwarder.py — SIEM delivery (Splunk HEC / Webhook / Syslog CEF).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import uuid
from datetime import datetime, timezone
from ipaddress import ip_address

import httpx
from manager.db import models
from manager.analyzer.ioc_extractor import extract_iocs
from manager.security.hashing import decrypt_secret

# Allow operators to opt-in to TLS verification for SIEM endpoints
# (default False because many enterprise SIEMs use internal/self-signed CAs)
_SIEM_TLS_VERIFY = os.environ.get("SIEM_TLS_VERIFY", "false").lower() in ("1", "true", "yes")

logger = logging.getLogger("otrap.siem")
SEVERITY_ORDER = {"noise": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NUM   = {"noise": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
# OTrap severity → CEF severity (0-10)
SEVERITY_CEF   = {"noise": 0, "low": 3, "medium": 5, "high": 7, "critical": 10}


async def maybe_forward_siem(db, ev: dict, session: models.Session, *, force: bool = False, redis=None) -> None:
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
            throttle_key = (
                f"siem.throttle:{ev.get('source_ip', '')}:{ev.get('protocol', '')}:"
                f"{ev.get('event_type', '')}:{severity}"
            )
            if redis is not None:
                # Use the app-level Redis connection (preferred)
                if await redis.exists(throttle_key):
                    return
                await redis.setex(throttle_key, 900, "1")
            else:
                # Fallback: create a short-lived connection
                import redis.asyncio as aioredis
                r = aioredis.from_url(os.environ.get("REDIS_URL", "redis://redis:6379/0"))
                try:
                    if await r.exists(throttle_key):
                        return
                    await r.setex(throttle_key, 900, "1")
                finally:
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
        # Run blocking UDP socket in thread pool to avoid blocking the event loop
        return await asyncio.get_event_loop().run_in_executor(None, _deliver_syslog_cef, url, payload)

    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Splunk {token}" if siem_type == "splunk_hec" else f"Bearer {token}"

    # Splunk HEC wraps in {"event": ...}
    body = json.dumps({"event": payload} if siem_type == "splunk_hec" else payload)

    async with httpx.AsyncClient(timeout=10.0, verify=_SIEM_TLS_VERIFY) as client:
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
    event_family = ot.get("event_family", "")
    mitre_technique = ot.get("mitre_technique", "")
    metadata = ot.get("metadata", {}) or {}

    # CEF severity (0-10)
    cef_sev = {1: 0, 2: 3, 3: 5, 4: 7, 5: 10}.get(sev_num, 5)

    ext = f"src={src}"
    if dpt:
        ext += f" dpt={dpt}"
    if proto:
        ext += f" proto={proto}"
    if session_id:
        ext += f" cs1={session_id} cs1Label=sessionId"
    if event_family:
        ext += f" cs2={_cef_escape(event_family)} cs2Label=eventFamily"
    if mitre_technique:
        ext += f" cs3={_cef_escape(mitre_technique)} cs3Label=mitreTechnique"
    if metadata.get("path"):
        ext += f" request={_cef_escape(str(metadata['path'])[:256])}"
    if metadata.get("function_code"):
        ext += f" cs4={_cef_escape(str(metadata['function_code'])[:64])} cs4Label=functionCode"
    if metadata.get("start_address"):
        ext += f" cn1={_cef_escape(str(metadata['start_address'])[:64])} cn1Label=startAddress"
    if metadata.get("write_value"):
        ext += f" cs5={_cef_escape(str(metadata['write_value'])[:128])} cs5Label=writeValue"
    ext += f" msg={msg}"

    safe_event_type = _cef_escape(event_type)
    return f"CEF:0|OTrap|Honeypot Manager|1.0|{safe_event_type}|{safe_event_type}|{cef_sev}|{ext}"


def _build_ecs_payload(ev: dict, session: models.Session) -> dict:
    """Build ECS-compatible event payload."""
    severity     = ev.get("severity", "SEVERITY_NOISE").replace("SEVERITY_", "").lower()
    event_type   = ev.get("event_type", "UNKNOWN")
    source_ip    = ev.get("source_ip", "")
    is_cpu_stop  = event_type == "S7_CPU_STOP"
    metadata     = ev.get("metadata", {}) if isinstance(ev.get("metadata", {}), dict) else {}
    iocs         = _serialize_iocs(ev)
    artifacts    = _serialize_artifacts(ev)

    from manager.analyzer.mitre_ics import MITRE_ICS_MAPPING
    mitre = MITRE_ICS_MAPPING.get(event_type, {})

    payload = {
        "@timestamp": ev.get("timestamp"),
        "event": {
            "kind":     "alert",
            "category": ["intrusion_detection"],
            "type":     ["indicator"],
            "severity": SEVERITY_NUM.get(severity, 1),
            "dataset":  "otrap.honeypot",
            "id":       ev.get("event_id", str(uuid.uuid4())),
            "action":   event_type,
            "reason":   ev.get("raw_summary", ""),
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
            "session_severity":  getattr(session, "severity", None),
            "attack_phase":      getattr(session, "attack_phase", None),
            "iocs":              iocs,
            "artifacts":         artifacts,
            "ioc_count":         len(iocs),
            "artifact_count":    len(artifacts),
            "metadata":          _sanitize_obj(metadata),
            "sensor_id":         ev.get("sensor_id"),
        },
        "message": ev.get("raw_summary", f"OTrap: {event_type} from {source_ip}"),
    }

    threat = _build_threat(session, mitre)
    if threat:
        payload["threat"] = threat

    user_name = metadata.get("username")
    if isinstance(user_name, str) and user_name:
        payload["user"] = {"name": user_name[:128]}

    url_path = metadata.get("path")
    url_query = metadata.get("query")
    host = metadata.get("host")
    if isinstance(url_path, str) and url_path:
        payload["url"] = {"path": url_path[:512]}
        if isinstance(url_query, str) and url_query:
            payload["url"]["query"] = url_query[:1024]
        if isinstance(host, str) and host and "." in host and not _looks_like_ip(host):
            payload["url"]["domain"] = host[:255]

    method = metadata.get("method")
    if isinstance(method, str) and method:
        payload["http"] = {"request": {"method": method[:16]}}

    user_agent = metadata.get("user_agent")
    if isinstance(user_agent, str) and user_agent:
        payload["user_agent"] = {"original": user_agent[:512]}

    related_ips = {source_ip}
    for item in iocs:
        if item.get("type") == "ip" and item.get("value"):
            related_ips.add(item["value"])
    payload["related"] = {"ip": sorted(ip for ip in related_ips if ip)}

    return payload


def _build_threat(session: models.Session, mitre: dict) -> dict:
    techniques = []
    seen_ids = set()

    session_techniques = getattr(session, "mitre_techniques", None) or []
    for item in session_techniques:
        if not isinstance(item, dict):
            continue
        technique_id = item.get("technique_id")
        technique_name = item.get("technique_name")
        tactic_name = item.get("tactic")
        if not technique_id or technique_id in seen_ids:
            continue
        seen_ids.add(technique_id)
        techniques.append({
            "id": technique_id,
            "name": technique_name,
            "reference": f"https://attack.mitre.org/techniques/ics/{technique_id}/",
            "tactic": {"name": tactic_name} if tactic_name else None,
        })

    if not techniques and mitre.get("technique_id"):
        techniques.append({
            "id": mitre.get("technique_id"),
            "name": mitre.get("technique_name"),
            "reference": f"https://attack.mitre.org/techniques/ics/{mitre.get('technique_id')}/",
            "tactic": {"name": mitre.get("tactic")} if mitre.get("tactic") else None,
        })

    if not techniques:
        return {}

    payload = {
        "framework": "MITRE ATT&CK for ICS",
        "technique": [],
    }

    tactic_names = []
    for technique in techniques:
        tactic = technique.pop("tactic", None)
        if tactic and tactic.get("name") and tactic["name"] not in tactic_names:
            tactic_names.append(tactic["name"])
        payload["technique"].append(technique)

    if tactic_names:
        payload["tactic"] = [{"name": name} for name in tactic_names]
    return payload


def _serialize_iocs(ev: dict) -> list[dict]:
    items = []
    seen = set()
    for ioc in extract_iocs(ev):
        ioc_type = str(ioc.get("type", "unknown"))[:64]
        value = _sanitize_indicator_value(ioc_type, ioc.get("value"))
        if not value:
            continue
        key = (ioc_type, value)
        if key in seen:
            continue
        seen.add(key)
        item = {"type": ioc_type, "value": value}
        context = ioc.get("context")
        if context:
            item["context"] = str(context)[:256]
        confidence = ioc.get("confidence")
        if confidence is not None:
            item["confidence"] = round(float(confidence), 2)
        items.append(item)
    return items[:20]


def _serialize_artifacts(ev: dict) -> list[dict]:
    items = []
    seen = set()
    for artifact in ev.get("artifacts", []) or []:
        if not isinstance(artifact, dict):
            continue
        artifact_type = str(artifact.get("artifact_type", "unknown"))[:64]
        value = _sanitize_indicator_value(artifact_type, artifact.get("value"))
        if not value:
            continue
        key = (artifact_type, value)
        if key in seen:
            continue
        seen.add(key)
        item = {"type": artifact_type, "value": value}
        encoding = artifact.get("encoding")
        if encoding:
            item["encoding"] = str(encoding)[:32]
        items.append(item)
    return items[:20]


def _sanitize_indicator_value(kind: str, value) -> str:
    if value is None:
        return ""
    if kind == "password":
        return "********"
    if kind in {"username", "user"}:
        return str(value)[:128]
    return str(value)[:512]


def _sanitize_obj(value):
    if value is None:
        return None
    if isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value[:512]
    if isinstance(value, list):
        return [_sanitize_obj(item) for item in value[:25]]
    if isinstance(value, dict):
        out = {}
        for key, item in list(value.items())[:25]:
            out[str(key)[:64]] = _sanitize_obj(item)
        return out
    return str(value)[:512]


def _looks_like_ip(value: str) -> bool:
    try:
        ip_address(value.split(":", 1)[0])
        return True
    except ValueError:
        return False


def _cef_escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("|", "\\|").replace("=", "\\=").replace("\n", " ")


def _event_family(event_type: str) -> str:
    if "CPU_STOP" in event_type or "DOWNLOAD" in event_type:
        return "ics_exploit"
    if event_type.startswith("S7_"):
        return "ics_recon"
    if event_type.startswith("MODBUS_"):
        return "ics_modbus"
    return "web_attack"
