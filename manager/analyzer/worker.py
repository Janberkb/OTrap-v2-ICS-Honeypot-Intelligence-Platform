"""
manager/analyzer/worker.py — Async Redis consumer → Session/IOC analysis pipeline.

Consumes events from Redis pub/sub channel 'sensor.events',
groups them into sessions, assigns MITRE ATT&CK for ICS mappings,
extracts IOCs, and writes everything to Postgres.

Architecture note: This runs as a background asyncio task within the
Manager process. It is NOT a separate service (unlike the old design).
This simplifies deployment while keeping the pipeline async.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from manager.db import models
from manager.analyzer.mitre_ics import MITRE_ICS_MAPPING
from manager.analyzer.ioc_extractor import extract_iocs

logger = logging.getLogger("otrap.analyzer")

# Session grouping window: events from same source within this window
# are grouped into the same session.
SESSION_WINDOW_SECONDS = 300  # 5 minutes of inactivity closes a session

# Severity ordering (must be monotonically increasing)
SEVERITY_ORDER = {
    "SEVERITY_NOISE":    0,
    "SEVERITY_LOW":      1,
    "SEVERITY_MEDIUM":   2,
    "SEVERITY_HIGH":     3,
    "SEVERITY_CRITICAL": 4,
}

SEVERITY_LABEL = {
    "SEVERITY_NOISE":    "noise",
    "SEVERITY_LOW":      "low",
    "SEVERITY_MEDIUM":   "medium",
    "SEVERITY_HIGH":     "high",
    "SEVERITY_CRITICAL": "critical",
}

SIGNAL_TIER = {
    "noise":    "noise",
    "low":      "recon",
    "medium":   "suspicious",
    "high":     "impact",
    "critical": "impact",
}

CPU_STOP_EVENT_TYPES = {"S7_CPU_STOP"}
HIGH_VALUE_EVENT_TYPES = {
    "S7_CPU_STOP", "S7_DOWNLOAD_BLOCK", "S7_DELETE_BLOCK",
    "HMI_LOGIN_SUCCESS", "S7_WRITE_VAR",
}


class AnalyzerWorker:
    """
    Consumes sensor events from Redis and writes analyzed data to Postgres.
    """

    def __init__(self, redis_url: str, db_session_factory, redis_broadcast_client) -> None:
        self._redis_url = redis_url
        self._db_factory = db_session_factory
        self._redis_broadcast = redis_broadcast_client

        # In-memory session state cache (reduces DB round-trips)
        # Maps session_hint → session_id
        self._session_cache: dict[str, str] = {}

    async def run(self) -> None:
        """Main loop — subscribe to sensor.events and process indefinitely."""
        logger.info("Analyzer worker starting")

        redis = aioredis.from_url(self._redis_url)
        pubsub = redis.pubsub()
        await pubsub.subscribe("sensor.events")

        try:
            async for message in pubsub.listen():
                if message["type"] != "message":
                    continue
                try:
                    event_data = json.loads(message["data"])
                    await self._process_event(event_data)
                except Exception as e:
                    logger.exception("Error processing event", extra={"error": str(e)})
        finally:
            await pubsub.unsubscribe("sensor.events")
            await redis.aclose()

    async def _process_event(self, ev: dict[str, Any]) -> None:
        """
        Full event processing pipeline:
        1. Resolve or create session
        2. Write event to DB
        3. Extract artifacts + IOCs
        4. Update session severity (monotonically increasing)
        5. Broadcast to SSE stream
        6. Trigger notifications if threshold met
        """
        async with self._db_factory() as session:
            # 1. Resolve session
            db_session = await self._resolve_session(session, ev)

            # 2. Write event
            db_event = await self._write_event(session, ev, db_session)

            # 3. Extract IOCs from artifacts
            iocs = extract_iocs(ev)
            for ioc in iocs:
                await models.IOC.upsert(
                    session,
                    session_id=db_session.id,
                    ioc_type=ioc["type"],
                    value=ioc["value"],
                    context=ioc.get("context"),
                    confidence=ioc.get("confidence", 1.0),
                )

            # 4. Update session
            new_severity = SEVERITY_LABEL.get(ev.get("severity", "SEVERITY_NOISE"), "noise")
            cpu_stop = ev.get("event_type") in CPU_STOP_EVENT_TYPES
            mitre = MITRE_ICS_MAPPING.get(ev.get("event_type", ""), {})

            await self._update_session(
                session, db_session,
                new_severity=new_severity,
                cpu_stop=cpu_stop,
                mitre=mitre,
                ioc_count=len(iocs),
                artifact_count=len(ev.get("artifacts", [])),
            )

            await session.commit()

        # 5. Broadcast to SSE
        await self._broadcast_event(ev, str(db_session.id), str(db_event.id))

        # 6. Trigger notifications (non-blocking)
        asyncio.create_task(self._check_notifications(ev, db_session))

    async def _resolve_session(
        self, db: AsyncSession, ev: dict
    ) -> models.Session:
        """
        Find an existing open session for this source, or create a new one.

        Session grouping key: source_ip + protocol (we ignore source_port
        for protocol-level session continuity, but use it for HMI).
        """
        hint = ev.get("session_hint", "")
        # Normalize: use IP + protocol only (not ephemeral port)
        parts = hint.split(":")
        ip = parts[0] if parts else ev.get("source_ip", "unknown")
        protocol = parts[2] if len(parts) >= 3 else ev.get("protocol", "unknown")
        group_key = f"{ip}:{protocol}"

        # Check in-memory cache first
        if group_key in self._session_cache:
            session_id = self._session_cache[group_key]
            db_session = await models.Session.get_recent_open(db, session_id)
            if db_session is not None:
                return db_session
            # Cache stale — remove
            del self._session_cache[group_key]

        # Look for recent open session in DB
        db_session = await models.Session.find_open_for_ip_protocol(
            db, ip, protocol, window_seconds=SESSION_WINDOW_SECONDS
        )

        if db_session is None:
            now = datetime.now(timezone.utc).isoformat()
            # Create new session
            db_session = models.Session(
                id=uuid.uuid4(),
                sensor_id=ev.get("sensor_id"),
                source_ip=ip,
                source_port=ev.get("source_port"),
                primary_protocol=_normalize_protocol(protocol),
                attack_phase=_infer_attack_phase(ev.get("event_type", "")),
                severity="noise",
                signal_tier="noise",
                is_actionable=False,
                started_at=now,
                updated_at=now,
            )
            db.add(db_session)
            await db.flush()  # Get the ID

        self._session_cache[group_key] = str(db_session.id)
        return db_session

    async def _write_event(
        self, db: AsyncSession, ev: dict, db_session: models.Session
    ) -> models.Event:
        """Write event + artifacts to Postgres."""
        db_event = models.Event(
            id=uuid.uuid4(),
            sensor_event_id=ev.get("event_id"),
            session_id=db_session.id,
            sensor_id=ev.get("sensor_id"),
            source_ip=ev.get("source_ip"),
            source_port=ev.get("source_port"),
            dst_port=ev.get("dst_port"),
            protocol=_normalize_protocol(ev.get("protocol", "")),
            event_type=ev.get("event_type", "EVENT_UNKNOWN"),
            event_family=_event_family(ev.get("event_type", "")),
            severity=SEVERITY_LABEL.get(ev.get("severity", "SEVERITY_NOISE"), "noise"),
            classification=_classification(ev.get("event_type", ""), ev.get("metadata", {})),
            raw_summary=ev.get("raw_summary", ""),
            raw_payload_hex=ev.get("raw_payload", ""),
            event_metadata=ev.get("metadata", {}),
            artifact_count=len(ev.get("artifacts", [])),
            timestamp=ev.get("timestamp") or datetime.now(timezone.utc).isoformat(),
        )
        db.add(db_event)
        await db.flush()

        # Write artifacts
        for art in ev.get("artifacts", []):
            db_artifact = models.Artifact(
                id=uuid.uuid4(),
                event_id=db_event.id,
                session_id=db_session.id,
                artifact_type=art.get("artifact_type", "unknown"),
                value=art.get("value", ""),
                encoding=art.get("encoding", "utf8"),
            )
            db.add(db_artifact)

        return db_event

    async def _update_session(
        self,
        db: AsyncSession,
        db_session: models.Session,
        new_severity: str,
        cpu_stop: bool,
        mitre: dict,
        ioc_count: int,
        artifact_count: int,
    ) -> None:
        """
        Update session metadata. Severity is monotonically increasing.
        """
        current_order = SEVERITY_ORDER.get(f"SEVERITY_{db_session.severity.upper()}", 0)
        new_order     = SEVERITY_ORDER.get(f"SEVERITY_{new_severity.upper()}", 0)

        if new_order > current_order:
            db_session.severity    = new_severity
            db_session.signal_tier = SIGNAL_TIER.get(new_severity, "noise")

        if cpu_stop:
            db_session.cpu_stop_occurred = True
            db_session.is_actionable     = True

        if ioc_count > 0:
            db_session.has_iocs   = True
            db_session.ioc_count  = (db_session.ioc_count or 0) + ioc_count

        if artifact_count > 0:
            db_session.artifact_count = (db_session.artifact_count or 0) + artifact_count

        if db_session.signal_tier in ("suspicious", "impact"):
            db_session.is_actionable = True

        # Merge MITRE techniques
        if mitre:
            techniques = db_session.mitre_techniques or []
            tech = {
                "technique_id":   mitre.get("technique_id"),
                "technique_name": mitre.get("technique_name"),
                "tactic":         mitre.get("tactic"),
            }
            if tech not in techniques:
                techniques.append(tech)
            db_session.mitre_techniques = techniques

        db_session.event_count = (db_session.event_count or 0) + 1
        now = datetime.now(timezone.utc)
        db_session.updated_at = now.isoformat()

        # Calculate duration
        if db_session.started_at:
            started_at = db_session.started_at
            if isinstance(started_at, str):
                started_at = datetime.fromisoformat(started_at)
            delta = now - started_at
            db_session.duration_seconds = delta.total_seconds()

    async def _broadcast_event(self, ev: dict, session_id: str, event_id: str) -> None:
        """Publish to SSE broadcast channel for UI live stream."""
        try:
            payload = {
                "type": "attack_event",
                "data": {
                    "event_id":   event_id,
                    "session_id": session_id,
                    "source_ip":  ev.get("source_ip"),
                    "event_type": ev.get("event_type"),
                    "severity":   SEVERITY_LABEL.get(ev.get("severity", "SEVERITY_NOISE"), "noise"),
                    "protocol":   _normalize_protocol(ev.get("protocol", "")),
                    "summary":    ev.get("raw_summary", ""),
                    "timestamp":  ev.get("timestamp"),
                    "cpu_stop":   ev.get("event_type") in CPU_STOP_EVENT_TYPES,
                    "dst_port":   ev.get("dst_port"),
                },
            }
            await self._redis_broadcast.publish("sse.broadcast", json.dumps(payload))
        except Exception as e:
            logger.warning("Failed to broadcast event", extra={"error": str(e)})

    async def _check_notifications(self, ev: dict, db_session: models.Session) -> None:
        """Trigger SMTP/SIEM notifications if severity threshold met."""
        # Import here to avoid circular imports
        from manager.notifications.smtp_sender import maybe_send_smtp
        from manager.notifications.siem_forwarder import maybe_forward_siem

        try:
            async with self._db_factory() as session:
                await maybe_send_smtp(session, ev, db_session)
                await maybe_forward_siem(session, ev, db_session)
        except Exception as e:
            logger.warning("Notification error", extra={"error": str(e)})


# ─────────────────────────────────────────────────────────────────────────────
# Helper functions
# ─────────────────────────────────────────────────────────────────────────────

def _normalize_protocol(proto: str) -> str:
    mapping = {
        "PROTOCOL_S7":      "s7comm",
        "PROTOCOL_MODBUS":  "modbus",
        "PROTOCOL_HTTP":    "http",
        "PROTOCOL_HTTPS":   "https",
        "PROTOCOL_RAW_TCP": "tcp",
    }
    return mapping.get(proto, proto.lower().replace("protocol_", ""))


def _event_family(event_type: str) -> str:
    if event_type.startswith("S7_"):
        if "MALFORMED" in event_type or "NON_TPKT" in event_type or "PARTIAL" in event_type:
            return "ics_anomaly"
        if "CPU_STOP" in event_type or "DOWNLOAD" in event_type or "DELETE" in event_type:
            return "ics_exploit"
        return "ics_recon"
    if event_type.startswith("MODBUS_"):
        return "ics_modbus"
    if event_type.startswith("HMI_"):
        if any(x in event_type for x in ["SQLI", "XSS", "CMD", "TRAVERSAL"]):
            return "web_attack"
        if "LOGIN" in event_type:
            return "credential_attack"
        return "web_access"
    return "unknown"


def _infer_attack_phase(event_type: str) -> str:
    """Map event type to cyber kill chain phase."""
    if event_type in ("S7_COTP_CONNECT", "MODBUS_CONNECT", "HMI_ACCESS"):
        return "initial_access"
    if event_type in ("S7_SZL_READ", "S7_READ_VAR", "HMI_SENSITIVE_PATH"):
        return "discovery"
    if event_type in ("S7_WRITE_VAR", "MODBUS_WRITE_MULTIPLE", "HMI_LOGIN_ATTEMPT"):
        return "lateral_movement"
    if event_type in ("S7_CPU_STOP", "S7_DOWNLOAD_BLOCK", "HMI_LOGIN_SUCCESS"):
        return "impact"
    return "initial_access"


def _classification(event_type: str, metadata: dict) -> str:
    """Return a human-readable classification label."""
    labels = {
        "S7_CPU_STOP":       "cpu_stop_attempt",
        "S7_SZL_READ":       "device_discovery",
        "S7_WRITE_VAR":      "plc_write",
        "S7_DOWNLOAD_BLOCK": "firmware_manipulation",
        "HMI_SQLI_PROBE":    "sql_injection",
        "HMI_XSS_PROBE":     "cross_site_scripting",
        "HMI_CMD_INJECTION": "command_injection",
        "HMI_PATH_TRAVERSAL": "path_traversal",
        "HMI_LOGIN_SUCCESS": "brute_force_success",
        "HMI_LOGIN_ATTEMPT": "credential_stuffing",
        "S7_MALFORMED_TPKT": "malformed_protocol",
        "S7_NON_TPKT_TRAFFIC": "port_scanner",
    }
    return labels.get(event_type, "generic_probe")
