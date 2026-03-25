"""
manager/db/models.py — SQLAlchemy async ORM models.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

import bcrypt
from sqlalchemy import (
    Boolean, Column, Float, ForeignKey, Index, Integer,
    String, Text, UniqueConstraint, delete, text, select, func, update
)
from sqlalchemy.dialects.postgresql import (
    ARRAY, INET, JSONB, UUID as PGUUID
)
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# Sensors
# ─────────────────────────────────────────────────────────────────────────────

class Sensor(Base):
    __tablename__ = "sensors"

    id               = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name             = Column(Text, nullable=False)
    join_token_hash  = Column(Text, nullable=True)
    token_expires_at = Column(Text, nullable=True)  # ISO string
    client_cert_pem  = Column(Text, nullable=True)
    last_seen_at     = Column(Text, nullable=True)
    registered_at    = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    version          = Column(Text, nullable=True)
    reported_ip      = Column(Text, nullable=True)
    capabilities     = Column(ARRAY(Text), default=list)
    status           = Column(Text, nullable=False, default="pending")

    @classmethod
    async def find_by_token_candidate(cls, session: AsyncSession, token: str) -> Optional["Sensor"]:
        """Find sensor with a pending join_token_hash that matches the token."""
        # Fetch all pending sensors and bcrypt-compare (can't do this in SQL)
        result = await session.execute(
            select(cls).where(
                cls.status == "pending",
                cls.join_token_hash.isnot(None),
            )
        )
        for sensor in result.scalars().all():
            try:
                if bcrypt.checkpw(token.encode(), sensor.join_token_hash.encode()):
                    return sensor
            except Exception:
                continue
        return None

    @classmethod
    async def get_by_id(cls, session: AsyncSession, sensor_id: str) -> Optional["Sensor"]:
        result = await session.execute(select(cls).where(cls.id == uuid.UUID(sensor_id)))
        return result.scalar_one_or_none()

    @classmethod
    async def update_last_seen(cls, session: AsyncSession, sensor_id: str) -> None:
        await session.execute(
            update(cls)
            .where(cls.id == uuid.UUID(sensor_id))
            .values(last_seen_at=datetime.now(timezone.utc).isoformat())
        )


# ─────────────────────────────────────────────────────────────────────────────
# Users
# ─────────────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id             = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username       = Column(Text, unique=True, nullable=False)
    email          = Column(Text, unique=True, nullable=False)
    password_hash  = Column(Text, nullable=False)
    role           = Column(Text, nullable=False, default="user")
    is_active      = Column(Boolean, nullable=False, default=True)
    force_pw_reset = Column(Boolean, nullable=False, default=False)
    created_at     = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    updated_at     = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    last_login_at  = Column(Text, nullable=True)

    @classmethod
    async def count(cls, session: AsyncSession) -> int:
        result = await session.execute(select(func.count()).select_from(cls))
        return result.scalar_one()

    @classmethod
    async def get_by_username(cls, session: AsyncSession, username: str) -> Optional["User"]:
        result = await session.execute(select(cls).where(cls.username == username))
        return result.scalar_one_or_none()

    @classmethod
    async def get_by_id(cls, session: AsyncSession, user_id: str) -> Optional["User"]:
        result = await session.execute(select(cls).where(cls.id == uuid.UUID(user_id)))
        return result.scalar_one_or_none()

    @classmethod
    async def list_all(cls, session: AsyncSession) -> list["User"]:
        result = await session.execute(select(cls).order_by(cls.created_at))
        return list(result.scalars().all())


# ─────────────────────────────────────────────────────────────────────────────
# Sessions
# ─────────────────────────────────────────────────────────────────────────────

class Session(Base):
    __tablename__ = "sessions"

    id                = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sensor_id         = Column(PGUUID(as_uuid=True), ForeignKey("sensors.id", ondelete="SET NULL"), nullable=True)
    source_ip         = Column(Text, nullable=False)
    source_port       = Column(Integer, nullable=True)
    primary_protocol  = Column(Text, nullable=False, default="unknown")
    attack_phase      = Column(Text, nullable=False, default="initial_access")
    severity          = Column(Text, nullable=False, default="noise")
    signal_tier       = Column(Text, nullable=False, default="noise")
    is_actionable     = Column(Boolean, nullable=False, default=False)
    cpu_stop_occurred = Column(Boolean, nullable=False, default=False)
    has_iocs          = Column(Boolean, nullable=False, default=False)
    ioc_count         = Column(Integer, nullable=False, default=0)
    artifact_count    = Column(Integer, nullable=False, default=0)
    event_count       = Column(Integer, nullable=False, default=0)
    duration_seconds  = Column(Float, nullable=True)
    mitre_techniques  = Column(JSONB, nullable=False, default=list)
    rule_ids          = Column(ARRAY(PGUUID(as_uuid=True)), nullable=True)
    report_ids        = Column(ARRAY(PGUUID(as_uuid=True)), nullable=True)
    session_metadata  = Column("metadata", JSONB, nullable=False, default=dict)
    started_at        = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    updated_at        = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    closed_at         = Column(Text, nullable=True)
    triage_status     = Column(Text, nullable=False, default="new", server_default="new")
    triage_note       = Column(Text, nullable=True)

    events    = relationship("Event", back_populates="session", lazy="noload")
    iocs      = relationship("IOC", back_populates="session", lazy="noload")
    artifacts = relationship("Artifact", back_populates="session", lazy="noload")

    __table_args__ = (
        Index("idx_sessions_source_ip",   "source_ip"),
        Index("idx_sessions_severity",    "severity"),
        Index("idx_sessions_signal_tier", "signal_tier"),
        Index("idx_sessions_started_at",  "started_at"),
    )

    @classmethod
    async def get_recent_open(cls, session: AsyncSession, session_id: str) -> Optional["Session"]:
        result = await session.execute(
            select(cls).where(cls.id == uuid.UUID(session_id), cls.closed_at.is_(None))
        )
        return result.scalar_one_or_none()

    @classmethod
    async def find_open_for_ip_protocol(
        cls, session: AsyncSession, source_ip: str, protocol: str, window_seconds: int
    ) -> Optional["Session"]:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(seconds=window_seconds)).isoformat()
        result = await session.execute(
            select(cls).where(
                cls.source_ip == source_ip,
                cls.primary_protocol == protocol,
                cls.closed_at.is_(None),
                cls.updated_at >= cutoff,
            ).order_by(cls.started_at.desc()).limit(1)
        )
        return result.scalar_one_or_none()

    @classmethod
    async def list_filtered(
        cls,
        session: AsyncSession,
        severity: str | None = None,
        signal_tier: str | None = None,
        protocol: str | None = None,
        source_ip: str | None = None,
        cpu_stop: bool | None = None,
        has_iocs: bool | None = None,
        is_actionable: bool | None = None,
        from_dt: str | None = None,
        to_dt: str | None = None,
        triage_status: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[list["Session"], int]:
        q = select(cls)
        if severity:
            q = q.where(cls.severity == severity)
        if signal_tier:
            q = q.where(cls.signal_tier == signal_tier)
        if protocol:
            q = q.where(cls.primary_protocol == protocol)
        if source_ip:
            q = q.where(cls.source_ip == source_ip)
        if cpu_stop is not None:
            q = q.where(cls.cpu_stop_occurred == cpu_stop)
        if has_iocs is not None:
            q = q.where(cls.has_iocs == has_iocs)
        if is_actionable is not None:
            q = q.where(cls.is_actionable == is_actionable)
        if from_dt:
            q = q.where(cls.started_at >= from_dt)
        if to_dt:
            q = q.where(cls.started_at <= to_dt)
        if triage_status:
            q = q.where(cls.triage_status == triage_status)

        count_q = select(func.count()).select_from(q.subquery())
        total   = (await session.execute(count_q)).scalar_one()
        rows    = (await session.execute(q.order_by(cls.started_at.desc()).limit(limit).offset(offset))).scalars().all()
        return list(rows), total


# ─────────────────────────────────────────────────────────────────────────────
# Events
# ─────────────────────────────────────────────────────────────────────────────

class Event(Base):
    __tablename__ = "events"

    id              = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sensor_event_id = Column(Text, unique=True, nullable=True)
    session_id      = Column(PGUUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"))
    sensor_id       = Column(PGUUID(as_uuid=True), ForeignKey("sensors.id", ondelete="SET NULL"), nullable=True)
    source_ip       = Column(Text, nullable=False)
    source_port     = Column(Integer, nullable=True)
    dst_port        = Column(Integer, nullable=True)
    protocol        = Column(Text, nullable=False)
    event_type      = Column(Text, nullable=False)
    event_family    = Column(Text, nullable=False)
    severity        = Column(Text, nullable=False)
    classification  = Column(Text, nullable=True)
    raw_summary     = Column(Text, nullable=True)
    raw_payload_hex = Column(Text, nullable=True)
    event_metadata  = Column("metadata", JSONB, nullable=False, default=dict)
    artifact_count  = Column(Integer, nullable=False, default=0)
    timestamp       = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    session   = relationship("Session", back_populates="events")
    artifacts = relationship("Artifact", back_populates="event", lazy="noload")

    __table_args__ = (
        Index("idx_events_session_id", "session_id"),
        Index("idx_events_source_ip",  "source_ip"),
        Index("idx_events_timestamp",  "timestamp"),
        Index("idx_events_event_type", "event_type"),
    )

    @classmethod
    async def list_recent(cls, session: AsyncSession, limit: int = 50) -> list["Event"]:
        result = await session.execute(
            select(cls).order_by(cls.timestamp.desc()).limit(limit)
        )
        return list(result.scalars().all())

    @classmethod
    async def list_for_session(cls, session: AsyncSession, session_id: str) -> list["Event"]:
        result = await session.execute(
            select(cls)
            .where(cls.session_id == uuid.UUID(session_id))
            .order_by(cls.timestamp.asc())
        )
        return list(result.scalars().all())

    @classmethod
    async def top_attackers(
        cls, db: AsyncSession, limit: int = 10
    ) -> list[dict]:
        result = await db.execute(
            text("""
                SELECT source_ip,
                       COUNT(*)                      AS event_count,
                       MAX(severity)                 AS max_severity,
                       COUNT(DISTINCT session_id)    AS session_count
                FROM events
                GROUP BY source_ip
                ORDER BY event_count DESC
                LIMIT :limit
            """),
            {"limit": limit},
        )
        return [dict(r._mapping) for r in result]


# ─────────────────────────────────────────────────────────────────────────────
# Artifacts
# ─────────────────────────────────────────────────────────────────────────────

class Artifact(Base):
    __tablename__ = "artifacts"

    id            = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_id      = Column(PGUUID(as_uuid=True), ForeignKey("events.id", ondelete="CASCADE"))
    session_id    = Column(PGUUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"))
    artifact_type = Column(Text, nullable=False)
    value         = Column(Text, nullable=False)
    encoding      = Column(Text, nullable=False, default="utf8")
    created_at    = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    event   = relationship("Event", back_populates="artifacts")
    session = relationship("Session", back_populates="artifacts")

    @classmethod
    async def list_for_session(cls, db: AsyncSession, session_id: str) -> list["Artifact"]:
        result = await db.execute(
            select(cls).where(cls.session_id == uuid.UUID(session_id)).order_by(cls.created_at)
        )
        return list(result.scalars().all())


# ─────────────────────────────────────────────────────────────────────────────
# IOCs
# ─────────────────────────────────────────────────────────────────────────────

class IOC(Base):
    __tablename__ = "iocs"

    id           = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id   = Column(PGUUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"))
    ioc_type     = Column(Text, nullable=False)
    value        = Column(Text, nullable=False)
    context      = Column(Text, nullable=True)
    confidence   = Column(Float, nullable=False, default=1.0)
    first_seen_at = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())
    last_seen_at  = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    session = relationship("Session", back_populates="iocs")

    __table_args__ = (
        UniqueConstraint("session_id", "ioc_type", "value", name="uq_ioc_session_type_value"),
        Index("idx_iocs_value",      "value"),
        Index("idx_iocs_session_id", "session_id"),
    )

    @classmethod
    async def upsert(
        cls, db: AsyncSession,
        session_id, ioc_type: str, value: str,
        context: str | None = None, confidence: float = 1.0,
    ) -> bool:
        """Returns True if a new IOC was inserted, False if an existing one was updated."""
        now = datetime.now(timezone.utc).isoformat()
        existing = await db.execute(
            select(cls).where(
                cls.session_id == session_id,
                cls.ioc_type   == ioc_type,
                cls.value      == value,
            )
        )
        row = existing.scalar_one_or_none()
        if row:
            row.last_seen_at = now
            row.confidence   = max(row.confidence, confidence)
            return False
        else:
            db.add(cls(
                session_id=session_id,
                ioc_type=ioc_type,
                value=value,
                context=context,
                confidence=confidence,
            ))
            return True

    @classmethod
    async def list_for_session(cls, db: AsyncSession, session_id: str) -> list["IOC"]:
        result = await db.execute(
            select(cls).where(cls.session_id == uuid.UUID(session_id))
        )
        return list(result.scalars().all())


# ─────────────────────────────────────────────────────────────────────────────
# S7 Memory Blocks
# ─────────────────────────────────────────────────────────────────────────────

class S7MemoryBlock(Base):
    __tablename__ = "s7_memory_blocks"

    id          = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sensor_id   = Column(PGUUID(as_uuid=True), ForeignKey("sensors.id", ondelete="CASCADE"))
    session_hint = Column(Text, nullable=True)
    db_number   = Column(Integer, nullable=False)
    byte_offset = Column(Integer, nullable=False)
    value_hex   = Column(Text, nullable=False)
    written_at  = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    __table_args__ = (
        UniqueConstraint("sensor_id", "db_number", "byte_offset", name="uq_s7mem_sensor_db_offset"),
    )

    @classmethod
    async def upsert(
        cls, db: AsyncSession,
        sensor_id: str, session_hint: str,
        db_number: int, byte_offset: int, value_hex: str,
    ) -> None:
        now = datetime.now(timezone.utc).isoformat()
        sid = uuid.UUID(sensor_id)
        existing = await db.execute(
            select(cls).where(
                cls.sensor_id   == sid,
                cls.db_number   == db_number,
                cls.byte_offset == byte_offset,
            )
        )
        row = existing.scalar_one_or_none()
        if row:
            row.value_hex    = value_hex
            row.written_at   = now
            row.session_hint = session_hint
        else:
            db.add(cls(
                sensor_id=sid,
                session_hint=session_hint,
                db_number=db_number,
                byte_offset=byte_offset,
                value_hex=value_hex,
            ))


# ─────────────────────────────────────────────────────────────────────────────
# SMTP Config (singleton row id=1)
# ─────────────────────────────────────────────────────────────────────────────

class SMTPConfig(Base):
    __tablename__ = "smtp_config"

    id              = Column(Integer, primary_key=True, default=1)
    host            = Column(Text, nullable=True)
    port            = Column(Integer, default=587)
    username        = Column(Text, nullable=True)
    password_enc    = Column(Text, nullable=True)   # AES-256-GCM
    from_address    = Column(Text, nullable=True)
    to_addresses    = Column(ARRAY(Text), default=list)
    use_tls         = Column(Boolean, default=True)
    use_starttls    = Column(Boolean, default=False)
    min_severity    = Column(Text, default="high")
    health_alerts   = Column(Boolean, default=True)
    cooldown_seconds = Column(Integer, default=300)
    enabled         = Column(Boolean, default=False)
    updated_at      = Column(Text, default=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    async def get(cls, db: AsyncSession) -> Optional["SMTPConfig"]:
        result = await db.execute(select(cls).where(cls.id == 1))
        return result.scalar_one_or_none()

    @classmethod
    async def upsert(cls, db: AsyncSession, **kwargs) -> "SMTPConfig":
        existing = await cls.get(db)
        if existing:
            for k, v in kwargs.items():
                setattr(existing, k, v)
            existing.updated_at = datetime.now(timezone.utc).isoformat()
            return existing
        row = cls(id=1, **kwargs)
        db.add(row)
        return row


# ─────────────────────────────────────────────────────────────────────────────
# SIEM Config (singleton row id=1)
# ─────────────────────────────────────────────────────────────────────────────

class SIEMConfig(Base):
    __tablename__ = "siem_config"

    id           = Column(Integer, primary_key=True, default=1)
    siem_type    = Column(Text, default="splunk_hec")
    url          = Column(Text, nullable=True)
    token_enc    = Column(Text, nullable=True)
    min_severity = Column(Text, default="medium")
    enabled      = Column(Boolean, default=False)
    updated_at   = Column(Text, default=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    async def get(cls, db: AsyncSession) -> Optional["SIEMConfig"]:
        result = await db.execute(select(cls).where(cls.id == 1))
        return result.scalar_one_or_none()

    @classmethod
    async def upsert(cls, db: AsyncSession, **kwargs) -> "SIEMConfig":
        existing = await cls.get(db)
        if existing:
            for k, v in kwargs.items():
                setattr(existing, k, v)
            existing.updated_at = datetime.now(timezone.utc).isoformat()
            return existing
        row = cls(id=1, **kwargs)
        db.add(row)
        return row


# ─────────────────────────────────────────────────────────────────────────────
# SIEM Delivery Log
# ─────────────────────────────────────────────────────────────────────────────

class SIEMDeliveryLog(Base):
    __tablename__ = "siem_delivery_log"

    id              = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id      = Column(PGUUID(as_uuid=True), ForeignKey("sessions.id", ondelete="SET NULL"), nullable=True)
    event_id        = Column(PGUUID(as_uuid=True), ForeignKey("events.id", ondelete="SET NULL"), nullable=True)
    siem_type       = Column(Text, nullable=True)
    status          = Column(Text, nullable=False)
    http_status     = Column(Integer, nullable=True)
    error_detail    = Column(Text, nullable=True)
    payload_preview = Column(JSONB, nullable=True)
    delivered_at    = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    async def list_recent(cls, db: AsyncSession, limit: int = 100) -> list["SIEMDeliveryLog"]:
        result = await db.execute(
            select(cls).order_by(cls.delivered_at.desc()).limit(limit)
        )
        return list(result.scalars().all())


# ─────────────────────────────────────────────────────────────────────────────
# Audit Log
# ─────────────────────────────────────────────────────────────────────────────

class AuditLog(Base):
    __tablename__ = "audit_log"

    id          = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id     = Column(PGUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    username    = Column(Text, nullable=True)
    action      = Column(Text, nullable=False)
    target_type = Column(Text, nullable=True)
    target_id   = Column(Text, nullable=True)
    detail      = Column(JSONB, default=dict)
    source_ip   = Column(Text, nullable=True)
    timestamp   = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    __table_args__ = (
        Index("idx_audit_log_timestamp", "timestamp"),
        Index("idx_audit_log_user_id",   "user_id"),
    )

    @classmethod
    async def write(
        cls, db: AsyncSession,
        user_id: str | None, username: str | None,
        action: str,
        target_type: str | None = None,
        target_id: str | None = None,
        detail: dict | None = None,
        source_ip: str | None = None,
    ) -> None:
        db.add(cls(
            user_id=uuid.UUID(user_id) if user_id else None,
            username=username,
            action=action,
            target_type=target_type,
            target_id=target_id,
            detail=detail or {},
            source_ip=source_ip,
        ))

    @classmethod
    async def list_recent(
        cls, db: AsyncSession, limit: int = 100, offset: int = 0,
        username: str | None = None, action: str | None = None,
        from_dt: str | None = None, to_dt: str | None = None,
    ) -> list["AuditLog"]:
        q = select(cls)
        if username:
            q = q.where(cls.username.ilike(f"%{username}%"))
        if action:
            q = q.where(cls.action == action)
        if from_dt:
            q = q.where(cls.timestamp >= from_dt)
        if to_dt:
            q = q.where(cls.timestamp <= to_dt + "T23:59:59")
        result = await db.execute(q.order_by(cls.timestamp.desc()).limit(limit).offset(offset))
        return list(result.scalars().all())

    @classmethod
    async def purge_before(cls, db: AsyncSession, before_iso: str) -> int:
        """Delete all entries with timestamp < before_iso. Returns deleted row count."""
        result = await db.execute(delete(cls).where(cls.timestamp < before_iso))
        return result.rowcount


# ─────────────────────────────────────────────────────────────────────────────
# App Config (singleton row id=1 — application-level settings)
# ─────────────────────────────────────────────────────────────────────────────

class AppConfig(Base):
    __tablename__ = "app_config"

    id                    = Column(Integer, primary_key=True, default=1)
    audit_retention_days  = Column(Integer, default=0)   # 0 = disabled
    updated_at            = Column(Text, default=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    async def get(cls, db: AsyncSession) -> "AppConfig":
        result = await db.execute(select(cls).where(cls.id == 1))
        row = result.scalar_one_or_none()
        if row is None:
            row = cls(id=1)
            db.add(row)
            await db.flush()
        return row

    @classmethod
    async def upsert(cls, db: AsyncSession, **kwargs) -> "AppConfig":
        row = await cls.get(db)
        for k, v in kwargs.items():
            setattr(row, k, v)
        row.updated_at = datetime.now(timezone.utc).isoformat()
        return row


# ─────────────────────────────────────────────────────────────────────────────
# LLM Outputs
# ─────────────────────────────────────────────────────────────────────────────

class LLMOutput(Base):
    __tablename__ = "llm_outputs"

    id                = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id        = Column(PGUUID(as_uuid=True), ForeignKey("sessions.id", ondelete="CASCADE"))
    output_type       = Column(Text, nullable=False)
    content           = Column(Text, nullable=False)
    model_used        = Column(Text, nullable=True)
    prompt_tokens     = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    created_at        = Column(Text, nullable=False, default=lambda: datetime.now(timezone.utc).isoformat())

    @classmethod
    async def list_for_session(cls, db: AsyncSession, session_id: str) -> list["LLMOutput"]:
        result = await db.execute(
            select(cls).where(cls.session_id == uuid.UUID(session_id)).order_by(cls.created_at.desc())
        )
        return list(result.scalars().all())
