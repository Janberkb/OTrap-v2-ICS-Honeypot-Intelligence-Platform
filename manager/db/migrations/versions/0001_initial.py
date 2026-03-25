"""Initial schema — all OTrap v2 tables.

Revision ID: 0001_initial
Revises:
Create Date: 2026-03-24
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── sensors ──────────────────────────────────────────────────────────────
    op.create_table(
        "sensors",
        sa.Column("id",               postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("name",             sa.Text, nullable=False),
        sa.Column("join_token_hash",  sa.Text, nullable=True),
        sa.Column("token_expires_at", sa.Text, nullable=True),
        sa.Column("client_cert_pem",  sa.Text, nullable=True),
        sa.Column("last_seen_at",     sa.Text, nullable=True),
        sa.Column("registered_at",    sa.Text, nullable=False),
        sa.Column("version",          sa.Text, nullable=True),
        sa.Column("reported_ip",      sa.Text, nullable=True),
        sa.Column("capabilities",     postgresql.ARRAY(sa.Text), nullable=True),
        sa.Column("status",           sa.Text, nullable=False, server_default="pending"),
    )

    # ── users ─────────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id",             postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("username",       sa.Text, unique=True, nullable=False),
        sa.Column("email",          sa.Text, unique=True, nullable=False),
        sa.Column("password_hash",  sa.Text, nullable=False),
        sa.Column("role",           sa.Text, nullable=False, server_default="user"),
        sa.Column("is_active",      sa.Boolean, nullable=False, server_default="true"),
        sa.Column("force_pw_reset", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at",     sa.Text, nullable=False),
        sa.Column("updated_at",     sa.Text, nullable=False),
        sa.Column("last_login_at",  sa.Text, nullable=True),
    )

    # ── sessions ──────────────────────────────────────────────────────────────
    op.create_table(
        "sessions",
        sa.Column("id",                postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sensor_id",         postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sensors.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_ip",         sa.Text, nullable=False),
        sa.Column("source_port",       sa.Integer, nullable=True),
        sa.Column("primary_protocol",  sa.Text, nullable=False, server_default="unknown"),
        sa.Column("attack_phase",      sa.Text, nullable=False, server_default="initial_access"),
        sa.Column("severity",          sa.Text, nullable=False, server_default="noise"),
        sa.Column("signal_tier",       sa.Text, nullable=False, server_default="noise"),
        sa.Column("is_actionable",     sa.Boolean, nullable=False, server_default="false"),
        sa.Column("cpu_stop_occurred", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("has_iocs",          sa.Boolean, nullable=False, server_default="false"),
        sa.Column("ioc_count",         sa.Integer, nullable=False, server_default="0"),
        sa.Column("artifact_count",    sa.Integer, nullable=False, server_default="0"),
        sa.Column("event_count",       sa.Integer, nullable=False, server_default="0"),
        sa.Column("duration_seconds",  sa.Float, nullable=True),
        sa.Column("mitre_techniques",  postgresql.JSONB, nullable=True),
        sa.Column("rule_ids",          postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=True),
        sa.Column("report_ids",        postgresql.ARRAY(postgresql.UUID(as_uuid=True)), nullable=True),
        sa.Column("metadata",          postgresql.JSONB, nullable=True),
        sa.Column("started_at",        sa.Text, nullable=False),
        sa.Column("updated_at",        sa.Text, nullable=False),
        sa.Column("closed_at",         sa.Text, nullable=True),
    )
    op.create_index("idx_sessions_source_ip",   "sessions", ["source_ip"])
    op.create_index("idx_sessions_severity",    "sessions", ["severity"])
    op.create_index("idx_sessions_signal_tier", "sessions", ["signal_tier"])
    op.create_index("idx_sessions_started_at",  "sessions", ["started_at"])

    # ── events ────────────────────────────────────────────────────────────────
    op.create_table(
        "events",
        sa.Column("id",              postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sensor_event_id", sa.Text, unique=True, nullable=True),
        sa.Column("session_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("sensor_id",       postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sensors.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_ip",       sa.Text, nullable=False),
        sa.Column("source_port",     sa.Integer, nullable=True),
        sa.Column("dst_port",        sa.Integer, nullable=True),
        sa.Column("protocol",        sa.Text, nullable=False),
        sa.Column("event_type",      sa.Text, nullable=False),
        sa.Column("event_family",    sa.Text, nullable=False),
        sa.Column("severity",        sa.Text, nullable=False),
        sa.Column("classification",  sa.Text, nullable=True),
        sa.Column("raw_summary",     sa.Text, nullable=True),
        sa.Column("raw_payload_hex", sa.Text, nullable=True),
        sa.Column("metadata",        postgresql.JSONB, nullable=True),
        sa.Column("artifact_count",  sa.Integer, nullable=False, server_default="0"),
        sa.Column("timestamp",       sa.Text, nullable=False),
    )
    op.create_index("idx_events_session_id", "events", ["session_id"])
    op.create_index("idx_events_source_ip",  "events", ["source_ip"])
    op.create_index("idx_events_timestamp",  "events", ["timestamp"])
    op.create_index("idx_events_event_type", "events", ["event_type"])

    # ── artifacts ─────────────────────────────────────────────────────────────
    op.create_table(
        "artifacts",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("event_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("events.id",    ondelete="CASCADE"), nullable=True),
        sa.Column("session_id",    postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sessions.id",  ondelete="CASCADE"), nullable=True),
        sa.Column("artifact_type", sa.Text, nullable=False),
        sa.Column("value",         sa.Text, nullable=False),
        sa.Column("encoding",      sa.Text, nullable=False, server_default="utf8"),
        sa.Column("created_at",    sa.Text, nullable=False),
    )

    # ── iocs ──────────────────────────────────────────────────────────────────
    op.create_table(
        "iocs",
        sa.Column("id",            postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id",    postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("ioc_type",      sa.Text, nullable=False),
        sa.Column("value",         sa.Text, nullable=False),
        sa.Column("context",       sa.Text, nullable=True),
        sa.Column("confidence",    sa.Float, nullable=False, server_default="1.0"),
        sa.Column("first_seen_at", sa.Text, nullable=False),
        sa.Column("last_seen_at",  sa.Text, nullable=False),
        sa.UniqueConstraint("session_id", "ioc_type", "value", name="uq_ioc_session_type_value"),
    )
    op.create_index("idx_iocs_value",      "iocs", ["value"])
    op.create_index("idx_iocs_session_id", "iocs", ["session_id"])

    # ── s7_memory_blocks ──────────────────────────────────────────────────────
    op.create_table(
        "s7_memory_blocks",
        sa.Column("id",           postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("sensor_id",    postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sensors.id", ondelete="CASCADE"), nullable=True),
        sa.Column("session_hint", sa.Text, nullable=True),
        sa.Column("db_number",    sa.Integer, nullable=False),
        sa.Column("byte_offset",  sa.Integer, nullable=False),
        sa.Column("value_hex",    sa.Text, nullable=False),
        sa.Column("written_at",   sa.Text, nullable=False),
        sa.UniqueConstraint("sensor_id", "db_number", "byte_offset", name="uq_s7mem_sensor_db_offset"),
    )

    # ── llm_outputs ───────────────────────────────────────────────────────────
    op.create_table(
        "llm_outputs",
        sa.Column("id",                postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id",        postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sessions.id", ondelete="CASCADE"), nullable=True),
        sa.Column("output_type",       sa.Text, nullable=False),
        sa.Column("content",           sa.Text, nullable=False),
        sa.Column("model_used",        sa.Text, nullable=True),
        sa.Column("prompt_tokens",     sa.Integer, nullable=True),
        sa.Column("completion_tokens", sa.Integer, nullable=True),
        sa.Column("created_at",        sa.Text, nullable=False),
    )

    # ── smtp_config (singleton) ───────────────────────────────────────────────
    op.create_table(
        "smtp_config",
        sa.Column("id",               sa.Integer, primary_key=True),
        sa.Column("host",             sa.Text, nullable=True),
        sa.Column("port",             sa.Integer, server_default="587"),
        sa.Column("username",         sa.Text, nullable=True),
        sa.Column("password_enc",     sa.Text, nullable=True),
        sa.Column("from_address",     sa.Text, nullable=True),
        sa.Column("to_addresses",     postgresql.ARRAY(sa.Text), nullable=True),
        sa.Column("use_tls",          sa.Boolean, server_default="true"),
        sa.Column("use_starttls",     sa.Boolean, server_default="false"),
        sa.Column("min_severity",     sa.Text, server_default="high"),
        sa.Column("health_alerts",    sa.Boolean, server_default="true"),
        sa.Column("cooldown_seconds", sa.Integer, server_default="300"),
        sa.Column("enabled",          sa.Boolean, server_default="false"),
        sa.Column("updated_at",       sa.Text, nullable=True),
    )

    # ── siem_config (singleton) ───────────────────────────────────────────────
    op.create_table(
        "siem_config",
        sa.Column("id",           sa.Integer, primary_key=True),
        sa.Column("siem_type",    sa.Text, server_default="splunk_hec"),
        sa.Column("url",          sa.Text, nullable=True),
        sa.Column("token_enc",    sa.Text, nullable=True),
        sa.Column("min_severity", sa.Text, server_default="medium"),
        sa.Column("enabled",      sa.Boolean, server_default="false"),
        sa.Column("updated_at",   sa.Text, nullable=True),
    )

    # ── siem_delivery_log ─────────────────────────────────────────────────────
    op.create_table(
        "siem_delivery_log",
        sa.Column("id",              postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id",      postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sessions.id",  ondelete="SET NULL"), nullable=True),
        sa.Column("event_id",        postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("events.id",    ondelete="SET NULL"), nullable=True),
        sa.Column("siem_type",       sa.Text, nullable=True),
        sa.Column("status",          sa.Text, nullable=False),
        sa.Column("http_status",     sa.Integer, nullable=True),
        sa.Column("error_detail",    sa.Text, nullable=True),
        sa.Column("payload_preview", postgresql.JSONB, nullable=True),
        sa.Column("delivered_at",    sa.Text, nullable=False),
    )

    # ── audit_log ─────────────────────────────────────────────────────────────
    op.create_table(
        "audit_log",
        sa.Column("id",          postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id",     postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("username",    sa.Text, nullable=True),
        sa.Column("action",      sa.Text, nullable=False),
        sa.Column("target_type", sa.Text, nullable=True),
        sa.Column("target_id",   sa.Text, nullable=True),
        sa.Column("detail",      postgresql.JSONB, nullable=True),
        sa.Column("source_ip",   sa.Text, nullable=True),
        sa.Column("timestamp",   sa.Text, nullable=False),
    )
    op.create_index("idx_audit_log_timestamp", "audit_log", ["timestamp"])
    op.create_index("idx_audit_log_user_id",   "audit_log", ["user_id"])


def downgrade() -> None:
    for table in [
        "audit_log", "siem_delivery_log", "siem_config", "smtp_config",
        "llm_outputs", "s7_memory_blocks", "iocs", "artifacts",
        "events", "sessions", "users", "sensors",
    ]:
        op.drop_table(table)
