"""
manager/db/engine.py — Async SQLAlchemy engine and session factory.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import Request
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)


def create_engine_and_session_factory(database_url: str):
    engine = create_async_engine(
        database_url,
        pool_size=10,
        max_overflow=20,
        pool_pre_ping=True,
        echo=False,
    )
    factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    return engine, factory


async def run_migrations(engine) -> None:
    """Create all tables from ORM models (Alembic handles incremental migrations in prod)."""
    from manager.db.models import Base
    from sqlalchemy import text
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        # Idempotent column additions for existing deployments
        for stmt in [
            "ALTER TABLE sessions    ADD COLUMN IF NOT EXISTS triage_status   TEXT NOT NULL DEFAULT 'new'",
            "ALTER TABLE sessions    ADD COLUMN IF NOT EXISTS triage_note      TEXT",
            "ALTER TABLE sensors     ADD COLUMN IF NOT EXISTS sensor_config    JSONB",
            "ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS window_seconds   INTEGER",
            "ALTER TABLE alert_rules ADD COLUMN IF NOT EXISTS threshold        INTEGER",
            "ALTER TABLE app_config  ADD COLUMN IF NOT EXISTS llm_enabled      BOOLEAN",
            "ALTER TABLE app_config  ADD COLUMN IF NOT EXISTS llm_backend      TEXT",
            "ALTER TABLE app_config  ADD COLUMN IF NOT EXISTS llm_base_url     TEXT",
            "ALTER TABLE app_config  ADD COLUMN IF NOT EXISTS llm_default_model TEXT",
        ]:
            await conn.execute(text(stmt))
        # Idempotent index additions (CREATE INDEX IF NOT EXISTS)
        for stmt in [
            "CREATE INDEX IF NOT EXISTS idx_sessions_sensor_id     ON sessions (sensor_id)",
            "CREATE INDEX IF NOT EXISTS idx_sessions_triage_status ON sessions (triage_status)",
            "CREATE INDEX IF NOT EXISTS idx_iocs_ioc_type          ON iocs (ioc_type)",
        ]:
            await conn.execute(text(stmt))


@asynccontextmanager
async def get_db_session(factory) -> AsyncGenerator[AsyncSession, None]:
    async with factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


# FastAPI dependency
async def get_db(request: Request) -> AsyncGenerator[AsyncSession, None]:
    factory = request.app.state.db_factory
    async with factory() as session:
        yield session
