"""
manager/main.py — OTrap Manager FastAPI application factory.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import redis.asyncio as aioredis
import grpc.aio
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from manager.config import Settings
from manager.db.engine import create_engine_and_session_factory, run_migrations
from manager.grpc.ca import CertificateAuthority
from manager.grpc.sensor_service import SensorServicer
from manager.grpc import sensor_pb2_grpc
from manager.analyzer.worker import AnalyzerWorker
from manager.api.routers import api_router

logger = logging.getLogger("otrap.manager")


def create_app() -> FastAPI:
    settings = Settings()
    logging.basicConfig(level=logging.INFO)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        # ── Database ──────────────────────────────────────────────────────────
        engine, session_factory = create_engine_and_session_factory(settings.database_url)
        await run_migrations(engine)
        app.state.db_factory = session_factory

        # ── Apply DB-stored LLM config on top of env defaults ─────────────────
        await _apply_db_llm_config(session_factory, settings)

        # ── Redis ─────────────────────────────────────────────────────────────
        redis = aioredis.from_url(settings.redis_url_with_auth, decode_responses=True)
        app.state.redis = redis

        # ── CA / mTLS ─────────────────────────────────────────────────────────
        ca, ca_key_pem, ca_cert_pem = CertificateAuthority.from_env_or_generate()
        app.state.ca = ca

        if not os.environ.get("GRPC_CA_KEY_B64"):
            import base64
            logger.warning(
                "GRPC CA auto-generated. Set these env vars to persist:\n"
                "  GRPC_CA_KEY_B64=%s\n  GRPC_CA_CERT_B64=%s",
                base64.b64encode(ca_key_pem).decode(),
                base64.b64encode(ca_cert_pem).decode(),
            )

        # ── gRPC Server ───────────────────────────────────────────────────────
        grpc_server = grpc.aio.server()
        sensor_pb2_grpc.add_SensorServiceServicer_to_server(
            SensorServicer(ca, redis, session_factory),
            grpc_server,
        )
        ssl_creds = ca.build_server_ssl_context()
        grpc_port = settings.grpc_port
        grpc_server.add_secure_port(f"0.0.0.0:{grpc_port}", ssl_creds)
        await grpc_server.start()
        logger.info(f"gRPC server started on port {grpc_port} (mTLS)")
        app.state.grpc_server = grpc_server

        # ── Analyzer Worker ───────────────────────────────────────────────────
        analyzer = AnalyzerWorker(settings.redis_url_with_auth, session_factory, redis)
        analyzer_task = asyncio.create_task(analyzer.run())
        app.state.analyzer_task = analyzer_task

        # ── Audit Retention Job ───────────────────────────────────────────────
        retention_task = asyncio.create_task(_run_audit_retention(session_factory))
        app.state.retention_task = retention_task

        # ── Sensor Heartbeat Checker ──────────────────────────────────────────
        hb_task = asyncio.create_task(_run_sensor_heartbeat_checker(session_factory, redis))
        app.state.hb_task = hb_task

        # ── Initial admin user ────────────────────────────────────────────────
        await _ensure_initial_admin(session_factory, settings)

        yield

        # ── Shutdown ──────────────────────────────────────────────────────────
        analyzer_task.cancel()
        retention_task.cancel()
        hb_task.cancel()
        await grpc_server.stop(grace=5)
        await redis.aclose()
        await engine.dispose()

    app = FastAPI(
        title="OTrap Manager",
        version="2.0.0",
        docs_url="/docs" if os.environ.get("DOCS_ENABLED") == "true" else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # ── CORS ──────────────────────────────────────────────────────────────────
    origins = [o.strip() for o in os.environ.get("CORS_ORIGINS", "").split(",") if o.strip()]
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
            allow_headers=["*"],
        )

    # ── Routes ────────────────────────────────────────────────────────────────
    app.include_router(api_router, prefix="/api/v1")

    return app


async def _run_sensor_heartbeat_checker(session_factory, redis) -> None:
    """Every 60s: mark active sensors with no heartbeat in >5min as offline."""
    import json
    from manager.db import models

    while True:
        await asyncio.sleep(60)
        try:
            async with session_factory() as db:
                timed_out = await models.Sensor.mark_timed_out_offline(db, timeout_seconds=300)
                if timed_out:
                    # Write audit entries in the same transaction
                    for sid in timed_out:
                        await models.AuditLog.write(
                            db,
                            user_id=None,
                            username="system",
                            action="sensor_offline",
                            target_type="sensor",
                            target_id=sid,
                            detail={"reason": "heartbeat_timeout"},
                        )
                    await db.commit()

                    # Clear Redis caches and broadcast SSE outside the DB transaction
                    for sid in timed_out:
                        await redis.delete(f"sensor.active:{sid}")
                        await redis.delete(f"sensor.health:{sid}")
                        await redis.publish(
                            "sse.broadcast",
                            json.dumps({
                                "type": "health_update",
                                "data": {"sensor_id": sid, "status": "offline"},
                            }),
                        )
                        logger.info("Sensor timed out → offline: %s", sid)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error("Sensor heartbeat checker failed: %s", e)


async def _run_audit_retention(session_factory) -> None:
    """Daily background job: purge audit log entries older than configured retention window."""
    from datetime import timedelta
    from manager.db import models

    while True:
        await asyncio.sleep(24 * 3600)
        try:
            async with session_factory() as db:
                cfg = await models.AppConfig.get(db)
                days = cfg.audit_retention_days if cfg else 0
                if days > 0:
                    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
                    deleted = await models.AuditLog.purge_before(db, cutoff)
                    await db.commit()
                    logger.info("Audit retention: purged %d entries older than %d days", deleted, days)
        except Exception as e:
            logger.error("Audit retention job failed: %s", e)


async def _apply_db_llm_config(session_factory, settings: Settings) -> None:
    """Override LLM settings with values stored in AppConfig (if set)."""
    from manager.db import models
    from manager.config import settings as module_settings

    try:
        async with session_factory() as db:
            cfg = await models.AppConfig.get(db)
            await db.commit()
            for attr in ("llm_enabled", "llm_backend", "llm_base_url", "llm_default_model"):
                val = getattr(cfg, attr, None)
                if val is not None:
                    setattr(settings, attr, val)
                    setattr(module_settings, attr, val)
    except Exception as e:
        logger.warning("Could not load LLM config from DB: %s", e)


async def _ensure_initial_admin(session_factory, settings: Settings) -> None:
    """Create initial superadmin if no users exist."""
    from manager.db import models
    from manager.security.hashing import hash_bcrypt

    async with session_factory() as session:
        count = await models.User.count(session)
        if count == 0:
            logger.info("Creating initial superadmin user")
            admin = models.User(
                username=settings.initial_admin_username,
                email=settings.initial_admin_email,
                password_hash=hash_bcrypt(settings.initial_admin_password),
                role="superadmin",
                is_active=True,
            )
            session.add(admin)
            await session.commit()
            logger.info("Initial superadmin created: %s", settings.initial_admin_username)


app = create_app()
