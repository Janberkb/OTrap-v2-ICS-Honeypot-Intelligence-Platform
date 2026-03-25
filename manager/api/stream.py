"""
manager/api/stream.py — Server-Sent Events live stream.

Delivers three event types to the UI:
  attack_event   — new attack detected
  health_update  — sensor heartbeat / status change
  stats_update   — dashboard KPI refresh (every 30s)

Uses Redis pub/sub as the fan-out mechanism so multiple Manager
instances (future horizontal scaling) all broadcast the same events.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import StreamingResponse

from manager.api.auth import get_current_user
from manager.db import models

router = APIRouter(tags=["stream"])
logger = logging.getLogger("otrap.stream")


@router.get("/stream")
async def live_stream(
    request: Request,
    user: models.User = Depends(get_current_user),
):
    """
    SSE endpoint. Clients connect and receive a continuous stream of events.
    The connection stays open until the client disconnects.
    """
    redis = request.app.state.redis
    session_factory = request.app.state.db_factory

    async def event_generator():
        # Send an immediate connection acknowledgment
        yield _sse("connected", json.dumps({
            "message": "OTrap live stream connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }))

        initial_stats = await _collect_stats(session_factory)
        if initial_stats is not None:
            yield _sse("stats_update", json.dumps(initial_stats))

        pubsub = redis.pubsub()
        await pubsub.subscribe("sse.broadcast")

        # Stats refresh task
        stats_task = asyncio.create_task(_stats_ticker(session_factory, redis))

        try:
            while True:
                if await request.is_disconnected():
                    break

                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=10.0)
                if message is None:
                    yield _sse("ping", json.dumps({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }))
                    continue

                try:
                    payload = json.loads(message["data"])
                    event_type = payload.get("type", "unknown")
                    data       = payload.get("data", {})
                    yield _sse(event_type, json.dumps(data))
                except Exception as e:
                    logger.warning("SSE marshal error", extra={"error": str(e)})

        finally:
            stats_task.cancel()
            await pubsub.unsubscribe("sse.broadcast")
            await pubsub.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",   # Disable nginx buffering
            "Connection":        "keep-alive",
        },
    )


def _sse(event: str, data: str) -> str:
    return f"event: {event}\ndata: {data}\n\n"


async def _stats_ticker(session_factory, redis_client) -> None:
    """Publish stats_update every 30 seconds."""
    while True:
        await asyncio.sleep(30)
        try:
            stats_payload = await _collect_stats(session_factory)
            if stats_payload is None:
                continue

            payload = {
                "type": "stats_update",
                "data": stats_payload,
            }
            await redis_client.publish("sse.broadcast", json.dumps(payload))
        except asyncio.CancelledError:
            return
        except Exception as e:
            logger.warning("Stats tick error: %s", e)


async def _collect_stats(session_factory) -> dict | None:
    """Compute the current dashboard KPIs."""
    try:
        from sqlalchemy import func, select, text

        async with session_factory() as session:
            total_sessions = (await session.execute(
                select(func.count()).select_from(models.Session)
            )).scalar_one()

            critical_sessions = (await session.execute(
                select(func.count()).select_from(models.Session)
                .where(models.Session.severity.in_(["critical", "high"]))
            )).scalar_one()

            cpu_stops = (await session.execute(
                select(func.count()).select_from(models.Session)
                .where(models.Session.cpu_stop_occurred == True)
            )).scalar_one()

            events_24h = (await session.execute(
                text("SELECT COUNT(*) FROM events WHERE CAST(timestamp AS timestamptz) >= NOW() - INTERVAL '24 hours'")
            )).scalar_one()

        return {
            "total_sessions":    total_sessions,
            "critical_sessions": critical_sessions,
            "cpu_stop_count":    cpu_stops,
            "events_24h":        events_24h,
            "timestamp":         datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        logger.warning("Initial stats error: %s", e)
        return None
