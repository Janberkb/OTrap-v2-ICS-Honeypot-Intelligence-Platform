# manager/api/health.py — Health aggregation API (extracted from sensors.py)
from fastapi import APIRouter, Depends, Request
from sqlalchemy import select, text as sa_text

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def get_health(request: Request, db=Depends(get_db)) -> dict:
    redis    = request.app.state.redis
    services = {}

    # ── Postgres ──────────────────────────────────────────────────────────────
    try:
        await db.execute(sa_text("SELECT 1"))
        services["postgres"] = {"status": "healthy", "detail": "Connection OK"}
    except Exception as e:
        services["postgres"] = {
            "status": "unhealthy", "detail": str(e),
            "fix": "Check POSTGRES_* environment variables and postgres container logs",
        }

    # ── Redis ─────────────────────────────────────────────────────────────────
    try:
        await redis.ping()
        services["redis"] = {"status": "healthy", "detail": "PONG received"}
    except Exception as e:
        services["redis"] = {"status": "unhealthy", "detail": str(e)}

    # ── Sensors ───────────────────────────────────────────────────────────────
    import json
    sensor_result = await db.execute(
        select(models.Sensor).where(models.Sensor.status == "active")
    )
    active_sensors = sensor_result.scalars().all()

    sensor_statuses = []
    for s in active_sensors:
        health_raw = await redis.get(f"sensor.health:{str(s.id)}")
        is_alive   = bool(health_raw)
        health_data = json.loads(health_raw) if health_raw else None
        sensor_statuses.append({
            "id":          str(s.id),
            "name":        s.name,
            "status":      "healthy" if is_alive else "offline",
            "last_seen":   s.last_seen_at,
            "port_status": health_data.get("port_status") if health_data else [],
        })

    active_count = sum(1 for sh in sensor_statuses if sh["status"] == "healthy")
    if not sensor_statuses:
        sensors_svc_status = "healthy"          # no sensors registered
    elif active_count == 0:
        sensors_svc_status = "unhealthy"        # all sensors offline
    elif active_count < len(sensor_statuses):
        sensors_svc_status = "degraded"         # some sensors offline
    else:
        sensors_svc_status = "healthy"          # all sensors online
    services["sensors"] = {
        "status":  sensors_svc_status,
        "sensors": sensor_statuses,
        "count":   active_count,
        "total":   len(sensor_statuses),
    }

    # ── LLM Engine (optional) ─────────────────────────────────────────────────
    import os, httpx
    if os.environ.get("LLM_ENABLED") == "true":
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(
                    f"{os.environ.get('LLM_ENGINE_URL', 'http://llm_engine:8001')}/health"
                )
            services["llm_engine"] = {
                "status": "healthy" if r.status_code == 200 else "unhealthy",
                "detail": f"HTTP {r.status_code}",
            }
        except Exception as e:
            services["llm_engine"] = {"status": "unhealthy", "detail": str(e)}
    else:
        services["llm_engine"] = {"status": "disabled"}

    overall = "healthy" if all(
        v.get("status") in ("healthy", "disabled")
        for v in services.values()
    ) else "degraded"

    return {"status": overall, "services": services}
