"""
manager/api/sensors.py — Sensor registry: list, token generation, revocation.
"""

from __future__ import annotations

import secrets
import shlex
import uuid
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import delete, select

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user, require_admin
from manager.security.audit import write_audit

router = APIRouter(prefix="/sensors", tags=["sensors"])


class GenerateTokenRequest(BaseModel):
    sensor_name: str


def _parse_manager_addr(addr: str) -> tuple[str, int]:
    host, sep, port_str = addr.rpartition(":")
    if not sep or not host or not port_str:
        raise ValueError("Expected host:port format.")
    try:
        port = int(port_str)
    except ValueError as exc:
        raise ValueError("Port must be numeric.") from exc
    if port < 1 or port > 65535:
        raise ValueError("Port must be between 1 and 65535.")
    return host, port


def _is_loopback_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ip_address(normalized).is_loopback
    except ValueError:
        return False


def _is_unspecified_host(host: str) -> bool:
    normalized = host.strip().strip("[]").lower()
    return normalized in {"0.0.0.0", "::", "*"}


def _slugify_sensor_name(name: str, fallback: str) -> str:
    slug = "".join(c.lower() if c.isalnum() else "-" for c in name).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return slug[:40] or fallback


def _build_deployment_command(
    *,
    sensor_name: str,
    sensor_id: str,
    join_token: str,
    sensor_cert_enc_key: str,
    manager_addr: str,
    sensor_image_ref: str,
) -> str:
    container_name = f"otrap-sensor-{_slugify_sensor_name(sensor_name, sensor_id[:8])}"
    parts = [
        "docker",
        "run",
        "-d",
        "--name",
        container_name,
        "--restart",
        "unless-stopped",
        "--network",
        "host",
        "--label",
        f"otrap.sensor_id={sensor_id}",
        "--label",
        f"otrap.sensor_name={sensor_name}",
        "-v",
        "/var/lib/otrap/sensor/certs:/etc/otrap/sensor/certs",
        "-e",
        f"SENSOR_MANAGER_URL={manager_addr}",
        "-e",
        f"SENSOR_JOIN_TOKEN={join_token}",
        "-e",
        f"SENSOR_NAME={sensor_name}",
        "-e",
        f"SENSOR_CERT_ENC_KEY={sensor_cert_enc_key}",
        "-e",
        "SENSOR_INSECURE_JOIN=true",
        "-e",
        "LOG_LEVEL=info",
        sensor_image_ref,
    ]
    return shlex.join(parts)


def _build_env_snippet(
    *,
    sensor_name: str,
    join_token: str,
    sensor_cert_enc_key: str,
    manager_addr: str,
    sensor_image_ref: str,
) -> str:
    return "\n".join([
        f"SENSOR_MANAGER_URL={manager_addr}",
        f"SENSOR_JOIN_TOKEN={join_token}",
        f"SENSOR_NAME={sensor_name}",
        f"SENSOR_CERT_ENC_KEY={sensor_cert_enc_key}",
        "SENSOR_INSECURE_JOIN=true",
        f"SENSOR_IMAGE_REF={sensor_image_ref}",
        "LOG_LEVEL=info",
    ])


def _build_warnings(*, manager_addr: str, grpc_host: str) -> list[str]:
    warnings: list[str] = []

    manager_host, _ = _parse_manager_addr(manager_addr)
    if _is_unspecified_host(manager_host):
        warnings.append(
            "SENSOR_PUBLIC_MANAGER_ADDR uses a wildcard host. Set it to the management server's reachable IP or DNS name."
        )

    if _is_loopback_host(manager_host):
        warnings.append(
            "SENSOR_PUBLIC_MANAGER_ADDR currently points to loopback. "
            "The generated command only works on the same host until you change it to the management server IP."
        )

    if grpc_host and _is_loopback_host(grpc_host):
        warnings.append(
            "GRPC_HOST is bound to loopback. Remote sensors cannot reach TCP/9443 until you set GRPC_HOST "
            "to the management server IP and rerun `docker compose up -d manager`."
        )

    return warnings


@router.get("")
async def list_sensors(
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    result = await db.execute(
        select(models.Sensor)
        .where(models.Sensor.status != "revoked")
        .order_by(models.Sensor.registered_at.desc())
    )
    sensors = result.scalars().all()
    redis = request.app.state.redis

    items = []
    for s in sensors:
        health_raw = await redis.get(f"sensor.health:{str(s.id)}")
        health = None
        if health_raw:
            import json
            health = json.loads(health_raw)

        items.append({
            "id":           str(s.id),
            "name":         s.name,
            "status":       s.status,
            "version":      s.version,
            "reported_ip":  s.reported_ip,
            "capabilities": s.capabilities,
            "last_seen_at": s.last_seen_at,
            "registered_at": s.registered_at,
            "health":       health,
        })

    return {"items": items}


@router.post("/token", status_code=status.HTTP_201_CREATED)
async def generate_join_token(
    payload: GenerateTokenRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    """Generate a single-use join token for a new sensor."""
    sensor_name = payload.sensor_name.strip()
    if not sensor_name:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "SENSOR_NAME_REQUIRED",
                "message": "sensor_name cannot be empty.",
            },
        )

    settings = request.app.state.settings
    manager_addr = settings.sensor_public_manager_addr.strip()
    if not manager_addr:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "SENSOR_PUBLIC_MANAGER_ADDR_MISSING",
                "message": (
                    "Set SENSOR_PUBLIC_MANAGER_ADDR in .env to the management server's reachable host:port, "
                    "then restart the Manager."
                ),
            },
        )
    try:
        manager_host, _ = _parse_manager_addr(manager_addr)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "SENSOR_PUBLIC_MANAGER_ADDR_INVALID",
                "message": f"Invalid SENSOR_PUBLIC_MANAGER_ADDR: {exc}",
            },
        ) from exc
    if _is_unspecified_host(manager_host):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "SENSOR_PUBLIC_MANAGER_ADDR_INVALID",
                "message": "SENSOR_PUBLIC_MANAGER_ADDR cannot use 0.0.0.0 or another wildcard host.",
            },
        )

    token = secrets.token_urlsafe(48)
    sensor_cert_enc_key = secrets.token_hex(32)
    token_hash = bcrypt.hashpw(token.encode(), bcrypt.gensalt(12)).decode()
    ttl_hours = int(settings.join_token_ttl_hours if hasattr(request.app.state, "settings") else 24)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat()

    sensor = models.Sensor(
        id=uuid.uuid4(),
        name=sensor_name,
        join_token_hash=token_hash,
        token_expires_at=expires_at,
        status="pending",
    )
    db.add(sensor)
    await db.commit()

    await write_audit(
        db, user,
        action="generate_sensor_token",
        target_type="sensor",
        target_id=str(sensor.id),
        detail={"sensor_name": sensor_name},
        source_ip=request.client.host if request.client else None,
    )

    warnings = _build_warnings(manager_addr=manager_addr, grpc_host=settings.grpc_host)
    sensor_id = str(sensor.id)
    sensor_image_ref = settings.sensor_image_ref

    return {
        "sensor_id":  sensor_id,
        "sensor_name": sensor_name,
        "join_token": token,      # Shown ONCE — operator must copy immediately
        "expires_at": expires_at,
        "sensor_cert_enc_key": sensor_cert_enc_key,
        "manager_addr": manager_addr,
        "sensor_image_ref": sensor_image_ref,
        "deployment_command": _build_deployment_command(
            sensor_name=sensor_name,
            sensor_id=sensor_id,
            join_token=token,
            sensor_cert_enc_key=sensor_cert_enc_key,
            manager_addr=manager_addr,
            sensor_image_ref=sensor_image_ref,
        ),
        "env_file_snippet": _build_env_snippet(
            sensor_name=sensor_name,
            join_token=token,
            sensor_cert_enc_key=sensor_cert_enc_key,
            manager_addr=manager_addr,
            sensor_image_ref=sensor_image_ref,
        ),
        "compose_command": "docker compose -f docker-compose.sensor.yml --env-file .env.sensor up -d",
        "warnings": warnings,
        "remote_ready": len(warnings) == 0,
        "warning":    "Store this token securely. It will not be shown again.",
    }


@router.delete("/{sensor_id}")
async def revoke_sensor(
    sensor_id: str,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    result = await db.execute(select(models.Sensor).where(models.Sensor.id == uuid.UUID(sensor_id)))
    sensor = result.scalar_one_or_none()
    if not sensor:
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND"})

    # Remove any active/health cache so an already-running sensor is forced to
    # revalidate against storage on its next heartbeat or reconnect attempt.
    await request.app.state.redis.delete(f"sensor.active:{sensor_id}")
    await request.app.state.redis.delete(f"sensor.health:{sensor_id}")
    await request.app.state.redis.delete(f"sensor.db_update_flag:{sensor_id}")

    await db.delete(sensor)
    await db.commit()

    await write_audit(
        db, user,
        action="delete_sensor",
        target_type="sensor",
        target_id=sensor_id,
        source_ip=request.client.host if request.client else None,
    )
    return {"ok": True}
