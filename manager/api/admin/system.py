"""
manager/api/admin/system.py — System metadata and control-plane diagnostics.
"""

from __future__ import annotations

import os

from fastapi import APIRouter, Depends, Request

from manager.api.auth import require_admin

router = APIRouter(prefix="/system", tags=["admin-system"])


@router.get("")
async def get_system_summary(
    request: Request,
    user=Depends(require_admin),
) -> dict:
    settings = request.app.state.settings
    analyzer_task = getattr(request.app.state, "analyzer_task", None)
    ca_persisted = bool(os.environ.get("GRPC_CA_KEY_B64") and os.environ.get("GRPC_CA_CERT_B64"))
    cors_origins = [origin.strip() for origin in settings.cors_origins.split(",") if origin.strip()]

    return {
        "product": {
            "name": "OTrap Manager",
            "version": request.app.version,
            "build_ref": os.environ.get("OTRAP_BUILD_REF", "source-tree"),
            "license_tier": os.environ.get("OTRAP_LICENSE_TIER", "self-hosted"),
            "deployment_mode": os.environ.get("OTRAP_DEPLOYMENT_MODE", "single-node"),
        },
        "pki": {
            "ca_mode": "persisted" if ca_persisted else "ephemeral",
            "ca_persisted": ca_persisted,
            "grpc_bind": f"{settings.grpc_host}:{settings.grpc_port}",
            "public_manager_addr": settings.sensor_public_manager_addr,
        },
        "defaults": {
            "join_token_ttl_hours": settings.join_token_ttl_hours,
            "session_max_age_hours": settings.session_max_age_hours,
            "sensor_image_ref": settings.sensor_image_ref,
            "session_secure": settings.session_secure,
            "docs_enabled": settings.docs_enabled,
        },
        "background_jobs": {
            "analyzer_worker": "running" if analyzer_task and not analyzer_task.done() else "stopped",
            "llm_engine": "enabled" if settings.llm_enabled else "disabled",
        },
        "retention_policy": {
            "mode": "manual",
            "detail": "Session and event retention are managed manually at the database/volume level.",
        },
        "backup_restore": {
            "mode": "manual",
            "detail": "Use Postgres dumps and Docker volume backups for restore points.",
        },
        "cluster": {
            "mode": "single-node",
            "detail": "Cluster orchestration and license controls are not configured in this deployment.",
        },
        "diagnostics": {
            "management_api": f"{settings.management_host}:{settings.management_port}",
            "grpc_listener": f"{settings.grpc_host}:{settings.grpc_port}",
            "sensor_public_manager_addr": settings.sensor_public_manager_addr,
            "cors_origins": cors_origins,
            "docs_enabled": settings.docs_enabled,
        },
    }
