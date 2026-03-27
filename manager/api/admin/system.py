"""
manager/api/admin/system.py — System metadata, control-plane diagnostics, backup/restore.
"""

from __future__ import annotations

import asyncio
import gzip
import os
import pathlib
import re
import shutil
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, status
from fastapi.responses import FileResponse, JSONResponse

from manager.api.auth import require_admin, require_reauth
from manager.db.engine import get_db
from manager.security.audit import write_audit

router = APIRouter(prefix="/system", tags=["admin-system"])

BACKUP_DIR = pathlib.Path("/app/backups")
_SAFE_NAME = re.compile(r"^otrap_\d{8}_\d{6}\.sql\.gz$")


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _pg_env(request: Request) -> dict:
    s = request.app.state.settings
    return {
        **os.environ,
        "PGPASSWORD": s.postgres_password,
        "PGHOST":     s.postgres_host,
        "PGPORT":     str(s.postgres_port),
        "PGUSER":     s.postgres_user,
        "PGDATABASE": s.postgres_db,
    }


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
            "heartbeat_checker": "running" if getattr(request.app.state, "hb_task", None) and not request.app.state.hb_task.done() else "stopped",
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


# ─── Backup / Restore ────────────────────────────────────────────────────────

@router.get("/backups")
async def list_backups(
    request: Request,
    user=Depends(require_admin),
) -> dict:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    files = sorted(BACKUP_DIR.glob("otrap_*.sql.gz"), key=lambda p: p.stat().st_mtime, reverse=True)
    return {
        "backups": [
            {
                "filename": f.name,
                "size_bytes": f.stat().st_size,
                "created_at": datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc).isoformat(),
            }
            for f in files
        ]
    }


@router.post("/backups", status_code=status.HTTP_202_ACCEPTED)
async def create_backup(
    request: Request,
    db=Depends(get_db),
    user=Depends(require_reauth),
) -> dict:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    output_path = BACKUP_DIR / f"otrap_{timestamp}.sql.gz"
    env = _pg_env(request)

    try:
        proc = await asyncio.create_subprocess_exec(
            "pg_dump", "-Fp", "--no-password",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await proc.communicate()
        if proc.returncode != 0:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"pg_dump failed: {stderr.decode(errors='replace')[:500]}",
            )

        with gzip.open(output_path, "wb") as f:
            f.write(stdout)

        await write_audit(
            db,
            user,
            "create_backup",
            target_type="backup",
            target_id=output_path.name,
            detail={"result": "success", "size_bytes": output_path.stat().st_size},
            source_ip=_client_ip(request),
        )
    except HTTPException as exc:
        await write_audit(
            db,
            user,
            "create_backup",
            target_type="backup",
            target_id=output_path.name,
            detail={"result": "failed", "error": exc.detail},
            source_ip=_client_ip(request),
        )
        raise

    return {
        "filename": output_path.name,
        "size_bytes": output_path.stat().st_size,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


@router.get("/backups/{filename}")
async def download_backup(
    filename: str,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_reauth),
):
    try:
        if not _SAFE_NAME.match(filename):
            raise HTTPException(status_code=400, detail="Invalid filename")
        path = BACKUP_DIR / filename
        if not path.exists():
            raise HTTPException(status_code=404, detail="Backup not found")

        await write_audit(
            db,
            user,
            "download_backup",
            target_type="backup",
            target_id=filename,
            detail={"result": "success", "size_bytes": path.stat().st_size},
            source_ip=_client_ip(request),
        )
    except HTTPException as exc:
        await write_audit(
            db,
            user,
            "download_backup",
            target_type="backup",
            target_id=filename,
            detail={"result": "failed", "error": exc.detail},
            source_ip=_client_ip(request),
        )
        raise
    return FileResponse(
        path=str(path),
        media_type="application/gzip",
        filename=filename,
    )


@router.delete("/backups/{filename}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_backup(
    filename: str,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_reauth),
):
    try:
        if not _SAFE_NAME.match(filename):
            raise HTTPException(status_code=400, detail="Invalid filename")
        path = BACKUP_DIR / filename
        if not path.exists():
            raise HTTPException(status_code=404, detail="Backup not found")
        path.unlink()
        await write_audit(
            db,
            user,
            "delete_backup",
            target_type="backup",
            target_id=filename,
            detail={"result": "success"},
            source_ip=_client_ip(request),
        )
    except HTTPException as exc:
        await write_audit(
            db,
            user,
            "delete_backup",
            target_type="backup",
            target_id=filename,
            detail={"result": "failed", "error": exc.detail},
            source_ip=_client_ip(request),
        )
        raise


@router.post("/backups/{filename}/restore", status_code=status.HTTP_202_ACCEPTED)
async def restore_backup(
    filename: str,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_reauth),
) -> dict:
    try:
        if not _SAFE_NAME.match(filename):
            raise HTTPException(status_code=400, detail="Invalid filename")
        path = BACKUP_DIR / filename
        if not path.exists():
            raise HTTPException(status_code=404, detail="Backup not found")
        result = await _do_restore(request, path)
        await write_audit(
            db,
            user,
            "restore_backup",
            target_type="backup",
            target_id=filename,
            detail={"result": "success", "source": "stored_backup"},
            source_ip=_client_ip(request),
        )
        return result
    except HTTPException as exc:
        await write_audit(
            db,
            user,
            "restore_backup",
            target_type="backup",
            target_id=filename,
            detail={"result": "failed", "source": "stored_backup", "error": exc.detail},
            source_ip=_client_ip(request),
        )
        raise


@router.post("/restore/upload", status_code=status.HTTP_202_ACCEPTED)
async def restore_from_upload(
    file: UploadFile,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_reauth),
) -> dict:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    dest = BACKUP_DIR / f"otrap_{timestamp}.sql.gz"
    try:
        if not file.filename or not file.filename.endswith(".sql.gz"):
            raise HTTPException(status_code=400, detail="File must be a .sql.gz backup")
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        content = await file.read()
        dest.write_bytes(content)
        result = await _do_restore(request, dest)
        await write_audit(
            db,
            user,
            "restore_backup_upload",
            target_type="backup",
            target_id=dest.name,
            detail={
                "result": "success",
                "source": "uploaded_backup",
                "uploaded_filename": file.filename,
            },
            source_ip=_client_ip(request),
        )
        return result
    except HTTPException as exc:
        await write_audit(
            db,
            user,
            "restore_backup_upload",
            target_type="backup",
            target_id=dest.name,
            detail={
                "result": "failed",
                "source": "uploaded_backup",
                "uploaded_filename": file.filename,
                "error": exc.detail,
            },
            source_ip=_client_ip(request),
        )
        raise


async def _do_restore(request: Request, path: pathlib.Path) -> dict:
    env = _pg_env(request)

    # Wipe existing schema (avoids needing to drop/recreate the whole DB)
    wipe = await asyncio.create_subprocess_exec(
        "psql", "--no-password", "-c",
        "DROP SCHEMA public CASCADE; CREATE SCHEMA public;",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    _, wipe_err = await wipe.communicate()
    if wipe.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Schema wipe failed: {wipe_err.decode(errors='replace')[:500]}",
        )

    # Decompress and pipe into psql
    sql = gzip.decompress(path.read_bytes())
    restore = await asyncio.create_subprocess_exec(
        "psql", "--no-password",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
    )
    _, restore_err = await restore.communicate(input=sql)
    if restore.returncode != 0:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Restore failed: {restore_err.decode(errors='replace')[:500]}",
        )

    return {"restored_from": path.name, "status": "ok"}
