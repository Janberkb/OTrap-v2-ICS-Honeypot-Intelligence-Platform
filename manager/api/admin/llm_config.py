"""
manager/api/admin/llm_config.py — Admin endpoints for LLM configuration.

Endpoints:
  GET  /admin/llm-config          — read current config
  PATCH /admin/llm-config         — update config (live effect, persisted to DB)
  POST  /admin/llm-config/test    — test connectivity to LLM backend
"""

from __future__ import annotations

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import require_admin, require_reauth
from manager.security.audit import write_audit

router = APIRouter(prefix="/llm-config", tags=["admin-llm"])


class LLMConfigUpdate(BaseModel):
    llm_enabled: bool | None = None
    llm_backend: str | None = None       # "ollama" | "lmstudio"
    llm_base_url: str | None = None
    llm_default_model: str | None = None


class LLMTestRequest(BaseModel):
    base_url: str
    backend: str = "ollama"


def _apply_to_settings(request: Request, cfg: models.AppConfig) -> None:
    """Push DB config values into the live settings singleton."""
    from manager.config import settings as _s

    s = request.app.state.settings
    for attr in ("llm_enabled", "llm_backend", "llm_base_url", "llm_default_model"):
        db_val = getattr(cfg, attr, None)
        if db_val is not None:
            setattr(s, attr, db_val)
            setattr(_s, attr, db_val)  # also update module-level singleton


@router.get("")
async def get_llm_config(
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    cfg = await models.AppConfig.get(db)
    s = request.app.state.settings
    return {
        "llm_enabled":       cfg.llm_enabled if cfg.llm_enabled is not None else s.llm_enabled,
        "llm_backend":       cfg.llm_backend or s.llm_backend,
        "llm_base_url":      cfg.llm_base_url or "",
        "llm_default_model": cfg.llm_default_model or s.llm_default_model,
        # Env-var defaults (read-only reference)
        "env_defaults": {
            "llm_enabled":       s.llm_enabled,
            "llm_backend":       s.llm_backend,
            "ollama_base_url":   s.ollama_base_url,
            "lm_studio_base_url": s.lm_studio_base_url,
            "llm_default_model": s.llm_default_model,
        },
    }


@router.patch("")
async def update_llm_config(
    body: LLMConfigUpdate,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_reauth),
) -> dict:
    update_kwargs: dict = {}
    if body.llm_enabled is not None:
        update_kwargs["llm_enabled"] = body.llm_enabled
    if body.llm_backend is not None:
        if body.llm_backend not in ("ollama", "lmstudio"):
            raise HTTPException(400, {"error": "llm_backend must be 'ollama' or 'lmstudio'"})
        update_kwargs["llm_backend"] = body.llm_backend
    if body.llm_base_url is not None:
        update_kwargs["llm_base_url"] = body.llm_base_url.strip()
    if body.llm_default_model is not None:
        update_kwargs["llm_default_model"] = body.llm_default_model.strip()

    cfg = await models.AppConfig.upsert(db, **update_kwargs)
    await db.commit()

    _apply_to_settings(request, cfg)
    await write_audit(
        db,
        user,
        "update_llm_config",
        target_type="config",
        target_id="llm",
        detail={
            "updated": list(update_kwargs.keys()),
            "llm_enabled": cfg.llm_enabled,
            "llm_backend": cfg.llm_backend,
            "llm_base_url": cfg.llm_base_url,
            "llm_default_model": cfg.llm_default_model,
        },
        source_ip=request.client.host if request.client else None,
    )

    return {"ok": True, "updated": list(update_kwargs.keys())}


@router.post("/test")
async def test_llm_connection(
    body: LLMTestRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    """Probe the given base URL to check if an LLM backend is reachable."""
    base = body.base_url.rstrip("/")

    # Ollama: GET /api/tags  |  LM Studio: GET /v1/models
    if body.backend == "lmstudio":
        probe_url = f"{base}/v1/models"
    else:
        probe_url = f"{base}/api/tags"

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(probe_url)
        if r.status_code == 200:
            # Try to extract model list
            data = r.json()
            if body.backend == "lmstudio":
                models_list = sorted(m["id"] for m in data.get("data", []))
            else:
                models_list = sorted(m.get("name", "") for m in data.get("models", []))
            await write_audit(
                db,
                user,
                "test_llm_connection",
                target_type="config",
                target_id="llm",
                detail={
                    "result": "success",
                    "backend": body.backend,
                    "base_url": base,
                    "status_code": r.status_code,
                    "models_count": len(models_list),
                },
                source_ip=request.client.host if request.client else None,
            )
            return {"ok": True, "status_code": r.status_code, "models": models_list}
        await write_audit(
            db,
            user,
            "test_llm_connection",
            target_type="config",
            target_id="llm",
            detail={
                "result": "failed",
                "backend": body.backend,
                "base_url": base,
                "status_code": r.status_code,
                "detail": r.text[:200],
            },
            source_ip=request.client.host if request.client else None,
        )
        return {"ok": False, "status_code": r.status_code, "detail": r.text[:200]}
    except Exception as e:
        await write_audit(
            db,
            user,
            "test_llm_connection",
            target_type="config",
            target_id="llm",
            detail={
                "result": "failed",
                "backend": body.backend,
                "base_url": base,
                "detail": str(e),
            },
            source_ip=request.client.host if request.client else None,
        )
        return {"ok": False, "status_code": None, "detail": str(e)}
