"""
manager/api/llm.py — Local LLM integration endpoints.

All analysis is user-triggered. Supports Ollama and LM Studio
(both expose an OpenAI-compatible REST API).

Endpoints:
  GET  /llm/models                       — list available models
  GET  /llm/outputs/session/{id}         — past analyses for a session
  POST /llm/analyze/session/{id}         — stream session analysis (SSE)
  POST /llm/analyze/attacker/{ip}        — stream attacker profile analysis (SSE)
"""

from __future__ import annotations

import asyncio
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import func, select

from manager.config import settings
from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import get_current_user

router = APIRouter(prefix="/llm", tags=["llm"])

_VALID_ANALYSIS_TYPES = {"threat_narrative", "triage_assist"}


class AnalyzeSessionRequest(BaseModel):
    analysis_type: str = "threat_narrative"
    model: str = ""


class AnalyzeAttackerRequest(BaseModel):
    model: str = ""


def _guard_llm() -> None:
    if not settings.llm_enabled:
        raise HTTPException(
            503,
            {
                "error": "LLM_DISABLED",
                "detail": (
                    "Set LLM_ENABLED=true and configure OLLAMA_BASE_URL "
                    "(or LM_STUDIO_BASE_URL with LLM_BACKEND=lmstudio) in your .env file."
                ),
            },
        )


# ─── Model listing ────────────────────────────────────────────────────────────

@router.get("/models")
async def list_models(user=Depends(get_current_user)) -> dict:
    """Return available models from the configured local LLM backend."""
    if not settings.llm_enabled:
        return {"models": [], "backend": settings.llm_backend, "enabled": False,
                "default_model": settings.llm_default_model}
    from manager.utils.llm_client import get_llm_client
    try:
        client = get_llm_client()
        model_list = await client.list_models()
        return {
            "models":        model_list,
            "backend":       settings.llm_backend,
            "enabled":       True,
            "default_model": settings.llm_default_model,
        }
    except Exception as e:
        return {
            "models":        [],
            "backend":       settings.llm_backend,
            "enabled":       True,
            "error":         str(e),
            "default_model": settings.llm_default_model,
        }


# ─── Past outputs ─────────────────────────────────────────────────────────────

@router.get("/outputs/session/{session_id}")
async def get_session_outputs(
    session_id: str,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> dict:
    """Return previously saved LLM analyses for a session."""
    outputs = await models.LLMOutput.list_for_session(db, session_id)
    return {
        "items": [
            {
                "id":               str(o.id),
                "output_type":      o.output_type,
                "content":          o.content,
                "model_used":       o.model_used,
                "prompt_tokens":    o.prompt_tokens,
                "completion_tokens": o.completion_tokens,
                "created_at":       o.created_at,
            }
            for o in outputs
        ]
    }


# ─── Session analysis ─────────────────────────────────────────────────────────

@router.post("/analyze/session/{session_id}")
async def analyze_session(
    session_id: str,
    body: AnalyzeSessionRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> StreamingResponse:
    """
    Run LLM analysis on a honeypot session.

    Streams SSE response. Saves completed analysis to llm_outputs.
    analysis_type: "threat_narrative" | "triage_assist"
    """
    _guard_llm()

    if body.analysis_type not in _VALID_ANALYSIS_TYPES:
        raise HTTPException(400, {"error": "INVALID_ANALYSIS_TYPE",
                                  "valid": list(_VALID_ANALYSIS_TYPES)})

    # Fetch session
    result = await db.execute(
        select(models.Session).where(models.Session.id == session_id)
    )
    sess = result.scalar_one_or_none()
    if sess is None:
        raise HTTPException(404, {"error": "NOT_FOUND"})

    # Fetch events + IOCs concurrently
    events_raw, iocs_raw = await asyncio.gather(
        models.Event.list_for_session(db, session_id),
        models.IOC.list_for_session(db, session_id),
    )

    # Geo enrichment
    from manager.utils.geoip import lookup
    geo = await lookup(sess.source_ip, request.app.state.redis)

    session_dict = {
        "source_ip":         sess.source_ip,
        "primary_protocol":  sess.primary_protocol,
        "severity":          sess.severity,
        "attack_phase":      sess.attack_phase,
        "duration_seconds":  sess.duration_seconds,
        "event_count":       sess.event_count,
        "ioc_count":         sess.ioc_count,
        "cpu_stop_occurred": sess.cpu_stop_occurred,
        "triage_status":     getattr(sess, "triage_status", "new"),
        "mitre_techniques":  sess.mitre_techniques or [],
        "geo":               geo,
    }
    events_dicts = [
        {
            "timestamp":   e.timestamp,
            "event_type":  e.event_type,
            "severity":    e.severity,
            "raw_summary": e.raw_summary or "",
        }
        for e in events_raw
    ]
    iocs_dicts = [
        {
            "ioc_type":   i.ioc_type,
            "value":      i.value,
            "context":    i.context,
            "confidence": i.confidence,
        }
        for i in iocs_raw
    ]

    # Build prompt
    from manager.utils.llm_prompts import build_session_narrative_prompt, build_triage_prompt
    if body.analysis_type == "triage_assist":
        messages = build_triage_prompt(session_dict, events_dicts, iocs_dicts)
    else:
        messages = build_session_narrative_prompt(
            session_dict, events_dicts, iocs_dicts, session_dict["mitre_techniques"]
        )

    model = body.model.strip() or settings.llm_default_model
    db_factory = request.app.state.db_factory

    return StreamingResponse(
        _stream_session(messages, model, session_id, body.analysis_type, db_factory),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── Attacker analysis ────────────────────────────────────────────────────────

@router.post("/analyze/attacker/{ip:path}")
async def analyze_attacker(
    ip: str,
    body: AnalyzeAttackerRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(get_current_user),
) -> StreamingResponse:
    """
    Run LLM analysis on an attacker IP profile.

    Streams SSE response. Saves completed analysis to llm_outputs.
    """
    _guard_llm()

    # Aggregate profile stats
    stats = await db.execute(
        select(
            func.count(models.Session.id).label("session_count"),
            func.sum(models.Session.event_count).label("event_count"),
            func.sum(models.Session.ioc_count).label("ioc_count"),
            func.min(models.Session.started_at).label("first_seen"),
            func.max(models.Session.started_at).label("last_seen"),
            func.bool_or(models.Session.cpu_stop_occurred).label("cpu_stop_ever"),
        ).where(models.Session.source_ip == ip)
    )
    row = stats.one()

    sev_rows = await db.execute(
        select(models.Session.severity, func.count(models.Session.id).label("cnt"))
        .where(models.Session.source_ip == ip)
        .group_by(models.Session.severity)
    )
    severity_dist = {r.severity: int(r.cnt) for r in sev_rows}

    proto_rows = await db.execute(
        select(models.Session.primary_protocol, func.count(models.Session.id).label("cnt"))
        .where(models.Session.source_ip == ip)
        .group_by(models.Session.primary_protocol)
        .order_by(func.count(models.Session.id).desc())
    )
    protocol_dist = [{"protocol": r.primary_protocol or "unknown", "count": int(r.cnt)} for r in proto_rows]

    phase_rows = await db.execute(
        select(models.Session.attack_phase)
        .where(models.Session.source_ip == ip)
        .distinct()
    )
    phases = [r.attack_phase for r in phase_rows if r.attack_phase]

    # Recent sessions (last 10)
    recent_q = await db.execute(
        select(models.Session)
        .where(models.Session.source_ip == ip)
        .order_by(models.Session.started_at.desc())
        .limit(10)
    )
    recent_sessions = [
        {
            "started_at":       s.started_at,
            "primary_protocol": s.primary_protocol,
            "severity":         s.severity,
            "attack_phase":     s.attack_phase,
            "event_count":      s.event_count,
        }
        for s in recent_q.scalars().all()
    ]

    # IOCs linked to this IP (across all sessions)
    ioc_q = await db.execute(
        select(models.IOC.ioc_type, models.IOC.value)
        .join(models.Session, models.IOC.session_id == models.Session.id)
        .where(models.Session.source_ip == ip)
        .limit(20)
    )
    all_iocs = [{"ioc_type": r.ioc_type, "value": r.value} for r in ioc_q]

    # Geo + threat intel (concurrent)
    from manager.utils.geoip import lookup
    from manager.utils.threat_intel import lookup_threat_intel

    redis = request.app.state.redis
    geo, threat_intel = await asyncio.gather(
        lookup(ip, redis),
        lookup_threat_intel(ip, redis),
    )

    profile = {
        "session_count": int(row.session_count or 0),
        "event_count":   int(row.event_count or 0),
        "ioc_count":     int(row.ioc_count or 0),
        "first_seen":    row.first_seen,
        "last_seen":     row.last_seen,
        "cpu_stop_ever": bool(row.cpu_stop_ever),
        "severity_dist": severity_dist,
        "protocol_dist": protocol_dist,
        "attack_phases": phases,
    }

    from manager.utils.llm_prompts import build_attacker_prompt
    messages = build_attacker_prompt(ip, geo, threat_intel, profile, recent_sessions, all_iocs)
    model = body.model.strip() or settings.llm_default_model
    db_factory = request.app.state.db_factory

    return StreamingResponse(
        _stream_attacker(messages, model, ip, db_factory),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ─── SSE streaming generators ─────────────────────────────────────────────────

async def _stream_session(
    messages: list[dict],
    model: str,
    session_id: str,
    analysis_type: str,
    db_factory,
):
    """Async generator that streams LLM output as SSE and saves on completion."""
    from manager.utils.llm_client import get_llm_client
    client = get_llm_client()
    full_text = ""

    try:
        async for chunk in client.stream_chat(messages, model):
            full_text += chunk
            yield f"data: {json.dumps(chunk)}\n\n"
    except Exception as e:
        err_chunk = f"\n\n[Error communicating with LLM: {e}]"
        full_text += err_chunk
        yield f"data: {json.dumps(err_chunk)}\n\n"

    yield "data: [DONE]\n\n"

    # Persist to DB after stream completes
    if full_text:
        try:
            async with db_factory() as save_db:
                save_db.add(
                    models.LLMOutput(
                        id=uuid.uuid4(),
                        session_id=session_id,
                        output_type=analysis_type,
                        content=full_text,
                        model_used=model,
                        created_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
                await save_db.commit()
        except Exception:
            pass  # Don't surface DB errors to the already-completed SSE stream


async def _stream_attacker(
    messages: list[dict],
    model: str,
    ip: str,
    db_factory,
):
    """Async generator for attacker profile analysis SSE stream."""
    from manager.utils.llm_client import get_llm_client
    client = get_llm_client()
    full_text = ""

    try:
        async for chunk in client.stream_chat(messages, model):
            full_text += chunk
            yield f"data: {json.dumps(chunk)}\n\n"
    except Exception as e:
        err_chunk = f"\n\n[Error communicating with LLM: {e}]"
        full_text += err_chunk
        yield f"data: {json.dumps(err_chunk)}\n\n"

    yield "data: [DONE]\n\n"

    if full_text:
        try:
            async with db_factory() as save_db:
                save_db.add(
                    models.LLMOutput(
                        id=uuid.uuid4(),
                        session_id=None,
                        output_type=f"attacker_profile:{ip}",
                        content=full_text,
                        model_used=model,
                        created_at=datetime.now(timezone.utc).isoformat(),
                    )
                )
                await save_db.commit()
        except Exception:
            pass
