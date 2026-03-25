"""
manager/api/auth.py — Authentication endpoints.

Stable error codes:
  INVALID_CREDENTIALS | AUTH_REQUIRED | CSRF_REQUIRED | CSRF_FAILED
  ADMIN_REQUIRED | REAUTH_REQUIRED | REAUTH_FAILED | VALIDATION_ERROR | NOT_FOUND
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, EmailStr, field_validator

from manager.db import models
from manager.db.engine import get_db
from manager.security.hashing import verify_bcrypt, hash_bcrypt
from manager.security.csrf import generate_csrf_token, CSRF_COOKIE
from manager.security.audit import write_audit

router = APIRouter(prefix="/auth", tags=["auth"])

# ─── Session management ───────────────────────────────────────────────────────

SESSION_COOKIE   = "otrap_session"
REAUTH_COOKIE    = "otrap_reauth"
SESSION_MAX_AGE  = 8 * 3600   # 8 hours
REAUTH_VALID_SEC = 300        # 5 minutes


def _cookie_secure(request: Request) -> bool:
    settings = getattr(request.app.state, "settings", None)
    return True if settings is None else bool(settings.session_secure)


def _set_session_cookie(response: Response, session_token: str, secure: bool = True) -> None:
    response.set_cookie(
        SESSION_COOKIE,
        session_token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )


def _clear_session(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE, path="/")
    response.delete_cookie(REAUTH_COOKIE, path="/")
    response.delete_cookie(CSRF_COOKIE, path="/")


async def get_current_user(request: Request, db=Depends(get_db)) -> models.User:
    """Dependency: resolve authenticated user from session cookie via Redis."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(status_code=401, detail={"error": "AUTH_REQUIRED"})

    redis = request.app.state.redis
    user_id = await redis.get(f"session:{token}")
    if not user_id:
        raise HTTPException(status_code=401, detail={"error": "AUTH_REQUIRED"})

    user = await models.User.get_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail={"error": "AUTH_REQUIRED"})

    return user


async def require_admin(user: models.User = Depends(get_current_user)) -> models.User:
    if user.role != "superadmin":
        raise HTTPException(status_code=403, detail={"error": "ADMIN_REQUIRED"})
    return user


async def require_reauth(request: Request, user: models.User = Depends(get_current_user)) -> models.User:
    """Verify that the user re-authenticated within the last 5 minutes."""
    redis = request.app.state.redis
    key   = f"reauth:{str(user.id)}"
    if not await redis.exists(key):
        raise HTTPException(status_code=403, detail={"error": "REAUTH_REQUIRED"})
    return user


# ─── Schemas ─────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def pw_strength(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        return v


class ReauthRequest(BaseModel):
    password: str


class ForgotPasswordRequest(BaseModel):
    username: str


class ResetPasswordRequest(BaseModel):
    token: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def pw_strength(cls, v: str) -> str:
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters")
        return v


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.post("/login")
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db=Depends(get_db),
) -> dict:
    redis = request.app.state.redis

    # Rate limit: 5 attempts / 60s per IP
    ip        = request.client.host if request.client else "unknown"
    rate_key  = f"login_rate:{ip}"
    attempts  = await redis.incr(rate_key)
    if attempts == 1:
        await redis.expire(rate_key, 60)
    if attempts > 5:
        raise HTTPException(status_code=429, detail={"error": "RATE_LIMITED"})

    user = await models.User.get_by_username(db, payload.username)
    if not user or not verify_bcrypt(payload.password, user.password_hash):
        await write_audit(db, None, "login_failed",
                          detail={"username": payload.username}, source_ip=ip)
        raise HTTPException(
            status_code=401,
            detail={"error": "INVALID_CREDENTIALS", "message": "Invalid username or password"},
        )

    if not user.is_active:
        await write_audit(db, user, "login_failed",
                          detail={"reason": "account_inactive"}, source_ip=ip)
        raise HTTPException(status_code=401, detail={"error": "INVALID_CREDENTIALS"})

    # Successful authentication resets the IP-based login limiter so routine
    # operator actions like repeated sensor onboarding do not lock themselves out.
    await redis.delete(rate_key)

    # Create session in Redis (TTL = SESSION_MAX_AGE)
    token = secrets.token_urlsafe(48)
    await redis.setex(f"session:{token}", SESSION_MAX_AGE, str(user.id))

    # Update last_login
    user.last_login_at = datetime.now(timezone.utc).isoformat()
    await db.commit()

    # CSRF token
    secure = _cookie_secure(request)
    csrf = generate_csrf_token()
    response.set_cookie(
        CSRF_COOKIE, csrf,
        max_age=SESSION_MAX_AGE,
        httponly=False,  # JS must be able to read it
        secure=secure,
        samesite="strict",
        path="/",
    )

    _set_session_cookie(response, token, secure=secure)
    await write_audit(db, user, "login", source_ip=ip)

    return {
        "id":       str(user.id),
        "username": user.username,
        "email":    user.email,
        "role":     user.role,
    }


@router.post("/logout")
async def logout(
    request: Request,
    response: Response,
    user: models.User = Depends(get_current_user),
    db=Depends(get_db),
) -> dict:
    token = request.cookies.get(SESSION_COOKIE, "")
    await request.app.state.redis.delete(f"session:{token}")
    _clear_session(response)
    await write_audit(db, user, "logout")
    return {"ok": True}


@router.get("/me")
async def me(user: models.User = Depends(get_current_user)) -> dict:
    return {
        "id":             str(user.id),
        "username":       user.username,
        "email":          user.email,
        "role":           user.role,
        "force_pw_reset": user.force_pw_reset,
        "last_login_at":  user.last_login_at,
    }


@router.get("/csrf-token")
async def csrf_token(request: Request, response: Response) -> dict:
    csrf = generate_csrf_token()
    response.set_cookie(
        CSRF_COOKIE, csrf,
        httponly=False,
        secure=_cookie_secure(request),
        samesite="strict",
        path="/",
    )
    return {"csrf_token": csrf}


@router.post("/reauth")
async def reauth(
    payload: ReauthRequest,
    request: Request,
    user: models.User = Depends(get_current_user),
    db=Depends(get_db),
) -> dict:
    ip = request.client.host if request.client else "unknown"
    if not verify_bcrypt(payload.password, user.password_hash):
        await write_audit(db, user, "reauth_failed", source_ip=ip)
        raise HTTPException(status_code=403, detail={"error": "REAUTH_FAILED"})

    # Mark reauth in Redis for 5 minutes
    await request.app.state.redis.setex(f"reauth:{str(user.id)}", REAUTH_VALID_SEC, "1")
    await write_audit(db, user, "reauth", source_ip=ip)
    return {"ok": True, "valid_for_seconds": REAUTH_VALID_SEC}


PW_RESET_TTL = 3600  # 1 hour


@router.post("/forgot-password")
async def forgot_password(
    payload: ForgotPasswordRequest,
    request: Request,
    db=Depends(get_db),
) -> dict:
    """
    If SMTP is configured: generate a reset token and email it to the user.
    If SMTP is not configured: return smtp_required so the UI can show
    'contact your administrator'.
    Always returns the same envelope so as not to reveal whether the account exists.
    """
    from manager.db import models as m
    cfg = await m.SMTPConfig.get(db)
    smtp_ok = bool(cfg and cfg.enabled and cfg.host)

    if not smtp_ok:
        return {"smtp_required": True}

    user = await m.User.get_by_username(db, payload.username)
    if user and user.is_active and user.email:
        token = secrets.token_urlsafe(32)
        redis = request.app.state.redis
        await redis.setex(f"pw_reset:{token}", PW_RESET_TTL, str(user.id))
        try:
            from manager.notifications.smtp_sender import send_reset_email
            send_reset_email(cfg, user, token)
        except Exception:
            pass  # Don't leak send errors

    # Always return the same message
    return {"ok": True}


@router.post("/reset-password")
async def reset_password(
    payload: ResetPasswordRequest,
    request: Request,
    db=Depends(get_db),
) -> dict:
    redis = request.app.state.redis
    key   = f"pw_reset:{payload.token}"
    user_id = await redis.get(key)
    if not user_id:
        raise HTTPException(status_code=400, detail={"error": "INVALID_TOKEN", "message": "Reset link is invalid or has expired"})

    user = await models.User.get_by_id(db, user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=400, detail={"error": "INVALID_TOKEN"})

    user.password_hash  = hash_bcrypt(payload.new_password)
    user.force_pw_reset = False
    user.updated_at     = datetime.now(timezone.utc).isoformat()
    await db.commit()
    await redis.delete(key)

    await write_audit(db, user, "reset_password")
    return {"ok": True}


@router.post("/change-password")
async def change_password(
    payload: ChangePasswordRequest,
    request: Request,
    user: models.User = Depends(get_current_user),
    db=Depends(get_db),
) -> dict:
    # Requires recent reauth
    redis = request.app.state.redis
    if not await redis.exists(f"reauth:{str(user.id)}"):
        raise HTTPException(status_code=403, detail={"error": "REAUTH_REQUIRED"})

    if not verify_bcrypt(payload.current_password, user.password_hash):
        raise HTTPException(status_code=403, detail={"error": "INVALID_CREDENTIALS"})

    user.password_hash  = hash_bcrypt(payload.new_password)
    user.force_pw_reset = False
    user.updated_at     = datetime.now(timezone.utc).isoformat()
    await db.commit()

    await write_audit(db, user, "change_password")
    return {"ok": True}
