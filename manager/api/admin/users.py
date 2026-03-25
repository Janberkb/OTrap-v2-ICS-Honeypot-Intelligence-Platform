"""
manager/api/admin/users.py — User management (superadmin only).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, field_validator

from manager.db import models
from manager.db.engine import get_db
from manager.api.auth import require_admin, require_reauth
from manager.security.hashing import hash_bcrypt
from manager.security.audit import write_audit

router = APIRouter(prefix="/users", tags=["admin-users"])


class CreateUserRequest(BaseModel):
    username: str
    email: EmailStr
    password: str
    role: str = "user"

    @field_validator("role")
    @classmethod
    def valid_role(cls, v):
        if v not in ("user", "superadmin"):
            raise ValueError("Role must be user or superadmin")
        return v

    @field_validator("password")
    @classmethod
    def pw_length(cls, v):
        if len(v) < 12:
            raise ValueError("Password must be >= 12 chars")
        return v


class UpdateUserRequest(BaseModel):
    email: EmailStr | None = None
    role: str | None = None
    is_active: bool | None = None
    force_pw_reset: bool | None = None
    new_password: str | None = None

    @field_validator("new_password")
    @classmethod
    def pw_length(cls, v):
        if v is not None and len(v) < 12:
            raise ValueError("Password must be >= 12 chars")
        return v


@router.get("")
async def list_users(db=Depends(get_db), user=Depends(require_admin)) -> dict:
    users = await models.User.list_all(db)
    return {"items": [_user_dto(u) for u in users]}


@router.post("")
async def create_user(
    payload: CreateUserRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    existing = await models.User.get_by_username(db, payload.username)
    if existing:
        raise HTTPException(status_code=409, detail={"error": "USERNAME_TAKEN"})

    new_user = models.User(
        id=uuid.uuid4(),
        username=payload.username,
        email=payload.email,
        password_hash=hash_bcrypt(payload.password),
        role=payload.role,
    )
    db.add(new_user)
    await db.commit()

    await write_audit(
        db, user, "create_user",
        target_type="user", target_id=str(new_user.id),
        detail={"username": payload.username, "role": payload.role},
        source_ip=request.client.host if request.client else None,
    )
    return _user_dto(new_user)


@router.put("/{user_id}")
async def update_user(
    user_id: str,
    payload: UpdateUserRequest,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_admin),
) -> dict:
    target = await models.User.get_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND"})

    if payload.email is not None:
        target.email = payload.email
    if payload.role is not None:
        target.role = payload.role
    if payload.is_active is not None:
        target.is_active = payload.is_active
    if payload.force_pw_reset is not None:
        target.force_pw_reset = payload.force_pw_reset
    if payload.new_password is not None:
        target.password_hash = hash_bcrypt(payload.new_password)

    target.updated_at = datetime.now(timezone.utc).isoformat()
    await db.commit()

    await write_audit(db, user, "update_user", target_type="user", target_id=user_id,
                       detail=payload.model_dump(exclude_none=True))
    return _user_dto(target)


@router.delete("/{user_id}")
async def delete_user(
    user_id: str,
    request: Request,
    db=Depends(get_db),
    user=Depends(require_reauth),   # Requires recent reauth
) -> dict:
    if user_id == str(user.id):
        raise HTTPException(status_code=400, detail={"error": "CANNOT_DELETE_SELF"})

    target = await models.User.get_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail={"error": "NOT_FOUND"})

    await db.delete(target)
    await db.commit()

    await write_audit(db, user, "delete_user", target_type="user", target_id=user_id,
                       detail={"username": target.username})
    return {"ok": True}


def _user_dto(u: models.User) -> dict:
    return {
        "id":             str(u.id),
        "username":       u.username,
        "email":          u.email,
        "role":           u.role,
        "is_active":      u.is_active,
        "force_pw_reset": u.force_pw_reset,
        "created_at":     u.created_at,
        "last_login_at":  u.last_login_at,
    }
