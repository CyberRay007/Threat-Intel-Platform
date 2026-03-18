import re
import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import uuid4

from app.database.session import get_db
from app.database.models import APIKey, Organization, Role, User
from app.core.security import hash_password, verify_password
from app.core.jwt import create_access_token
from app.core.logging import logger
from app.dependencies import get_current_user, require_permission
from app.core.entitlements import check_quota
from app.utils.errors import E, api_error
from app.core.audit import write_audit_event
from app.schemas.auth_schema import APIKeyCreateRequest, APIKeyCreateResponse, APIKeyListItem, Token, UserCreate, UserResponse

router = APIRouter()


def _validate_password_strength(password: str) -> None:
    checks = {
        "minimum length of 8": len(password) >= 8,
        "one uppercase letter": bool(re.search(r"[A-Z]", password)),
        "one lowercase letter": bool(re.search(r"[a-z]", password)),
        "one number": bool(re.search(r"[0-9]", password)),
        "one special character": bool(re.search(r"[^A-Za-z0-9]", password)),
    }
    missing = [name for name, ok in checks.items() if not ok]
    if missing:
        raise HTTPException(
            status_code=422,
            detail=f"Password must include {', '.join(missing)}",
        )


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(user_in: UserCreate, request: Request, db: AsyncSession = Depends(get_db)):
    _validate_password_strength(user_in.password)

    # Check if user exists
    result = await db.execute(select(User).filter_by(email=user_in.email))
    existing = result.scalar_one_or_none()
    if existing:
        raise HTTPException(status_code=400, detail="User already exists")

    org = Organization(id=uuid4(), name=f"{user_in.email.split('@')[0]}-org")
    db.add(org)
    await db.flush()

    user = User(
        email=user_in.email,
        password_hash=hash_password(user_in.password),
        org_id=org.id,
        role=Role.ADMIN.value,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    await write_audit_event(
        db,
        action="user_registered",
        resource_type="user",
        resource_id=str(user.id),
        org_id=user.org_id,
        user_id=user.id,
        request_id=getattr(request.state, "request_id", None),
        details={"email": user.email},
    )
    await db.commit()
    logger.info(
        "user_registered",
        extra={"extra_payload": {"event": "user_registered", "user_id": user.id, "org_id": str(user.org_id)}},
    )
    return user


@router.post("/login", response_model=Token)
async def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).filter_by(email=form_data.username))
    user = result.scalar_one_or_none()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token({
        "sub": str(user.id),
        "org_id": str(user.org_id),
        "role": user.role,
    })
    logger.info(
        "user_login_success",
        extra={"extra_payload": {"event": "user_login_success", "user_id": user.id, "org_id": str(user.org_id)}},
    )
    await write_audit_event(
        db,
        action="user_login",
        resource_type="auth",
        resource_id=str(user.id),
        org_id=user.org_id,
        user_id=user.id,
        request_id=getattr(request.state, "request_id", None),
        details={"email": user.email},
    )
    await db.commit()
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/api-keys", response_model=APIKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    payload: APIKeyCreateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("admin:all")),
):
    org_row = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
    org = org_row.scalar_one_or_none()
    await check_quota(db, current_user.org_id, "api_keys", plan_name=(org.plan if org else "free"))

    raw_key = f"tip_{secrets.token_urlsafe(32)}"
    key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    record = APIKey(
        org_id=current_user.org_id,
        key_hash=key_hash,
        permissions=payload.permissions,
    )
    db.add(record)
    await db.commit()
    await db.refresh(record)
    await write_audit_event(
        db,
        action="api_key_created",
        resource_type="api_key",
        resource_id=str(record.id),
        org_id=record.org_id,
        user_id=current_user.id,
        request_id=getattr(request.state, "request_id", None),
        details={"permissions": payload.permissions},
    )
    await db.commit()
    logger.info(
        "api_key_created",
        extra={"extra_payload": {"event": "api_key_created", "api_key_id": record.id, "org_id": str(record.org_id), "created_by": current_user.id}},
    )
    return APIKeyCreateResponse(
        id=record.id,
        org_id=str(record.org_id),
        key=raw_key,
        permissions=payload.permissions,
    )


@router.get("/api-keys", response_model=list[APIKeyListItem])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("admin:all")),
):
    rows = await db.execute(select(APIKey).where(APIKey.org_id == current_user.org_id).order_by(APIKey.id.desc()))
    items = rows.scalars().all()
    return [
        APIKeyListItem(
            id=item.id,
            org_id=str(item.org_id),
            permissions=item.permissions or [],
            last_used=item.last_used.isoformat() if item.last_used else None,
        )
        for item in items
    ]


@router.delete("/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(
    key_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("admin:all")),
):
    row = await db.execute(select(APIKey).where(APIKey.id == key_id, APIKey.org_id == current_user.org_id))
    item = row.scalar_one_or_none()
    if not item:
        raise api_error(E.API_KEY_NOT_FOUND)
    logger.info(
        "api_key_revoked",
        extra={"extra_payload": {"event": "api_key_revoked", "api_key_id": item.id, "org_id": str(item.org_id), "revoked_by": current_user.id}},
    )
    await write_audit_event(
        db,
        action="api_key_revoked",
        resource_type="api_key",
        resource_id=str(item.id),
        org_id=item.org_id,
        user_id=current_user.id,
        request_id=getattr(request.state, "request_id", None),
        details={},
    )
    await db.delete(item)
    await db.commit()


@router.post("/api-keys/{key_id}/rotate", response_model=APIKeyCreateResponse)
async def rotate_api_key(
    key_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("admin:all")),
):
    row = await db.execute(select(APIKey).where(APIKey.id == key_id, APIKey.org_id == current_user.org_id))
    item = row.scalar_one_or_none()
    if not item:
        raise api_error(E.API_KEY_NOT_FOUND)

    raw_key = f"tip_{secrets.token_urlsafe(32)}"
    item.key_hash = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
    item.last_used = None
    await db.commit()
    await db.refresh(item)
    logger.info(
        "api_key_rotated",
        extra={"extra_payload": {"event": "api_key_rotated", "api_key_id": item.id, "org_id": str(item.org_id), "rotated_by": current_user.id}},
    )
    await write_audit_event(
        db,
        action="api_key_rotated",
        resource_type="api_key",
        resource_id=str(item.id),
        org_id=item.org_id,
        user_id=current_user.id,
        request_id=getattr(request.state, "request_id", None),
        details={},
    )
    await db.commit()

    return APIKeyCreateResponse(
        id=item.id,
        org_id=str(item.org_id),
        key=raw_key,
        permissions=item.permissions or [],
    )
