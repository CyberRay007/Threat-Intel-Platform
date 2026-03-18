import hashlib
from datetime import datetime
from typing import Optional
import time

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.database.session import get_db
from app.database.models import APIKey, User
from app.core.jwt import decode_access_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
API_KEY_RATE_WINDOW_SECONDS = 60
API_KEY_RATE_MAX = 120
_api_key_rate_counters: dict[str, tuple[float, int]] = {}


async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = decode_access_token(token)
        user_id: Optional[int] = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except Exception:
        raise credentials_exception
    result = await db.execute(select(User).filter_by(id=int(user_id)))
    user = result.scalar_one_or_none()
    if user is None:
        raise credentials_exception
    token_org_id = payload.get("org_id")
    if token_org_id and str(user.org_id) != str(token_org_id):
        raise credentials_exception
    return user


ROLE_PERMISSIONS = {
    "admin": {
        "alerts:read", "alerts:write", "intel:read", "intel:write", "feed:read", "feed:write", "admin:all"
    },
    "analyst": {
        "alerts:read", "alerts:write", "intel:read", "intel:write", "feed:read"
    },
    "viewer": {
        "alerts:read", "intel:read", "feed:read"
    },
    "api_client": {
        "intel:read", "intel:export", "feed:read"
    },
}


def require_permission(permission: str):
    async def checker(current_user: User = Depends(get_current_user)) -> User:
        role = (current_user.role or "viewer").lower()
        allowed = ROLE_PERMISSIONS.get(role, set())
        if permission not in allowed and "admin:all" not in allowed:
            raise HTTPException(status_code=403, detail="insufficient permissions")
        return current_user

    return checker


async def get_api_client(
    x_api_key: str = Header(default="", alias="X-API-Key"),
    request: Request = None,
    db: AsyncSession = Depends(get_db),
) -> APIKey:
    if not x_api_key:
        logger.warning("api_key_missing", extra={"extra_payload": {"event": "api_key_missing"}})
        raise HTTPException(status_code=401, detail="missing api key")
    key_hash = hashlib.sha256(x_api_key.encode("utf-8")).hexdigest()
    row = await db.execute(select(APIKey).where(APIKey.key_hash == key_hash))
    api_key = row.scalar_one_or_none()
    if not api_key:
        logger.warning("api_key_invalid", extra={"extra_payload": {"event": "api_key_invalid"}})
        raise HTTPException(status_code=401, detail="invalid api key")

    counter_key = str(api_key.org_id)
    now = time.time()
    window_start, count = _api_key_rate_counters.get(counter_key, (now, 0))
    if now - window_start > API_KEY_RATE_WINDOW_SECONDS:
        window_start, count = now, 0
    count += 1
    _api_key_rate_counters[counter_key] = (window_start, count)
    if count > API_KEY_RATE_MAX:
        logger.warning(
            "api_key_rate_limited",
            extra={"extra_payload": {"event": "api_key_rate_limited", "org_id": str(api_key.org_id), "api_key_id": api_key.id}},
        )
        raise HTTPException(status_code=429, detail="api key rate limit exceeded")

    api_key.last_used = datetime.utcnow()
    await db.commit()
    client_ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        if request else "unknown"
    ) or (str(request.client.host) if request and request.client else "unknown")
    logger.info(
        "api_key_authenticated",
        extra={"extra_payload": {
            "event": "api_key_authenticated",
            "org_id": str(api_key.org_id),
            "api_key_id": api_key.id,
            "client_ip": client_ip,
        }},
    )
    return api_key
