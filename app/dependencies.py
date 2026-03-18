import hashlib
from datetime import datetime
from typing import Optional
import time
import os

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.database.session import get_db
from app.database.models import APIKey, User
from app.core.jwt import decode_access_token
from app.core.audit import write_security_event

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
API_KEY_RATE_WINDOW_SECONDS = 60
API_KEY_RATE_MAX = 120
_api_key_rate_counters: dict[str, tuple[float, int]] = {}
API_KEY_SPIKE_THRESHOLD = int(os.getenv("API_KEY_SPIKE_THRESHOLD", "80"))
_api_key_usage_window: dict[int, tuple[float, int]] = {}
_api_key_seen_ips: dict[int, set[str]] = {}
_api_key_seen_paths: dict[int, set[str]] = {}


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
    request_id = getattr(getattr(request, "state", None), "request_id", None)

    path = request.url.path if request else "unknown"
    now2 = time.time()

    win_start, win_count = _api_key_usage_window.get(api_key.id, (now2, 0))
    if now2 - win_start > API_KEY_RATE_WINDOW_SECONDS:
        win_start, win_count = now2, 0
    win_count += 1
    _api_key_usage_window[api_key.id] = (win_start, win_count)

    if win_count > API_KEY_SPIKE_THRESHOLD:
        await write_security_event(
            db,
            event_type="api_key_anomaly",
            signal="rate_spike",
            org_id=api_key.org_id,
            api_key_id=api_key.id,
            request_id=request_id,
            metadata={
                "requests_in_window": win_count,
                "window_seconds": API_KEY_RATE_WINDOW_SECONDS,
                "threshold": API_KEY_SPIKE_THRESHOLD,
                "path": path,
                "client_ip": client_ip,
            },
        )
        logger.warning(
            "api_key_usage_spike",
            extra={"extra_payload": {
                "event": "api_key_usage_spike",
                "api_key_id": api_key.id,
                "org_id": str(api_key.org_id),
                "requests_in_window": win_count,
                "window_seconds": API_KEY_RATE_WINDOW_SECONDS,
                "threshold": API_KEY_SPIKE_THRESHOLD,
                "path": path,
            }},
        )

    seen_ips = _api_key_seen_ips.setdefault(api_key.id, set())
    if client_ip not in seen_ips:
        if seen_ips:
            await write_security_event(
                db,
                event_type="api_key_anomaly",
                signal="new_ip",
                org_id=api_key.org_id,
                api_key_id=api_key.id,
                request_id=request_id,
                metadata={
                    "new_ip": client_ip,
                    "known_ips_count": len(seen_ips),
                    "path": path,
                },
            )
            logger.warning(
                "api_key_new_ip",
                extra={"extra_payload": {
                    "event": "api_key_new_ip",
                    "api_key_id": api_key.id,
                    "org_id": str(api_key.org_id),
                    "new_ip": client_ip,
                    "known_ips_count": len(seen_ips),
                }},
            )
        seen_ips.add(client_ip)

    seen_paths = _api_key_seen_paths.setdefault(api_key.id, set())
    if path not in seen_paths:
        if seen_paths:
            await write_security_event(
                db,
                event_type="api_key_anomaly",
                signal="new_path",
                org_id=api_key.org_id,
                api_key_id=api_key.id,
                request_id=request_id,
                metadata={
                    "path": path,
                    "client_ip": client_ip,
                },
            )
            logger.info(
                "api_key_new_path",
                extra={"extra_payload": {
                    "event": "api_key_new_path",
                    "api_key_id": api_key.id,
                    "org_id": str(api_key.org_id),
                    "path": path,
                }},
            )
        seen_paths.add(path)

    logger.info(
        "api_key_authenticated",
        extra={"extra_payload": {
            "event": "api_key_authenticated",
            "org_id": str(api_key.org_id),
            "api_key_id": api_key.id,
            "client_ip": client_ip,
            "path": path,
            "request_id": request_id,
        }},
    )
    await db.commit()
    return api_key
