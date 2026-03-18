from __future__ import annotations

from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import AuditEvent, SecurityEvent


async def write_audit_event(
    db: AsyncSession,
    *,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    org_id: Any = None,
    user_id: Optional[int] = None,
    request_id: Optional[str] = None,
    details: Optional[dict] = None,
) -> None:
    db.add(
        AuditEvent(
            org_id=org_id,
            user_id=user_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            details=details or {},
        )
    )


async def write_security_event(
    db: AsyncSession,
    *,
    event_type: str,
    signal: str,
    org_id: Any = None,
    api_key_id: Optional[int] = None,
    request_id: Optional[str] = None,
    metadata: Optional[dict] = None,
) -> None:
    db.add(
        SecurityEvent(
            org_id=org_id,
            api_key_id=api_key_id,
            event_type=event_type,
            signal=signal,
            request_id=request_id,
            event_metadata=metadata or {},
        )
    )
