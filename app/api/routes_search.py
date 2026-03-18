from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query

from app.core.entitlements import require_entitlement
from app.dependencies import require_permission
from app.database.models import User
from app.services.search_backend import opensearch_backend
from app.services.search_service import search_iocs
from app.utils.errors import E, api_error


router = APIRouter()


@router.get("/search/iocs")
async def search_iocs_endpoint(
    q: str | None = Query(default=None, min_length=1),
    ioc_type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    min_confidence: float | None = Query(default=None, ge=0.0, le=1.0),
    first_seen_after: datetime | None = Query(default=None),
    last_seen_before: datetime | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    current_user: User = Depends(require_permission("intel:read")),
    _: User = Depends(require_entitlement("search_intelligence")),
):
    if not opensearch_backend.health_check():
        raise api_error(E.SERVICE_UNAVAILABLE, detail_override="OpenSearch is not reachable")
    return await search_iocs(
        org_id=str(current_user.org_id),
        q=q,
        ioc_type=ioc_type,
        source=source,
        min_confidence=min_confidence,
        first_seen_after=first_seen_after,
        last_seen_before=last_seen_before,
        page=page,
        limit=limit,
    )