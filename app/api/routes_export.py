from __future__ import annotations

import csv
import hashlib
import io
import json
from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.entitlements import require_entitlement
from app.database.models import IOC, ThreatActor, User
from app.database.session import get_db
from app.dependencies import require_permission
from app.services.integrations.elastic import ElasticAdapter
from app.services.integrations.splunk import SplunkAdapter
from app.services.search_service import search_iocs


router = APIRouter(tags=["export"])


def _stix_indicator_id(org_id: str, ioc_id: int) -> str:
    # Deterministic STIX id for stable downstream dedupe.
    digest = hashlib.sha256(f"{org_id}:{ioc_id}".encode("utf-8")).hexdigest()[:32]
    return f"indicator--{digest}"


def _ioc_to_stix_indicator(ioc: IOC) -> dict:
    pattern_map = {
        "domain": "[domain-name:value",
        "ip": "[ipv4-addr:value",
        "url": "[url:value",
        "file_hash": "[file:hashes.MD5",
    }
    prefix = pattern_map.get(ioc.type, "[x-tip-ioc:value")
    pattern = f"{prefix} = '{ioc.value}']"

    ts_created = (ioc.first_seen or datetime.utcnow()).isoformat()
    ts_modified = (ioc.last_seen or datetime.utcnow()).isoformat()

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": _stix_indicator_id(str(ioc.org_id), ioc.id),
        "created": ts_created,
        "modified": ts_modified,
        "name": f"{ioc.type}:{ioc.value}",
        "description": f"source={ioc.source or 'unknown'} confidence={ioc.confidence}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts_created,
        "labels": ["malicious-activity"],
    }


@router.get("/export/stix2.1/indicators")
async def export_stix21_indicators(
    q: Optional[str] = Query(default=None),
    ioc_type: Optional[str] = Query(default=None, alias="type"),
    min_confidence: Optional[float] = Query(default=None, ge=0.0, le=1.0),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=500, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
    _: User = Depends(require_entitlement("stix_export")),
):
    search_result = await search_iocs(
        org_id=str(current_user.org_id),
        q=q,
        ioc_type=ioc_type,
        source=None,
        min_confidence=min_confidence,
        first_seen_after=None,
        last_seen_before=None,
        page=page,
        limit=limit,
    )

    ids = [row["id"] for row in search_result.get("items", [])]
    if not ids:
        return {"type": "bundle", "id": f"bundle--{uuid4().hex}", "objects": []}

    db_rows = await db.execute(select(IOC).where(IOC.org_id == current_user.org_id, IOC.id.in_(ids)))
    iocs = db_rows.scalars().all()

    bundle = {
        "type": "bundle",
        "id": f"bundle--{uuid4().hex}",
        "objects": [_ioc_to_stix_indicator(ioc) for ioc in iocs],
    }
    return bundle


@router.get("/export/json")
async def export_json(
    q: Optional[str] = Query(default=None),
    ioc_type: Optional[str] = Query(default=None, alias="type"),
    min_confidence: Optional[float] = Query(default=None, ge=0.0, le=1.0),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=1000, ge=1, le=2000),
    current_user: User = Depends(require_permission("intel:read")),
    _: User = Depends(require_entitlement("ioc_export_json")),
):
    result = await search_iocs(
        org_id=str(current_user.org_id),
        q=q,
        ioc_type=ioc_type,
        source=None,
        min_confidence=min_confidence,
        first_seen_after=None,
        last_seen_before=None,
        page=page,
        limit=limit,
    )
    return {
        "meta": {
            "org_id": str(current_user.org_id),
            "exported_at": datetime.utcnow().isoformat(),
            "total": result.get("total", 0),
            "page": page,
            "limit": limit,
        },
        "data": result.get("items", []),
        "aggregations": result.get("aggregations", {}),
    }


@router.get("/export/csv")
async def export_csv(
    q: Optional[str] = Query(default=None),
    ioc_type: Optional[str] = Query(default=None, alias="type"),
    min_confidence: Optional[float] = Query(default=None, ge=0.0, le=1.0),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=5000, ge=1, le=10000),
    current_user: User = Depends(require_permission("intel:read")),
    _: User = Depends(require_entitlement("ioc_export_csv")),
):
    result = await search_iocs(
        org_id=str(current_user.org_id),
        q=q,
        ioc_type=ioc_type,
        source=None,
        min_confidence=min_confidence,
        first_seen_after=None,
        last_seen_before=None,
        page=page,
        limit=limit,
    )

    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id",
            "type",
            "value",
            "source",
            "confidence",
            "source_reliability",
            "threat_actor_name",
            "first_seen",
            "last_seen",
            "tags",
            "relationship_count",
        ],
    )
    writer.writeheader()
    for row in result.get("items", []):
        writer.writerow(
            {
                "id": row.get("id"),
                "type": row.get("type"),
                "value": row.get("value"),
                "source": row.get("source"),
                "confidence": row.get("confidence"),
                "source_reliability": row.get("source_reliability"),
                "threat_actor_name": row.get("threat_actor_name") or "",
                "first_seen": row.get("first_seen"),
                "last_seen": row.get("last_seen"),
                "tags": ";".join(row.get("tags", [])),
                "relationship_count": row.get("relationship_count", 0),
            }
        )

    filename = f"iocs-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/export/taxii2.1/discovery")
async def taxii_discovery(
    current_user: User = Depends(require_permission("intel:read")),
    _: User = Depends(require_entitlement("stix_export")),
):
    return {
        "title": "Threat Intel Platform TAXII",
        "description": "Tenant-scoped TAXII discovery",
        "api_roots": [f"/api/v1/export/taxii2.1/api_roots/{current_user.org_id}"],
    }


@router.get("/export/taxii2.1/collections")
async def taxii_collections(
    current_user: User = Depends(require_permission("intel:read")),
    _: User = Depends(require_entitlement("stix_export")),
):
    return {
        "collections": [
            {
                "id": "iocs",
                "title": "Organization IOCs",
                "description": "Tenant-isolated IOC collection",
                "can_read": True,
                "can_write": current_user.role == "admin",
            }
        ]
    }


@router.post("/export/partners/siem/{provider}")
async def push_to_siem(
    provider: str,
    q: Optional[str] = Query(default=None),
    ioc_type: Optional[str] = Query(default=None, alias="type"),
    min_confidence: Optional[float] = Query(default=0.7, ge=0.0, le=1.0),
    limit: int = Query(default=500, ge=1, le=5000),
    current_user: User = Depends(require_permission("intel:read")),
    _: User = Depends(require_entitlement("siem_push")),
):
    result = await search_iocs(
        org_id=str(current_user.org_id),
        q=q,
        ioc_type=ioc_type,
        source=None,
        min_confidence=min_confidence,
        first_seen_after=None,
        last_seen_before=None,
        page=1,
        limit=limit,
    )
    payload = result.get("items", [])

    provider_name = provider.strip().lower()
    if provider_name == "splunk":
        adapter = SplunkAdapter()
    elif provider_name == "elastic":
        adapter = ElasticAdapter()
    else:
        return {"success": False, "error": f"Unsupported provider '{provider_name}'"}

    health = adapter.health_check()
    if not health:
        return {"success": False, "error": f"{provider_name} integration health check failed"}

    push_result = adapter.push_iocs(payload)
    return {
        "provider": provider_name,
        "success": push_result.success,
        "pushed": push_result.pushed,
        "failed": push_result.failed,
        "error": push_result.error,
        "total_selected": len(payload),
    }
