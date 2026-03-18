from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.database.models import IOC, IOCTag, IOCRelationship, ThreatActor
from app.services.search_backend import opensearch_backend


def _canonical_ioc_type(ioc_type: str) -> str:
    return "file_hash" if ioc_type == "hash" else ioc_type


def _parse_org_id(org_id: str | Any) -> Any:
    try:
        return UUID(str(org_id))
    except Exception:
        return org_id


async def _load_ioc_tags(db: AsyncSession, ioc_ids: Iterable[int], org_id: str) -> dict[int, list[str]]:
    ids = list(ioc_ids)
    if not ids:
        return {}
    rows = await db.execute(
        select(IOCTag.ioc_id, IOCTag.tag)
        .where(IOCTag.ioc_id.in_(ids), IOCTag.org_id == org_id)
        .order_by(IOCTag.ioc_id.asc(), IOCTag.tag.asc())
    )
    tag_map: dict[int, list[str]] = {}
    for ioc_id, tag in rows.all():
        tag_map.setdefault(ioc_id, []).append(tag)
    return tag_map


async def _load_relationship_counts(db: AsyncSession, ioc_ids: Iterable[int], org_id: str) -> dict[int, int]:
    ids = list(ioc_ids)
    if not ids:
        return {}
    rows = await db.execute(
        select(IOCRelationship.ioc_id, func.count(IOCRelationship.id))
        .where(IOCRelationship.ioc_id.in_(ids), IOCRelationship.org_id == org_id)
        .group_by(IOCRelationship.ioc_id)
    )
    return {ioc_id: count for ioc_id, count in rows.all()}


async def _serialize_iocs(db: AsyncSession, iocs: list[IOC]) -> list[dict[str, Any]]:
    if not iocs:
        return []
    org_id_value = iocs[0].org_id
    ids = [ioc.id for ioc in iocs]
    tag_map = await _load_ioc_tags(db, ids, org_id_value)
    relationship_count_map = await _load_relationship_counts(db, ids, org_id_value)

    actor_ids = sorted({ioc.threat_actor_id for ioc in iocs if ioc.threat_actor_id})
    actor_name_map: dict[int, str] = {}
    if actor_ids:
        actor_rows = await db.execute(
            select(ThreatActor.id, ThreatActor.name)
            .where(ThreatActor.id.in_(actor_ids), ThreatActor.org_id == org_id_value)
        )
        actor_name_map = {actor_id: name for actor_id, name in actor_rows.all()}

    documents = []
    for ioc in iocs:
        canonical_type = _canonical_ioc_type(ioc.type)
        documents.append(
            {
                "id": ioc.id,
                "org_id": str(ioc.org_id),
                "type": canonical_type,
                "value": ioc.value,
                "value_text": ioc.value,
                "tags": tag_map.get(ioc.id, []),
                "source": ioc.source or "unknown",
                "threat_actor_id": ioc.threat_actor_id,
                "threat_actor_name": actor_name_map.get(ioc.threat_actor_id or -1, "") if ioc.threat_actor_id else "",
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                "confidence": float(ioc.confidence or 0.0),
                "source_reliability": float(ioc.source_reliability or 0.0),
                "relationship_count": int(relationship_count_map.get(ioc.id, 0)),
            }
        )
    return documents


async def index_ioc_by_id(db: AsyncSession, *, ioc_id: int, org_id: str, request_id: str | None = None) -> dict[str, Any]:
    row = await db.execute(select(IOC).where(IOC.id == ioc_id, IOC.org_id == _parse_org_id(org_id)))
    ioc = row.scalar_one_or_none()
    if not ioc:
        logger.info(
            "search_index_skip_missing_ioc",
            extra={"extra_payload": {"event": "search_index_skip_missing_ioc", "ioc_id": ioc_id, "org_id": org_id, "request_id": request_id}},
        )
        return {"indexed": 0, "skipped": 1}
    documents = await _serialize_iocs(db, [ioc])
    result = opensearch_backend.bulk_upsert_iocs(documents)
    logger.info(
        "search_ioc_indexed",
        extra={"extra_payload": {"event": "search_ioc_indexed", "ioc_id": ioc_id, "org_id": org_id, "request_id": request_id, **result}},
    )
    return result


async def index_iocs_by_identity(
    db: AsyncSession,
    *,
    org_id: str,
    identities: list[list[str]] | list[tuple[str, str]],
    request_id: str | None = None,
) -> dict[str, Any]:
    if not identities:
        return {"indexed": 0}
    filters = [(str(ioc_type).lower(), str(value)) for ioc_type, value in identities]
    filter_set = {(_canonical_ioc_type(t), v) for t, v in filters}
    rows = await db.execute(select(IOC).where(IOC.org_id == _parse_org_id(org_id)))
    candidates = [ioc for ioc in rows.scalars().all() if (_canonical_ioc_type(ioc.type), ioc.value) in filter_set]
    documents = await _serialize_iocs(db, candidates)
    result = opensearch_backend.bulk_upsert_iocs(documents)
    logger.info(
        "search_ioc_bulk_indexed",
        extra={"extra_payload": {"event": "search_ioc_bulk_indexed", "org_id": org_id, "request_id": request_id, "requested": len(filters), **result}},
    )
    return result


def delete_ioc_document(*, org_id: str, ioc_id: int, request_id: str | None = None) -> dict[str, Any]:
    opensearch_backend.delete_ioc_document(org_id=org_id, ioc_id=ioc_id)
    logger.info(
        "search_ioc_deleted",
        extra={"extra_payload": {"event": "search_ioc_deleted", "org_id": org_id, "ioc_id": ioc_id, "request_id": request_id}},
    )
    return {"deleted": 1}


async def search_iocs(
    *,
    org_id: str,
    q: str | None,
    ioc_type: str | None,
    source: str | None,
    min_confidence: float | None,
    first_seen_after: datetime | None,
    last_seen_before: datetime | None,
    page: int,
    limit: int,
) -> dict[str, Any]:
    filters: list[dict[str, Any]] = [{"term": {"org_id": org_id}}]
    must: list[dict[str, Any]] = []

    if ioc_type:
        filters.append({"term": {"type": _canonical_ioc_type(ioc_type.strip().lower())}})
    if source:
        filters.append({"term": {"source": source.strip().lower()}})
    if min_confidence is not None:
        filters.append({"range": {"confidence": {"gte": min_confidence}}})
    if first_seen_after:
        filters.append({"range": {"first_seen": {"gte": first_seen_after.isoformat()}}})
    if last_seen_before:
        filters.append({"range": {"last_seen": {"lte": last_seen_before.isoformat()}}})
    if q:
        must.append(
            {
                "simple_query_string": {
                    "query": q,
                    "fields": ["value_text^4", "value^5", "tags^2", "source^1.5", "threat_actor_name^2"],
                    "default_operator": "and",
                }
            }
        )

    payload = {
        "from": (page - 1) * limit,
        "size": limit,
        "track_total_hits": True,
        "query": {
            "bool": {
                "filter": filters,
                "must": must or [{"match_all": {}}],
            }
        },
        "sort": [{"last_seen": {"order": "desc"}}, {"id": {"order": "desc"}}],
        "aggs": {
            "by_type": {"terms": {"field": "type", "size": 10}},
            "by_source": {"terms": {"field": "source", "size": 20}},
        },
    }
    result = opensearch_backend.search_iocs(payload)
    hits = result.get("hits", {})
    aggregations = result.get("aggregations", {})
    return {
        "items": [hit.get("_source", {}) for hit in hits.get("hits", [])],
        "page": page,
        "limit": limit,
        "total": int((hits.get("total") or {}).get("value", 0)),
        "aggregations": {
            "by_type": [{"key": bucket.get("key"), "count": bucket.get("doc_count", 0)} for bucket in aggregations.get("by_type", {}).get("buckets", [])],
            "by_source": [{"key": bucket.get("key"), "count": bucket.get("doc_count", 0)} for bucket in aggregations.get("by_source", {}).get("buckets", [])],
        },
    }