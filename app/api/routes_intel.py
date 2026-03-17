from datetime import datetime
from typing import Optional
import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import OTX_API_KEY
from app.database.models import IOC, IOCGraphRelationship, IOCRelationship, MalwareFamily, User
from app.database.session import get_db
from app.dependencies import get_current_user, require_permission
from app.schemas.intel_schema import (
    IOCCreate,
    IOCResponse,
    IOCUpdate,
    ThreatActorCreate,
    ThreatActorResponse,
    ThreatActorUpdate,
)
from app.services.intel_enrichment import attribute_observable, enrich_ioc
from app.services.feed_ingestion import FEEDS, ingest_all_sources, ingest_source
from app.database.models import Alert, Campaign, ThreatActor


router = APIRouter()


@router.post("/intel/ingest")
async def run_ingestion(
    source: Optional[str] = Query(default=None),
    limit: Optional[int] = Query(default=None, ge=1),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("feed:write")),
):
    if source:
        if source not in FEEDS:
            return {"error": f"unknown source '{source}'", "supported_sources": sorted(FEEDS.keys())}
        result = await ingest_source(
            db,
            source=source,
            limit=limit,
            otx_api_key=OTX_API_KEY or None,
            org_id=current_user.org_id,
        )
        return {"source": result.__dict__}

    return await ingest_all_sources(
        db,
        limit_per_source=limit,
        otx_api_key=OTX_API_KEY or None,
        org_id=current_user.org_id,
    )


@router.get("/intel/ioc/enrich")
async def enrich_ioc_endpoint(
    ioc_type: str = Query(..., description="domain|url|ip|file_hash"),
    value: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    return await enrich_ioc(db, ioc_type=ioc_type, value=value, org_id=current_user.org_id)


@router.get("/intel/attribution")
async def attribution_endpoint(
    ioc_type: str = Query(..., description="domain|url|ip|file_hash"),
    value: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    return await attribute_observable(db, ioc_type=ioc_type, value=value, org_id=current_user.org_id)


@router.get("/intel/ioc/stats")
async def ioc_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    total = await db.execute(select(func.count()).select_from(IOC).where(IOC.org_id == current_user.org_id))
    by_type = await db.execute(
        select(IOC.type, func.count()).where(IOC.org_id == current_user.org_id).group_by(IOC.type).order_by(IOC.type)
    )
    by_source = await db.execute(
        select(IOC.source, func.count()).where(IOC.org_id == current_user.org_id).group_by(IOC.source).order_by(IOC.source)
    )

    by_type_rows = by_type.all()
    by_source_rows = by_source.all()
    by_type_map = {}
    for t, c in by_type_rows:
        canonical_type = "file_hash" if t == "hash" else t
        by_type_map[canonical_type] = by_type_map.get(canonical_type, 0) + c

    canonical_by_type = [{"type": t, "count": c} for t, c in sorted(by_type_map.items())]

    return {
        "total_iocs": total.scalar_one(),
        "domains": by_type_map.get("domain", 0),
        "urls": by_type_map.get("url", 0),
        "file_hashes": by_type_map.get("file_hash", 0),
        "ips": by_type_map.get("ip", 0),
        "by_type": canonical_by_type,
        "by_source": [{"source": s, "count": c} for s, c in by_source_rows],
    }


@router.get("/intel/graph/domains/shared-malware-family")
async def domains_shared_malware_family(
    domain: str = Query(..., min_length=3),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    """Return domains linked to the same malware family as the input domain."""
    domain_norm = domain.strip().lower().strip(".")

    source_ioc_row = await db.execute(
        select(IOC).where(IOC.type == "domain", IOC.value == domain_norm, IOC.org_id == current_user.org_id)
    )
    source_ioc = source_ioc_row.scalar_one_or_none()
    if not source_ioc:
        return {"domain": domain_norm, "families": [], "related_domains": []}

    family_rows = await db.execute(
        select(IOCRelationship.malware_family_id)
        .where(
            IOCRelationship.ioc_id == source_ioc.id,
            IOCRelationship.malware_family_id.isnot(None),
            IOCRelationship.org_id == current_user.org_id,
        )
        .distinct()
    )
    family_ids = [fid for (fid,) in family_rows.all() if fid is not None]
    if not family_ids:
        return {"domain": domain_norm, "families": [], "related_domains": []}

    family_name_rows = await db.execute(
        select(MalwareFamily.id, MalwareFamily.name).where(MalwareFamily.id.in_(family_ids), MalwareFamily.org_id == current_user.org_id)
    )
    family_name_map = {fid: name for fid, name in family_name_rows.all()}

    related_rows = await db.execute(
        select(IOC.value, IOCRelationship.malware_family_id)
        .join(IOCRelationship, IOCRelationship.ioc_id == IOC.id)
        .where(
            IOC.type == "domain",
            IOCRelationship.malware_family_id.in_(family_ids),
            IOC.org_id == current_user.org_id,
            IOCRelationship.org_id == current_user.org_id,
        )
        .distinct()
    )

    related_domains = sorted({value for value, _ in related_rows.all() if value != domain_norm})
    families = sorted({family_name_map.get(fid, f"family_{fid}") for fid in family_ids})

    return {
        "domain": domain_norm,
        "families": families,
        "related_domains": related_domains,
    }


@router.get("/intel/iocs")
async def list_iocs(
    query: Optional[str] = Query(default=None),
    ioc_type: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    offset = (page - 1) * limit
    base = select(IOC).where(IOC.org_id == current_user.org_id)
    count_q = select(func.count()).select_from(IOC).where(IOC.org_id == current_user.org_id)

    if query:
        q = f"%{query.strip().lower()}%"
        base = base.where(func.lower(IOC.value).like(q))
        count_q = count_q.where(func.lower(IOC.value).like(q))

    if ioc_type:
        ioc_type_norm = ioc_type.strip().lower()
        if ioc_type_norm == "file_hash":
            base = base.where(IOC.type.in_(["file_hash", "hash"]))
            count_q = count_q.where(IOC.type.in_(["file_hash", "hash"]))
        else:
            base = base.where(IOC.type == ioc_type_norm)
            count_q = count_q.where(IOC.type == ioc_type_norm)

    rows = await db.execute(base.order_by(IOC.id.desc()).limit(limit).offset(offset))
    total = await db.execute(count_q)
    items = rows.scalars().all()

    ioc_ids = [ioc.id for ioc in items]
    rels = []
    if ioc_ids:
        rel_rows = await db.execute(
            select(IOCRelationship).where(IOCRelationship.ioc_id.in_(ioc_ids), IOCRelationship.org_id == current_user.org_id)
        )
        rels = rel_rows.scalars().all()

    family_ids = sorted({r.malware_family_id for r in rels if r.malware_family_id})
    campaign_ids = sorted({r.campaign_id for r in rels if r.campaign_id})
    family_map = {}
    campaign_map = {}
    if family_ids:
        fam_rows = await db.execute(select(MalwareFamily).where(MalwareFamily.id.in_(family_ids), MalwareFamily.org_id == current_user.org_id))
        family_map = {f.id: f.name for f in fam_rows.scalars().all()}
    if campaign_ids:
        camp_rows = await db.execute(select(Campaign).where(Campaign.id.in_(campaign_ids), Campaign.org_id == current_user.org_id))
        campaign_map = {c.id: c.name for c in camp_rows.scalars().all()}

    rel_by_ioc: dict[int, list[IOCRelationship]] = {}
    for rel in rels:
        rel_by_ioc.setdefault(rel.ioc_id, []).append(rel)

    result = []
    for ioc in items:
        ioc_rels = rel_by_ioc.get(ioc.id, [])
        max_conf = max([r.confidence or 0 for r in ioc_rels], default=70)
        families = sorted({family_map.get(r.malware_family_id) for r in ioc_rels if r.malware_family_id in family_map})
        campaigns = sorted({campaign_map.get(r.campaign_id) for r in ioc_rels if r.campaign_id in campaign_map})
        result.append(
            {
                "id": ioc.id,
                "value": ioc.value,
                "type": "file_hash" if ioc.type == "hash" else ioc.type,
                "confidence": max_conf,
                "threat_type": ioc.source or "unknown",
                "malware_family": families[0] if families else None,
                "first_seen": ioc.first_seen,
                "last_seen": ioc.last_seen,
                "campaigns": campaigns,
                "feeds": sorted({r.source for r in ioc_rels if r.source} | ({ioc.source} if ioc.source else set())),
                "relationships": [
                    {
                        "relationship_type": r.relationship_type,
                        "entity_type": r.related_entity_type,
                        "entity_id": r.related_entity_id,
                        "confidence": r.confidence,
                    }
                    for r in ioc_rels
                ],
            }
        )

    return {
        "page": page,
        "limit": limit,
        "total": total.scalar_one(),
        "items": result,
    }


@router.get("/intel/actors")
async def list_threat_actors(
    query: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    offset = (page - 1) * limit
    base = select(ThreatActor).where(ThreatActor.org_id == current_user.org_id)
    count_q = select(func.count()).select_from(ThreatActor).where(ThreatActor.org_id == current_user.org_id)

    if query:
        q = f"%{query.strip().lower()}%"
        base = base.where(func.lower(ThreatActor.name).like(q))
        count_q = count_q.where(func.lower(ThreatActor.name).like(q))

    rows = await db.execute(base.order_by(ThreatActor.name.asc()).limit(limit).offset(offset))
    total = await db.execute(count_q)
    actors = rows.scalars().all()

    result = []
    for actor in actors:
        ioc_count = await db.execute(
            select(func.count()).select_from(IOC).where(IOC.threat_actor_id == actor.id, IOC.org_id == current_user.org_id)
        )
        campaign_count = await db.execute(
            select(func.count()).select_from(Campaign).where(Campaign.threat_actor_id == actor.id, Campaign.org_id == current_user.org_id)
        )
        result.append(
            {
                "id": actor.id,
                "name": actor.name,
                "country": actor.origin,
                "motivation": actor.description,
                "ioc_count": ioc_count.scalar_one(),
                "campaign_count": campaign_count.scalar_one(),
                "aliases": actor.aliases or [],
                "first_seen": actor.first_seen,
                "last_seen": actor.last_seen,
            }
        )

    return {
        "page": page,
        "limit": limit,
        "total": total.scalar_one(),
        "items": result,
    }


@router.get("/intel/actors/{actor_id}/iocs")
async def list_actor_iocs(
    actor_id: int,
    ioc_type: Optional[str] = Query(default=None),
    source: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    actor_row = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id, ThreatActor.org_id == current_user.org_id))
    actor = actor_row.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="actor not found")

    offset = (page - 1) * limit
    base = select(IOC).where(IOC.threat_actor_id == actor_id, IOC.org_id == current_user.org_id)
    count_q = select(func.count()).select_from(IOC).where(IOC.threat_actor_id == actor_id, IOC.org_id == current_user.org_id)

    if ioc_type:
        ioc_type_norm = ioc_type.strip().lower()
        if ioc_type_norm == "file_hash":
            base = base.where(IOC.type.in_(["file_hash", "hash"]))
            count_q = count_q.where(IOC.type.in_(["file_hash", "hash"]))
        else:
            base = base.where(IOC.type == ioc_type_norm)
            count_q = count_q.where(IOC.type == ioc_type_norm)

    if source:
        source_norm = source.strip().lower()
        base = base.where(func.lower(IOC.source) == source_norm)
        count_q = count_q.where(func.lower(IOC.source) == source_norm)

    rows = await db.execute(base.order_by(IOC.id.desc()).limit(limit).offset(offset))
    total = await db.execute(count_q)
    items = rows.scalars().all()

    return {
        "actor": {
            "id": actor.id,
            "name": actor.name,
        },
        "page": page,
        "limit": limit,
        "total": total.scalar_one(),
        "items": [
            {
                "id": ioc.id,
                "type": "file_hash" if ioc.type == "hash" else ioc.type,
                "value": ioc.value,
                "source": ioc.source,
            }
            for ioc in items
        ],
    }


@router.get("/intel/actors/{actor_id}")
async def get_threat_actor(
    actor_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    actor_row = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id, ThreatActor.org_id == current_user.org_id))
    actor = actor_row.scalar_one_or_none()
    if not actor:
        return {"error": "actor not found"}

    ioc_rows = await db.execute(select(IOC).where(IOC.threat_actor_id == actor.id, IOC.org_id == current_user.org_id).limit(200))
    iocs = ioc_rows.scalars().all()

    campaign_rows = await db.execute(
        select(Campaign).where(Campaign.threat_actor_id == actor.id, Campaign.org_id == current_user.org_id).order_by(Campaign.name.asc())
    )
    campaigns = campaign_rows.scalars().all()

    ioc_values = [ioc.value for ioc in iocs]
    recent_alerts = []
    if ioc_values:
        alert_rows = await db.execute(
            select(Alert)
            .where(Alert.observable_value.in_(ioc_values), Alert.org_id == current_user.org_id)
            .order_by(Alert.last_seen_at.desc())
            .limit(50)
        )
        recent_alerts = [
            {
                "id": a.id,
                "severity": a.severity,
                "status": a.status,
                "observable_type": a.observable_type,
                "observable_value": a.observable_value,
                "occurrence_count": a.occurrence_count,
                "first_seen_at": a.first_seen_at,
                "last_seen_at": a.last_seen_at,
            }
            for a in alert_rows.scalars().all()
        ]

    return {
        "actor": {
            "id": actor.id,
            "name": actor.name,
            "country": actor.origin,
            "motivation": actor.description,
            "aliases": actor.aliases or [],
            "first_seen": actor.first_seen,
            "last_seen": actor.last_seen,
        },
        "iocs": [
            {
                "id": ioc.id,
                "type": "file_hash" if ioc.type == "hash" else ioc.type,
                "value": ioc.value,
                "source": ioc.source,
            }
            for ioc in iocs
        ],
        "campaigns": [
            {
                "id": campaign.id,
                "name": campaign.name,
                "description": campaign.description,
                "first_seen": campaign.first_seen,
                "last_seen": campaign.last_seen,
            }
            for campaign in campaigns
        ],
        "recent_alerts": recent_alerts,
    }


@router.get("/intel/dashboard")
async def intel_dashboard(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    total_iocs = await db.execute(select(func.count()).select_from(IOC).where(IOC.org_id == current_user.org_id))
    by_source = await db.execute(
        select(IOC.source, func.count()).where(IOC.org_id == current_user.org_id).group_by(IOC.source).order_by(func.count().desc())
    )
    by_type = await db.execute(select(IOC.type, func.count()).where(IOC.org_id == current_user.org_id).group_by(IOC.type).order_by(IOC.type))

    actor_rows = await db.execute(
        select(ThreatActor.id, ThreatActor.name, func.count(IOC.id))
        .outerjoin(IOC, IOC.threat_actor_id == ThreatActor.id)
        .where(ThreatActor.org_id == current_user.org_id)
        .group_by(ThreatActor.id, ThreatActor.name)
        .order_by(func.count(IOC.id).desc())
        .limit(10)
    )

    return {
        "total_iocs": total_iocs.scalar_one(),
        "by_source": [{"source": s or "unknown", "count": c} for s, c in by_source.all()],
        "by_type": [{"type": "file_hash" if t == "hash" else t, "count": c} for t, c in by_type.all()],
        "top_actors": [
            {"id": actor_id, "name": actor_name, "ioc_count": ioc_count}
            for actor_id, actor_name, ioc_count in actor_rows.all()
        ],
    }


# ---------------------------------------------------------------------------
# IOC CRUD
# ---------------------------------------------------------------------------

@router.post("/intel/ioc", response_model=IOCResponse, status_code=201, summary="Create a new IOC")
async def create_ioc(
    payload: IOCCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:write")),
):
    ioc_type = payload.type.strip().lower()
    if ioc_type == "file_hash":
        ioc_type = "hash"
    existing = await db.execute(select(IOC).where(IOC.type == ioc_type, IOC.value == payload.value.strip(), IOC.org_id == current_user.org_id))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="IOC with this type and value already exists")
    if payload.threat_actor_id:
        ta = await db.execute(select(ThreatActor).where(ThreatActor.id == payload.threat_actor_id, ThreatActor.org_id == current_user.org_id))
        if not ta.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="ThreatActor not found")
    ioc = IOC(
        org_id=current_user.org_id,
        type=ioc_type,
        value=payload.value.strip(),
        threat_actor_id=payload.threat_actor_id,
        source=payload.source,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow(),
        confidence=0.7,
        source_reliability=0.7,
    )
    db.add(ioc)
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.get("/intel/ioc/{ioc_id}", response_model=IOCResponse, summary="Get single IOC by ID")
async def get_ioc(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    row = await db.execute(select(IOC).where(IOC.id == ioc_id, IOC.org_id == current_user.org_id))
    ioc = row.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    return ioc


@router.get("/intel/ioc/{ioc_id}/relationships", summary="Get IOC graph relationships")
async def get_ioc_relationships(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    source_row = await db.execute(select(IOC).where(IOC.id == ioc_id, IOC.org_id == current_user.org_id))
    source_ioc = source_row.scalar_one_or_none()
    if not source_ioc:
        raise HTTPException(status_code=404, detail="IOC not found")

    outgoing = await db.execute(
        select(IOCGraphRelationship, IOC)
        .join(IOC, IOC.id == IOCGraphRelationship.target_ioc_id)
        .where(
            IOCGraphRelationship.source_ioc_id == ioc_id,
            IOCGraphRelationship.org_id == current_user.org_id,
            IOC.org_id == current_user.org_id,
        )
        .order_by(IOCGraphRelationship.id.desc())
        .limit(500)
    )

    incoming = await db.execute(
        select(IOCGraphRelationship, IOC)
        .join(IOC, IOC.id == IOCGraphRelationship.source_ioc_id)
        .where(
            IOCGraphRelationship.target_ioc_id == ioc_id,
            IOCGraphRelationship.org_id == current_user.org_id,
            IOC.org_id == current_user.org_id,
        )
        .order_by(IOCGraphRelationship.id.desc())
        .limit(500)
    )

    rels = []
    for rel, target_ioc in outgoing.all():
        rels.append(
            {
                "direction": "outgoing",
                "type": rel.relationship_type,
                "target": {
                    "id": target_ioc.id,
                    "type": "file_hash" if target_ioc.type == "hash" else target_ioc.type,
                    "value": target_ioc.value,
                },
                "confidence": rel.confidence,
            }
        )

    for rel, source_link_ioc in incoming.all():
        rels.append(
            {
                "direction": "incoming",
                "type": rel.relationship_type,
                "target": {
                    "id": source_link_ioc.id,
                    "type": "file_hash" if source_link_ioc.type == "hash" else source_link_ioc.type,
                    "value": source_link_ioc.value,
                },
                "confidence": rel.confidence,
            }
        )

    return {
        "ioc": {
            "id": source_ioc.id,
            "type": "file_hash" if source_ioc.type == "hash" else source_ioc.type,
            "value": source_ioc.value,
        },
        "total_relationships": len(rels),
        "relationships": rels,
    }


@router.put("/intel/ioc/{ioc_id}", response_model=IOCResponse, summary="Update IOC source or actor")
async def update_ioc(
    ioc_id: int,
    payload: IOCUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:write")),
):
    row = await db.execute(select(IOC).where(IOC.id == ioc_id, IOC.org_id == current_user.org_id))
    ioc = row.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    if payload.threat_actor_id is not None:
        ta = await db.execute(select(ThreatActor).where(ThreatActor.id == payload.threat_actor_id, ThreatActor.org_id == current_user.org_id))
        if not ta.scalar_one_or_none():
            raise HTTPException(status_code=404, detail="ThreatActor not found")
        ioc.threat_actor_id = payload.threat_actor_id
    if payload.source is not None:
        ioc.source = payload.source
    await db.commit()
    await db.refresh(ioc)
    return ioc


@router.delete("/intel/ioc/{ioc_id}", status_code=204, summary="Delete an IOC")
async def delete_ioc(
    ioc_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:write")),
):
    row = await db.execute(select(IOC).where(IOC.id == ioc_id, IOC.org_id == current_user.org_id))
    ioc = row.scalar_one_or_none()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    await db.delete(ioc)
    await db.commit()


# ---------------------------------------------------------------------------
# ThreatActor CRUD
# ---------------------------------------------------------------------------

@router.post("/intel/actors", response_model=ThreatActorResponse, status_code=201, summary="Create a threat actor")
async def create_threat_actor(
    payload: ThreatActorCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:write")),
):
    existing = await db.execute(select(ThreatActor).where(ThreatActor.name == payload.name.strip(), ThreatActor.org_id == current_user.org_id))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Threat actor with this name already exists")
    actor = ThreatActor(
        org_id=current_user.org_id,
        name=payload.name.strip(),
        description=payload.description,
        origin=payload.origin,
        aliases=payload.aliases or [],
        first_seen=payload.first_seen,
        last_seen=payload.last_seen,
    )
    db.add(actor)
    await db.commit()
    await db.refresh(actor)
    return actor


@router.put("/intel/actors/{actor_id}", response_model=ThreatActorResponse, summary="Update a threat actor")
async def update_threat_actor(
    actor_id: int,
    payload: ThreatActorUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:write")),
):
    row = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id, ThreatActor.org_id == current_user.org_id))
    actor = row.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    if payload.description is not None:
        actor.description = payload.description
    if payload.origin is not None:
        actor.origin = payload.origin
    if payload.aliases is not None:
        actor.aliases = payload.aliases
    if payload.first_seen is not None:
        actor.first_seen = payload.first_seen
    if payload.last_seen is not None:
        actor.last_seen = payload.last_seen
    await db.commit()
    await db.refresh(actor)
    return actor


@router.delete("/intel/actors/{actor_id}", status_code=204, summary="Delete a threat actor")
async def delete_threat_actor(
    actor_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:write")),
):
    row = await db.execute(select(ThreatActor).where(ThreatActor.id == actor_id, ThreatActor.org_id == current_user.org_id))
    actor = row.scalar_one_or_none()
    if not actor:
        raise HTTPException(status_code=404, detail="Threat actor not found")
    await db.delete(actor)
    await db.commit()


@router.post("/intel/check")
async def intel_check(
    ioc_type: str,
    value: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    enrichment = await enrich_ioc(db, ioc_type=ioc_type, value=value, org_id=current_user.org_id)
    attribution = await attribute_observable(db, ioc_type=ioc_type, value=value, org_id=current_user.org_id)
    confidence = 0.0
    if enrichment.get("exists"):
        confidence = max(
            float(enrichment.get("confidence") or 0),
            max([float(a.get("confidence", 0)) for a in attribution.get("actors", [])], default=0.0),
        )
    risk_score = min(100, int(confidence))
    return {
        "ioc_type": ioc_type,
        "value": value,
        "risk_score": risk_score,
        "confidence_score": confidence,
        "malware_family": enrichment.get("malware_families", [{}])[0].get("name") if enrichment.get("malware_families") else None,
        "threat_type": enrichment.get("threat_type") or enrichment.get("source"),
        "tags": [],
        "campaign": enrichment.get("campaigns", [{}])[0].get("name") if enrichment.get("campaigns") else None,
        "actor": attribution.get("actors", [{}])[0].get("name") if attribution.get("actors") else None,
    }


@router.get("/intel/campaigns/{campaign_id}")
async def get_campaign(
    campaign_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    row = await db.execute(select(Campaign).where(Campaign.id == campaign_id, Campaign.org_id == current_user.org_id))
    campaign = row.scalar_one_or_none()
    if not campaign:
        raise HTTPException(status_code=404, detail="campaign not found")
    ioc_rows = await db.execute(
        select(IOC)
        .join(IOCRelationship, IOCRelationship.ioc_id == IOC.id)
        .where(IOCRelationship.campaign_id == campaign.id, IOC.org_id == current_user.org_id, IOCRelationship.org_id == current_user.org_id)
        .limit(500)
    )
    return {
        "id": campaign.id,
        "name": campaign.name,
        "description": campaign.description,
        "first_seen": campaign.first_seen,
        "last_seen": campaign.last_seen,
        "iocs": [
            {"id": i.id, "type": i.type, "value": i.value, "source": i.source}
            for i in ioc_rows.scalars().all()
        ],
    }


def _to_csv(rows: list[dict]) -> str:
    if not rows:
        return ""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0].keys()))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


@router.get("/feeds/phishing")
async def export_phishing_feed(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("feed:read")),
):
    rows = await db.execute(
        select(IOC).where(IOC.org_id == current_user.org_id, IOC.type.in_(["domain", "url"]), IOC.source.in_(["phishtank", "openphish"])).order_by(IOC.id.desc()).limit(10000)
    )
    items = [{"id": i.id, "type": i.type, "value": i.value, "source_feed": i.source, "confidence": i.confidence, "last_verified": i.last_seen} for i in rows.scalars().all()]
    if format == "csv":
        return Response(content=_to_csv(items), media_type="text/csv")
    return {"items": items}


@router.get("/feeds/malware")
async def export_malware_feed(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("feed:read")),
):
    rows = await db.execute(
        select(IOC).where(IOC.org_id == current_user.org_id, IOC.type == "file_hash").order_by(IOC.id.desc()).limit(10000)
    )
    items = [{"id": i.id, "type": i.type, "value": i.value, "source_feed": i.source, "confidence": i.confidence, "last_verified": i.last_seen} for i in rows.scalars().all()]
    if format == "csv":
        return Response(content=_to_csv(items), media_type="text/csv")
    return {"items": items}


@router.get("/feeds/iocs")
async def export_all_iocs(
    format: str = Query(default="json", pattern="^(json|csv)$"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("feed:read")),
):
    rows = await db.execute(select(IOC).where(IOC.org_id == current_user.org_id).order_by(IOC.id.desc()).limit(20000))
    items = [{"id": i.id, "type": i.type, "value": i.value, "source_feed": i.source, "confidence": i.confidence, "first_seen": i.first_seen, "last_seen": i.last_seen} for i in rows.scalars().all()]
    if format == "csv":
        return Response(content=_to_csv(items), media_type="text/csv")
    return {"items": items}
