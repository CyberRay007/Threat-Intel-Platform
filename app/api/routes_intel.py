from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import OTX_API_KEY
from app.database.models import IOC, IOCRelationship, MalwareFamily, User
from app.database.session import get_db
from app.dependencies import get_current_user
from app.services.intel_enrichment import attribute_observable, enrich_ioc
from app.services.feed_ingestion import FEEDS, ingest_all_sources, ingest_source


router = APIRouter()


@router.post("/intel/ingest")
async def run_ingestion(
    source: Optional[str] = Query(default=None),
    limit: Optional[int] = Query(default=None, ge=1),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if source:
        if source not in FEEDS:
            return {"error": f"unknown source '{source}'", "supported_sources": sorted(FEEDS.keys())}
        result = await ingest_source(db, source=source, limit=limit, otx_api_key=OTX_API_KEY or None)
        return {"source": result.__dict__}

    return await ingest_all_sources(db, limit_per_source=limit, otx_api_key=OTX_API_KEY or None)


@router.get("/intel/ioc/enrich")
async def enrich_ioc_endpoint(
    ioc_type: str = Query(..., description="domain|url|ip|file_hash"),
    value: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await enrich_ioc(db, ioc_type=ioc_type, value=value)


@router.get("/intel/attribution")
async def attribution_endpoint(
    ioc_type: str = Query(..., description="domain|url|ip|file_hash"),
    value: str = Query(..., min_length=2),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    return await attribute_observable(db, ioc_type=ioc_type, value=value)


@router.get("/intel/ioc/stats")
async def ioc_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = await db.execute(select(func.count()).select_from(IOC))
    by_type = await db.execute(
        select(IOC.type, func.count()).group_by(IOC.type).order_by(IOC.type)
    )
    by_source = await db.execute(
        select(IOC.source, func.count()).group_by(IOC.source).order_by(IOC.source)
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
    current_user: User = Depends(get_current_user),
):
    """Return domains linked to the same malware family as the input domain."""
    domain_norm = domain.strip().lower().strip(".")

    source_ioc_row = await db.execute(
        select(IOC).where(IOC.type == "domain", IOC.value == domain_norm)
    )
    source_ioc = source_ioc_row.scalar_one_or_none()
    if not source_ioc:
        return {"domain": domain_norm, "families": [], "related_domains": []}

    family_rows = await db.execute(
        select(IOCRelationship.malware_family_id)
        .where(
            IOCRelationship.ioc_id == source_ioc.id,
            IOCRelationship.malware_family_id.isnot(None),
        )
        .distinct()
    )
    family_ids = [fid for (fid,) in family_rows.all() if fid is not None]
    if not family_ids:
        return {"domain": domain_norm, "families": [], "related_domains": []}

    family_name_rows = await db.execute(
        select(MalwareFamily.id, MalwareFamily.name).where(MalwareFamily.id.in_(family_ids))
    )
    family_name_map = {fid: name for fid, name in family_name_rows.all()}

    related_rows = await db.execute(
        select(IOC.value, IOCRelationship.malware_family_id)
        .join(IOCRelationship, IOCRelationship.ioc_id == IOC.id)
        .where(
            IOC.type == "domain",
            IOCRelationship.malware_family_id.in_(family_ids),
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
