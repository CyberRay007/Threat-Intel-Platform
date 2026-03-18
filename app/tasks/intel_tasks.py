import asyncio
import os
from typing import Any, Dict, Optional

from sqlalchemy import select

from app.database.session import AsyncSessionLocal
from app.services.feed_ingestion import ingest_all_sources, ingest_source, FEEDS
from app.core.metrics import record_feed_ingest, check_feed_staleness
from app.database.models import Organization
from app.core.logging import logger


async def _run_ingest_all(limit_per_source: Optional[int] = None) -> Dict[str, Any]:
    otx_api_key = os.getenv("OTX_API_KEY")
    async with AsyncSessionLocal() as db:
        rows = await db.execute(select(Organization.id))
        org_ids = [str(row[0]) for row in rows.all()]
        if not org_ids:
            raise RuntimeError("No organizations found; refusing to ingest without org context")

        all_sources = []
        totals = {"fetched": 0, "normalized": 0, "inserted": 0, "skipped": 0, "errors": 0}
        for org_id in org_ids:
            summary = await ingest_all_sources(
                db,
                limit_per_source=limit_per_source,
                otx_api_key=otx_api_key,
                org_id=org_id,
            )
            for source_row in summary.get("sources", []):
                success = int(source_row.get("errors", 0)) == 0
                record_feed_ingest(org_id, source_row.get("source", "unknown"), success=success)
                all_sources.append({"org_id": org_id, **source_row})
            for key in totals.keys():
                totals[key] += int(summary.get("totals", {}).get(key, 0))

        return {"sources": all_sources, "totals": totals}


async def _run_ingest_source(source: str, limit: Optional[int] = None) -> Dict[str, Any]:
    otx_api_key = os.getenv("OTX_API_KEY")
    async with AsyncSessionLocal() as db:
        rows = await db.execute(select(Organization.id))
        org_ids = [str(row[0]) for row in rows.all()]
        if not org_ids:
            raise RuntimeError("No organizations found; refusing to ingest without org context")

        aggregate: Dict[str, Any] = {"source": source, "by_org": []}
        try:
            for org_id in org_ids:
                result = await ingest_source(db, source=source, limit=limit, otx_api_key=otx_api_key, org_id=org_id)
                success = (result.errors == 0 or result.inserted > 0)
                record_feed_ingest(org_id, source, success=success)
                aggregate["by_org"].append({"org_id": org_id, **result.__dict__})
            return aggregate
        except Exception as exc:
            for org_id in org_ids:
                record_feed_ingest(org_id, source, success=False)
            logger.warning("ingest_single_feed_failed", extra={"extra_payload": {"source": source, "error": str(exc)}})
            raise


def ingest_all_feeds(limit_per_source: Optional[int] = None) -> Dict[str, Any]:
    return asyncio.run(_run_ingest_all(limit_per_source=limit_per_source))


def ingest_single_feed(source: str, limit: Optional[int] = None) -> Dict[str, Any]:
    return asyncio.run(_run_ingest_source(source=source, limit=limit))


def check_feed_staleness_all() -> None:
    """Called from Celery beat to check every feed for staleness."""
    # Feed staleness checks run in-memory per worker. We scope by org by reusing
    # known keys from metric state via ingest record paths.
    # This function intentionally checks common source keys for each org seen.
    # If an org has never ingested, no stale alert is emitted.
    # NOTE: Multi-worker deployments should externalize metric state.
    rows = []
    try:
        async def _org_ids():
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(Organization.id))
                return [str(r[0]) for r in result.all()]
        rows = asyncio.run(_org_ids())
    except Exception:
        rows = []

    for org_id in rows:
        for source in FEEDS:
            check_feed_staleness(org_id, source)
