import asyncio
import os
from typing import Any, Dict, Optional

from app.database.session import AsyncSessionLocal
from app.services.feed_ingestion import ingest_all_sources, ingest_source, FEEDS
from app.core.metrics import record_feed_ingest, check_feed_staleness


async def _run_ingest_all(limit_per_source: Optional[int] = None) -> Dict[str, Any]:
    otx_api_key = os.getenv("OTX_API_KEY")
    async with AsyncSessionLocal() as db:
        return await ingest_all_sources(db, limit_per_source=limit_per_source, otx_api_key=otx_api_key)


async def _run_ingest_source(source: str, limit: Optional[int] = None) -> Dict[str, Any]:
    otx_api_key = os.getenv("OTX_API_KEY")
    async with AsyncSessionLocal() as db:
        try:
            result = await ingest_source(db, source=source, limit=limit, otx_api_key=otx_api_key)
            success = (result.errors == 0 or result.inserted > 0)
            record_feed_ingest(source, success=success)
            return result.__dict__
        except Exception as exc:
            record_feed_ingest(source, success=False)
            raise


def ingest_all_feeds(limit_per_source: Optional[int] = None) -> Dict[str, Any]:
    return asyncio.run(_run_ingest_all(limit_per_source=limit_per_source))


def ingest_single_feed(source: str, limit: Optional[int] = None) -> Dict[str, Any]:
    return asyncio.run(_run_ingest_source(source=source, limit=limit))


def check_feed_staleness_all() -> None:
    """Called from Celery beat to check every feed for staleness."""
    for source in FEEDS:
        check_feed_staleness(source)
