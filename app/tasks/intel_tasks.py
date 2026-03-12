import asyncio
import os
from typing import Any, Dict, Optional

from app.database.session import AsyncSessionLocal
from app.services.feed_ingestion import ingest_all_sources, ingest_source


async def _run_ingest_all(limit_per_source: Optional[int] = None) -> Dict[str, Any]:
    otx_api_key = os.getenv("OTX_API_KEY")
    async with AsyncSessionLocal() as db:
        return await ingest_all_sources(db, limit_per_source=limit_per_source, otx_api_key=otx_api_key)


async def _run_ingest_source(source: str, limit: Optional[int] = None) -> Dict[str, Any]:
    otx_api_key = os.getenv("OTX_API_KEY")
    async with AsyncSessionLocal() as db:
        result = await ingest_source(db, source=source, limit=limit, otx_api_key=otx_api_key)
        return result.__dict__


def ingest_all_feeds(limit_per_source: Optional[int] = None) -> Dict[str, Any]:
    return asyncio.run(_run_ingest_all(limit_per_source=limit_per_source))


def ingest_single_feed(source: str, limit: Optional[int] = None) -> Dict[str, Any]:
    return asyncio.run(_run_ingest_source(source=source, limit=limit))
