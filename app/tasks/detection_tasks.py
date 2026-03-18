import asyncio
from typing import Any, Dict

from sqlalchemy import select

from app.database.models import Event
from app.database.session import AsyncSessionLocal
from app.services.detection_pipeline import process_event
from app.core.metrics import record_event_queued, record_event_processed
from app.core.logging import logger


_WORKER_LOOP: asyncio.AbstractEventLoop | None = None


def _run_in_worker_loop(coro):
    global _WORKER_LOOP
    if _WORKER_LOOP is None or _WORKER_LOOP.is_closed():
        _WORKER_LOOP = asyncio.new_event_loop()
        asyncio.set_event_loop(_WORKER_LOOP)
    return _WORKER_LOOP.run_until_complete(coro)


async def _process_event_by_id(event_id: int, org_id: str | None = None, request_id: str | None = None) -> Dict[str, Any]:
    async with AsyncSessionLocal() as db:
        row = await db.execute(select(Event).where(Event.id == event_id))
        event = row.scalar_one_or_none()
        if not event:
            return {"event_id": event_id, "status": "not_found"}
        if not event.org_id:
            raise RuntimeError(f"event {event_id} missing org_id")
        if org_id is not None and str(event.org_id) != str(org_id):
            raise RuntimeError(f"event {event_id} org mismatch: task={org_id} db={event.org_id}")

        record_event_queued(event_id, str(event.org_id))
        logger.info(
            "detection_task_start",
            extra={"extra_payload": {
                "event": "detection_task_start",
                "event_id": event_id,
                "org_id": str(event.org_id),
                "request_id": request_id,
            }},
        )

        await process_event(db, event)
        record_event_processed(event_id)
        return {"event_id": event_id, "status": "processed"}


async def process_event_by_id(event_id: int, org_id: str | None = None, request_id: str | None = None) -> Dict[str, Any]:
    return await _process_event_by_id(event_id, org_id=org_id, request_id=request_id)


def process_event_task(event_id: int, org_id: str | None = None, request_id: str | None = None) -> Dict[str, Any]:
    return _run_in_worker_loop(_process_event_by_id(event_id, org_id=org_id, request_id=request_id))


async def _process_backlog(limit: int = 100) -> Dict[str, Any]:
    async with AsyncSessionLocal() as db:
        rows = await db.execute(
            select(Event)
            .where(Event.status.in_(["queued", "queue_failed"]))
            .order_by(Event.created_at.asc())
            .limit(limit)
        )
        events = rows.scalars().all()

        processed = 0
        failed = 0
        for event in events:
            try:
                if not event.org_id:
                    raise RuntimeError(f"event {event.id} missing org_id")
                await process_event(db, event)
                processed += 1
            except Exception:
                failed += 1
                await db.rollback()

        return {
            "requested_limit": limit,
            "picked": len(events),
            "processed": processed,
            "failed": failed,
        }


def process_detection_backlog_task(limit: int = 100) -> Dict[str, Any]:
    return _run_in_worker_loop(_process_backlog(limit=limit))
