from __future__ import annotations

import asyncio
import threading
from typing import Any

from app.core.logging import reset_log_context, set_log_context
from app.database.session import AsyncSessionLocal
from app.services.search_service import delete_ioc_document, index_ioc_by_id, index_iocs_by_identity


async def _index_ioc(ioc_id: int, org_id: str, request_id: str | None = None) -> dict[str, Any]:
    tokens = set_log_context(request_id=request_id, org_id=org_id)
    try:
        async with AsyncSessionLocal() as db:
            return await index_ioc_by_id(db, ioc_id=ioc_id, org_id=org_id, request_id=request_id)
    finally:
        reset_log_context(tokens)


async def _bulk_index_iocs(org_id: str, identities: list[list[str]], request_id: str | None = None) -> dict[str, Any]:
    tokens = set_log_context(request_id=request_id, org_id=org_id)
    try:
        async with AsyncSessionLocal() as db:
            return await index_iocs_by_identity(db, org_id=org_id, identities=identities, request_id=request_id)
    finally:
        reset_log_context(tokens)


def _run_async_in_thread(coro):
    """Run an async coroutine in a separate thread with its own event loop."""
    result = []
    exception = []

    def run():
        try:
            result.append(asyncio.run(coro))
        except Exception as e:
            exception.append(e)

    thread = threading.Thread(target=run, daemon=False)
    thread.start()
    thread.join()

    if exception:
        raise exception[0]
    return result[0]


def run_index_ioc_task(ioc_id: int, org_id: str, request_id: str | None = None) -> dict[str, Any]:
    return _run_async_in_thread(_index_ioc(ioc_id=ioc_id, org_id=org_id, request_id=request_id))


def run_bulk_index_iocs_task(org_id: str, identities: list[list[str]], request_id: str | None = None) -> dict[str, Any]:
    return _run_async_in_thread(_bulk_index_iocs(org_id=org_id, identities=identities, request_id=request_id))


def run_delete_ioc_document_task(ioc_id: int, org_id: str, request_id: str | None = None) -> dict[str, Any]:
    tokens = set_log_context(request_id=request_id, org_id=org_id)
    try:
        return delete_ioc_document(org_id=org_id, ioc_id=ioc_id, request_id=request_id)
    finally:
        reset_log_context(tokens)