import asyncio
import json
import os
import uuid
from typing import AsyncGenerator

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import create_access_token
from app.core.logging import JsonFormatter, logger
from app.core.security import hash_password
from app.database.models import AuditEvent, Base, IOC, Organization, User
from app.database.session import get_db
from app.main import app
from app.services.search_backend import opensearch_backend
from app.tasks.celery_worker import celery_app
from app.tasks.search_tasks import run_index_ioc_task


pytestmark = pytest.mark.asyncio

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://threat_user:password@localhost:5432/threat_intel_db")
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)


class _ListHandler:
    def __init__(self) -> None:
        import logging

        self.handler = logging.Handler()
        self.messages: list[str] = []
        self.handler.emit = self._emit  # type: ignore[method-assign]
        self.handler.setFormatter(JsonFormatter())

    def _emit(self, record) -> None:
        self.messages.append(self.handler.format(record))


@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture()
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    engine = create_async_engine(DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.execute(text("ALTER TABLE organizations ADD COLUMN IF NOT EXISTS plan varchar DEFAULT 'free'"))
        await conn.run_sync(Base.metadata.create_all)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with async_session() as session:
        yield session
    await engine.dispose()


@pytest_asyncio.fixture()
async def client(db_session: AsyncSession):
    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as async_client:
        yield async_client
    app.dependency_overrides.clear()


async def _create_admin_user(db: AsyncSession) -> tuple[Organization, User]:
    org = Organization(name=f"search-trace-{uuid.uuid4().hex[:8]}")
    db.add(org)
    await db.flush()

    user = User(
        org_id=org.id,
        email=f"search-trace-{uuid.uuid4().hex[:8]}@test.local",
        password_hash=hash_password("TestPass!1"),
        role="admin",
    )
    db.add(user)
    await db.commit()
    await db.refresh(org)
    await db.refresh(user)
    return org, user


async def test_ioc_create_enqueues_index_task_and_preserves_request_id(client: AsyncClient, db_session: AsyncSession, monkeypatch):
    org, user = await _create_admin_user(db_session)
    token = create_access_token({"sub": str(user.id), "org_id": str(org.id)})

    sent_task: dict[str, object] = {}

    def fake_send_task(name, args=None, kwargs=None):
        sent_task["name"] = name
        sent_task["args"] = args or []
        sent_task["kwargs"] = kwargs or {}
        return {"queued": True}

    monkeypatch.setattr(celery_app, "send_task", fake_send_task)

    response = await client.post(
        "/api/v1/intel/ioc",
        headers={"Authorization": f"Bearer {token}"},
        json={"type": "domain", "value": f"trace-{uuid.uuid4().hex[:8]}.example", "source": "manual"},
    )

    assert response.status_code == 201
    request_id = response.headers.get("X-Request-ID")
    assert request_id

    response_payload = response.json()
    payload = response_payload.get("data", response_payload)
    ioc_id = payload["id"]
    assert sent_task["name"] == "app.tasks.celery_worker.index_ioc_task"
    assert sent_task["args"] == [ioc_id, str(org.id), request_id]

    audit_row = await db_session.execute(
        select(AuditEvent).where(
            AuditEvent.action == "ioc_created",
            AuditEvent.request_id == request_id,
            AuditEvent.resource_id == str(ioc_id),
        )
    )
    audit_event = audit_row.scalar_one_or_none()
    assert audit_event is not None

    monkeypatch.setattr(opensearch_backend, "ensure_ioc_index", lambda: None)
    monkeypatch.setattr(opensearch_backend, "bulk_upsert_iocs", lambda docs: {"indexed": len(docs), "failed": 0})

    list_handler = _ListHandler()
    logger.addHandler(list_handler.handler)
    try:
        task_result = run_index_ioc_task(ioc_id=ioc_id, org_id=str(org.id), request_id=request_id)
    finally:
        logger.removeHandler(list_handler.handler)

    assert task_result["indexed"] == 1

    task_log = None
    for message in list_handler.messages:
        payload = json.loads(message)
        if payload.get("event") == "search_ioc_indexed":
            task_log = payload
            break

    assert task_log is not None
    assert task_log["request_id"] == request_id
    assert task_log["org_id"] == str(org.id)

    indexed_row = await db_session.execute(select(IOC).where(IOC.id == ioc_id, IOC.org_id == org.id))
    assert indexed_row.scalar_one_or_none() is not None