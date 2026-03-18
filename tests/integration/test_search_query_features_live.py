import os
import uuid

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.config import OPENSEARCH_IOC_INDEX
from app.core.jwt import create_access_token
from app.core.security import hash_password
from app.database.models import Base, Organization, User
from app.database.session import get_db
from app.main import app
from app.services.search_backend import opensearch_backend


pytestmark = pytest.mark.asyncio

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://threat_user:password@localhost:5432/threat_intel_db")
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)


def _bulk_docs(org_id: str, start_id: int, count: int):
    docs = []
    for i in range(count):
        ioc_type = ["domain", "ip", "url", "file_hash"][i % 4]
        value = f"feature-{ioc_type}-{start_id + i}.example" if ioc_type != "ip" else f"10.2.{i // 255}.{i % 255}"
        docs.append(
            {
                "id": start_id + i,
                "org_id": org_id,
                "type": ioc_type,
                "value": value,
                "value_text": value,
                "tags": ["feature-test", f"bucket-{i % 3}"],
                "source": ["feed-a", "feed-b", "feed-c"][i % 3],
                "threat_actor_id": None,
                "threat_actor_name": "",
                "first_seen": "2026-03-18T00:00:00Z",
                "last_seen": "2026-03-18T00:00:00Z",
                "confidence": round(0.5 + ((i % 40) / 100), 2),
                "source_reliability": 0.8,
                "relationship_count": i % 4,
            }
        )
    return docs


@pytest_asyncio.fixture()
async def db_session():
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


async def _create_user(db: AsyncSession, plan: str):
    org = Organization(name=f"search-{plan}-{uuid.uuid4().hex[:6]}", plan=plan)
    db.add(org)
    await db.flush()
    user = User(
        org_id=org.id,
        email=f"{plan}-{uuid.uuid4().hex[:6]}@test.local",
        password_hash=hash_password("TestPass!1"),
        role="admin",
    )
    db.add(user)
    await db.commit()
    await db.refresh(org)
    await db.refresh(user)
    return org, user


async def test_search_entitlements_pagination_filtering_and_aggs(client: AsyncClient, db_session: AsyncSession):
    opensearch_backend.ensure_ioc_index()

    free_org, free_user = await _create_user(db_session, "free")
    pro_org, pro_user = await _create_user(db_session, "pro")
    ent_org, ent_user = await _create_user(db_session, "enterprise")

    # Index tenant-specific docs for each org.
    opensearch_backend.bulk_upsert_iocs(_bulk_docs(str(free_org.id), 300000, 30))
    opensearch_backend.bulk_upsert_iocs(_bulk_docs(str(pro_org.id), 400000, 30))
    opensearch_backend.bulk_upsert_iocs(_bulk_docs(str(ent_org.id), 500000, 30))
    opensearch_backend._request("POST", f"/{OPENSEARCH_IOC_INDEX}/_refresh")

    # Entitlement check: all current plans include search_intelligence.
    for user in (free_user, pro_user, ent_user):
        token = create_access_token({"sub": str(user.id), "org_id": str(user.org_id)})
        resp = await client.get("/api/v1/search/iocs", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 200

    # Pagination + filter + aggregations check on enterprise org.
    token = create_access_token({"sub": str(ent_user.id), "org_id": str(ent_org.id)})
    resp = await client.get(
        "/api/v1/search/iocs?ioc_type=domain&min_confidence=0.6&page=1&limit=10",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    body = resp.json()

    assert body["page"] == 1
    assert body["limit"] == 10
    assert body["total"] >= 1
    assert len(body["items"]) <= 10
    assert "aggregations" in body
    assert "by_type" in body["aggregations"]
    assert "by_source" in body["aggregations"]

    # Tenant isolation on same query (enterprise user should only see enterprise org docs).
    assert all(item["org_id"] == str(ent_org.id) for item in body["items"])
