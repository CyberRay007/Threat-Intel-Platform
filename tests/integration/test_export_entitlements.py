import os
import uuid

os.environ.setdefault("JWT_SECRET_KEY", "test-secret")

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import create_access_token
from app.core.security import hash_password
from app.database.models import Base, Organization, User
from app.database.session import get_db
from app.main import app


pytestmark = pytest.mark.asyncio

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://threat_user:password@localhost:5432/threat_intel_db")
if DATABASE_URL.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)


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


async def _create_user(db: AsyncSession, plan: str) -> tuple[Organization, User]:
    org = Organization(name=f"org-{plan}-{uuid.uuid4().hex[:6]}", plan=plan)
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


async def test_stix_export_denied_for_free_plan(client: AsyncClient, db_session: AsyncSession):
    org, user = await _create_user(db_session, "free")
    token = create_access_token({"sub": str(user.id), "org_id": str(org.id)})

    response = await client.get(
        "/api/v1/export/stix2.1/indicators",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 402


async def test_json_export_allowed_for_free_plan(client: AsyncClient, db_session: AsyncSession):
    org, user = await _create_user(db_session, "free")
    token = create_access_token({"sub": str(user.id), "org_id": str(org.id)})

    response = await client.get(
        "/api/v1/export/json",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    body = response.json()
    assert "meta" in body
    assert "data" in body


async def test_csv_export_content_type(client: AsyncClient, db_session: AsyncSession):
    org, user = await _create_user(db_session, "pro")
    token = create_access_token({"sub": str(user.id), "org_id": str(org.id)})

    response = await client.get(
        "/api/v1/export/csv",
        headers={"Authorization": f"Bearer {token}"},
    )

    assert response.status_code == 200
    assert response.headers.get("content-type", "").startswith("text/csv")
    assert "content-disposition" in response.headers
