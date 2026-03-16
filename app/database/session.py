# app/database/session.py
import os
import asyncio
from datetime import datetime
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.database.models import Base, User, Scan, ScanResult, ThreatActor, IOC

# load environment variables
load_dotenv()

# look up URL in environment or use default
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://threat_user:password@localhost:5432/threat_intel_db",
)

# convert to asyncpg dialect if using Postgres
if DATABASE_URL.startswith("postgresql://"):
    ASYNC_DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://", 1)
else:
    ASYNC_DATABASE_URL = DATABASE_URL

# create async engine and session maker
async_engine = create_async_engine(ASYNC_DATABASE_URL, echo=True)
AsyncSessionLocal = sessionmaker(
    bind=async_engine, expire_on_commit=False, class_=AsyncSession
)


async def get_db():
    """FastAPI dependency which yields an AsyncSession."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Create tables asynchronously."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def seed_sample_data():
    """Insert sample rows if they aren't already in the database."""
    async with AsyncSessionLocal() as db:
        result = await db.execute(text("SELECT * FROM users WHERE email = :email"), {"email": "alice@example.com"})
        if result.fetchone():
            print("Sample data already exists, skipping seeding.")
            return

        user = User(email="alice@example.com", password_hash="hashedpassword123")
        db.add(user)
        await db.commit()
        await db.refresh(user)
        print(f"Inserted User: {user.id}, {user.email}")

        scan = Scan(user_id=user.id, target_url="http://example.com", status="completed", completed_at=datetime.utcnow())
        db.add(scan)
        await db.commit()
        await db.refresh(scan)
        print(f"Inserted Scan: {scan.id}, for User ID: {scan.user_id}")

        result_obj = ScanResult(
            scan_id=scan.id,
            domain_score=8,
            structure_score=7,
            behavior_score=6,
            exploit_score=5,
            total_score=26,
            risk_level="medium",
            details={"note": "Sample scan result"},
        )
        db.add(result_obj)
        await db.commit()
        await db.refresh(result_obj)
        print(f"Inserted ScanResult: {result_obj.id}, linked to Scan ID: {result_obj.scan_id}")

        actor = ThreatActor(
            name="APT Lazarus",
            description="North Korean state-sponsored threat actor.",
            first_seen=datetime(2020, 1, 1),
            last_seen=datetime(2023, 12, 31),
        )
        db.add(actor)
        await db.commit()
        await db.refresh(actor)
        print(f"Inserted ThreatActor: {actor.id}, {actor.name}")

        iocs = [
            IOC(type="ip", value="192.168.1.100", threat_actor_id=actor.id, source="ThreatIntelFeed"),
            IOC(type="domain", value="malicious-example.com", threat_actor_id=actor.id, source="ThreatIntelFeed"),
            IOC(type="hash", value="abcdef1234567890", threat_actor_id=actor.id, source="InternalAnalysis"),
        ]
        db.add_all(iocs)
        await db.commit()
        for ioc in iocs:
            await db.refresh(ioc)
            print(f"Inserted IOC: {ioc.id}, type: {ioc.type}, value: {ioc.value}")

        print("\n✅ Sample data inserted successfully!")


if __name__ == "__main__":
    async def main():
        await init_db()
        await seed_sample_data()

    asyncio.run(main())