from __future__ import annotations

import argparse
import random
import string
import time
from datetime import datetime, timedelta
from uuid import uuid4

import asyncio
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.database.models import Base, IOC, Organization
from app.services.search_service import search_iocs


def _rand_domain() -> str:
    root = "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"{root}.example"


async def seed_iocs(db: AsyncSession, org_id, count: int) -> None:
    batch = []
    types = ["domain", "ip", "url", "file_hash"]
    sources = ["urlhaus", "otx", "phishtank", "internal"]

    for i in range(count):
        ioc_type = types[i % len(types)]
        if ioc_type == "ip":
            value = f"10.{(i // 255) % 255}.{i % 255}.{(i * 7) % 255}"
        elif ioc_type == "url":
            value = f"http://{_rand_domain()}/p/{i}"
        elif ioc_type == "file_hash":
            value = f"{i:064x}"[-64:]
        else:
            value = _rand_domain()

        batch.append(
            IOC(
                org_id=org_id,
                type=ioc_type,
                value=value,
                source=sources[i % len(sources)],
                confidence=round(0.5 + (i % 50) / 100, 2),
                source_reliability=0.8,
                first_seen=datetime.utcnow() - timedelta(days=i % 90),
                last_seen=datetime.utcnow(),
            )
        )

        if len(batch) == 5000:
            db.add_all(batch)
            await db.flush()
            batch.clear()

    if batch:
        db.add_all(batch)
        await db.flush()


async def run_benchmark(database_url: str, ioc_count: int, warmup_queries: int, measured_queries: int) -> None:
    engine = create_async_engine(database_url, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    Session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async with Session() as db:
        org = Organization(name=f"load-bench-{uuid4().hex[:8]}", plan="enterprise")
        db.add(org)
        await db.flush()

        start_seed = time.perf_counter()
        await seed_iocs(db, org.id, ioc_count)
        await db.commit()
        seed_seconds = time.perf_counter() - start_seed

        print(f"Seeded {ioc_count} IOCs in {seed_seconds:.2f}s ({ioc_count / max(seed_seconds, 0.001):.1f} ioc/s)")

        for _ in range(warmup_queries):
            await search_iocs(org_id=str(org.id), q=None, page=1, limit=50)

        latencies = []
        for idx in range(measured_queries):
            t0 = time.perf_counter()
            await search_iocs(
                org_id=str(org.id),
                q=None if idx % 3 else ".example",
                ioc_type="domain" if idx % 2 else None,
                min_confidence=0.7,
                page=1,
                limit=100,
            )
            latencies.append((time.perf_counter() - t0) * 1000)

        latencies.sort()
        p50 = latencies[len(latencies) // 2]
        p95 = latencies[int(len(latencies) * 0.95) - 1]
        p99 = latencies[int(len(latencies) * 0.99) - 1]
        avg = sum(latencies) / len(latencies)

        print("Search benchmark results (ms):")
        print(f"  avg={avg:.2f}")
        print(f"  p50={p50:.2f}")
        print(f"  p95={p95:.2f}")
        print(f"  p99={p99:.2f}")

    await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Load-test search with production-like IOC volume")
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--iocs", type=int, default=100000)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--queries", type=int, default=50)
    args = parser.parse_args()

    asyncio.run(run_benchmark(args.database_url, args.iocs, args.warmup, args.queries))


if __name__ == "__main__":
    main()
