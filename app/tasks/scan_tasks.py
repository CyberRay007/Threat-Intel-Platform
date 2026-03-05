import asyncio
from datetime import datetime
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import AsyncSessionLocal
from app.database.models import Scan, ScanResult
from app.services import domain_engine


async def process_scan(scan_id: int):
    """Background worker to process a scan and write results."""
    async with AsyncSessionLocal() as db:  # new session independent of request
        try:
            result = await db.execute(select(Scan).filter_by(id=scan_id))
            scan = result.scalar_one_or_none()
            if not scan:
                return
            # run analysis
            analysis = domain_engine.analyze(scan.target_url)
            # save scan result
            scan_result = ScanResult(
                scan_id=scan.id,
                structural_score=analysis.get("score", {}).get("structural_score", 0),
                vt_score=analysis.get("score", {}).get("vt_score", 0),
                ioc_score=analysis.get("score", {}).get("ioc_score", 0),
                risk_score=analysis.get("score", {}).get("total_score", 0),
                signals_json=analysis.get("signals"),
                vt_raw_json=analysis.get("vt", {}).get("raw"),
                summary="",  # could generate summary later
            )
            db.add(scan_result)
            # update scan status
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            await db.commit()
        except Exception as e:
            # mark scan failed
            await db.execute(
                update(Scan)
                .where(Scan.id == scan_id)
                .values(status="failed", completed_at=datetime.utcnow())
            )
            await db.commit()
            raise
