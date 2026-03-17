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
            analysis = await domain_engine.analyze(scan.target_url, db)
            score = analysis.get("score", {})
            structural_score = score.get("structural_score", 0)
            vt_score = score.get("vt_score", 0)
            ioc_score = score.get("ioc_score", 0)
            feed_intel_score = score.get("feed_intel_score", 0)
            historical_score = score.get("historical_score", 0)
            risk_score = score.get("total_score", 0)
            level = score.get("risk_level", "low")
            signals = analysis.get("signals", {})
            vt_response = analysis.get("vt", {}).get("raw", {})
            # save scan result
            scan_result = ScanResult(
                scan_id=scan.id,
                structural_score=structural_score,
                vt_score=vt_score,
                ioc_score=ioc_score,
                feed_intel_score=feed_intel_score,
                historical_score=historical_score,
                risk_score=risk_score,
                risk_level=level,
                signals_json=signals,
                vt_raw_json=vt_response,
                signals=signals,
                vt_response=vt_response,
                summary="",  # could generate summary later
            )
            db.add(scan_result)
            # mirror key outputs on scans table for Week 3 requirements
            scan.structural_score = structural_score
            scan.vt_score = vt_score
            scan.feed_intel_score = feed_intel_score
            scan.historical_score = historical_score
            scan.risk_score = risk_score
            scan.signals = signals
            scan.vt_response = vt_response
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
            return


async def process_file_scan(file_scan_id: int, file_content: bytes, filename: str):
    """Background worker to process a file scan."""
    from app.database.models import FileScan
    from app.services import file_engine

    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(FileScan).filter_by(id=file_scan_id))
            file_scan = result.scalar_one_or_none()
            if not file_scan:
                return
            # run analysis
            analysis = await file_engine.analyze_file(file_content, filename)
            # update file scan
            file_scan.vt_score = analysis.get("vt_result", {}).get("stats", {}).get("malicious", 0)
            file_scan.risk_score = analysis.get("risk_score", 0)
            file_scan.vt_raw_json = analysis.get("vt_result", {}).get("raw", {})
            file_scan.status = "completed"
            file_scan.completed_at = datetime.utcnow()
            await db.commit()
        except Exception as e:
            await db.execute(
                update(FileScan)
                .where(FileScan.id == file_scan_id)
                .values(status="failed", completed_at=datetime.utcnow())
            )
            await db.commit()
            return
