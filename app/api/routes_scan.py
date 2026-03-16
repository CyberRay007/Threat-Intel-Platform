from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from datetime import datetime

from app.database.session import get_db
from app.database.models import Scan, ScanResult, User, FileScan
from app.schemas.scan_schema import ScanCreate, ScanResponse, FileScanCreate, FileScanResponse
from app.dependencies import get_current_user
from app.tasks.scan_tasks import process_scan, process_file_scan


router = APIRouter()


@router.get("/", summary="List scans for current user")
async def list_scans(
    status: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    offset = (page - 1) * limit
    base = select(Scan).where(Scan.user_id == current_user.id)
    count_q = select(func.count()).select_from(Scan).where(Scan.user_id == current_user.id)
    if status:
        base = base.where(Scan.status == status)
        count_q = count_q.where(Scan.status == status)
    rows = await db.execute(base.order_by(Scan.created_at.desc()).limit(limit).offset(offset))
    total = await db.execute(count_q)
    return {
        "page": page,
        "limit": limit,
        "total": total.scalar_one(),
        "scans": rows.scalars().all(),
    }


@router.post("/scan", response_model=ScanResponse)
async def submit_scan(
    scan_in: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Create Scan for authenticated user
    scan = Scan(
        user_id=current_user.id,
        target_url=scan_in.target_url,
        status="pending",
        created_at=datetime.utcnow(),
    )
    db.add(scan)
    await db.commit()
    await db.refresh(scan)

    # schedule background processing
    background_tasks.add_task(process_scan, scan.id)

    return ScanResponse(
        id=scan.id,
        target_url=scan.target_url,
        status=scan.status,
        structural_score=scan.structural_score,
        vt_score=scan.vt_score,
        feed_intel_score=scan.feed_intel_score,
        historical_score=scan.historical_score,
        risk_score=scan.risk_score,
        created_at=scan.created_at,
        completed_at=scan.completed_at,
        result=None,
    )


@router.get("/scan/{scan_id}", response_model=ScanResponse)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    row = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id))
    scan = row.scalar_one_or_none()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # eagerly load the result row so it appears in the response
    result_row = await db.execute(select(ScanResult).where(ScanResult.scan_id == scan_id))
    scan.result = result_row.scalar_one_or_none()

    return scan


@router.post("/scan/file", response_model=FileScanResponse)
async def submit_file_scan(
    file: UploadFile = File(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Read file content
    file_content = await file.read()
    if len(file_content) == 0:
        raise HTTPException(status_code=400, detail="Empty file")

    # Generate hashes
    import hashlib
    sha256 = hashlib.sha256(file_content).hexdigest()

    # Create FileScan
    file_scan = FileScan(
        user_id=current_user.id,
        filename=file.filename,
        sha256=sha256,
        status="pending",
        created_at=datetime.utcnow(),
    )
    db.add(file_scan)
    await db.commit()
    await db.refresh(file_scan)

    # schedule background processing
    background_tasks.add_task(process_file_scan, file_scan.id, file_content, file.filename)

    return file_scan
