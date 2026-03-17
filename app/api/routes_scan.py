from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, UploadFile, File, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import func, select
from datetime import datetime

from app.database.session import get_db
from app.database.models import Scan, ScanResult, User, FileScan
from app.schemas.scan_schema import ScanCreate, ScanResponse, FileScanCreate, FileScanResponse, FileScanListResponse
from app.dependencies import require_permission
from app.tasks.scan_tasks import process_scan, process_file_scan


router = APIRouter()


@router.get("/scan/file", response_model=FileScanListResponse, summary="List file scans for current user")
async def list_file_scans(
    status: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    offset = (page - 1) * limit
    base = select(FileScan).where(FileScan.user_id == current_user.id)
    base = base.where(FileScan.org_id == current_user.org_id)
    count_q = select(func.count()).select_from(FileScan).where(FileScan.user_id == current_user.id, FileScan.org_id == current_user.org_id)
    if status:
        base = base.where(FileScan.status == status)
        count_q = count_q.where(FileScan.status == status)
    rows = await db.execute(base.order_by(FileScan.created_at.desc()).limit(limit).offset(offset))
    total = await db.execute(count_q)
    return {
        "page": page,
        "limit": limit,
        "total": total.scalar_one(),
        "scans": rows.scalars().all(),
    }


@router.get("/scan/file/{file_scan_id}", response_model=FileScanResponse, summary="Get file scan for current user")
async def get_file_scan(
    file_scan_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    row = await db.execute(
        select(FileScan).where(FileScan.id == file_scan_id, FileScan.user_id == current_user.id)
        .where(FileScan.org_id == current_user.org_id)
    )
    file_scan = row.scalar_one_or_none()
    if not file_scan:
        raise HTTPException(status_code=404, detail="File scan not found")
    return file_scan


@router.get("/", summary="List scans for current user")
async def list_scans(
    status: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    offset = (page - 1) * limit
    base = select(Scan).where(Scan.user_id == current_user.id, Scan.org_id == current_user.org_id)
    count_q = select(func.count()).select_from(Scan).where(Scan.user_id == current_user.id, Scan.org_id == current_user.org_id)
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


@router.get("/scan", summary="List scans for current user (alias to GET /)")
async def list_scans_alias(
    status: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("intel:read")),
):
    """Alias endpoint for consistency with POST /scan pattern"""
    offset = (page - 1) * limit
    base = select(Scan).where(Scan.user_id == current_user.id, Scan.org_id == current_user.org_id)
    count_q = select(func.count()).select_from(Scan).where(Scan.user_id == current_user.id, Scan.org_id == current_user.org_id)
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
    current_user: User = Depends(require_permission("intel:write")),
):
    # Create Scan for authenticated user
    scan = Scan(
        org_id=current_user.org_id,
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
    current_user: User = Depends(require_permission("intel:read")),
):
    row = await db.execute(select(Scan).where(Scan.id == scan_id, Scan.user_id == current_user.id, Scan.org_id == current_user.org_id))
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
    current_user: User = Depends(require_permission("intel:write")),
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
        org_id=current_user.org_id,
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
