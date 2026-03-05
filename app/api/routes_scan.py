from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from datetime import datetime

from app.database.session import get_db
from app.database.models import Scan, User
from app.schemas.scan_schema import ScanCreate, ScanResponse
from app.dependencies import get_current_user
from app.tasks.scan_tasks import process_scan


router = APIRouter()


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

    return scan
