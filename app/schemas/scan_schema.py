from pydantic import BaseModel
from typing import Any, Dict, Optional
from datetime import datetime


class ScanCreate(BaseModel):
    target_url: str


class ScanResultResponse(BaseModel):
    structural_score: int = 0
    vt_score: int = 0
    ioc_score: int = 0
    feed_intel_score: int = 0
    historical_score: int = 0
    risk_score: int = 0
    risk_level: str = "low"
    signals: Optional[Dict[str, Any]] = None
    vt_response: Optional[Dict[str, Any]] = None
    summary: Optional[str] = ""

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: str
    structural_score: int = 0
    vt_score: int = 0
    feed_intel_score: int = 0
    historical_score: int = 0
    risk_score: int = 0
    created_at: datetime
    completed_at: Optional[datetime] = None
    result: Optional[ScanResultResponse] = None

    class Config:
        from_attributes = True

class FileScanCreate(BaseModel):
    pass  # File will be uploaded via multipart

class FileScanResponse(BaseModel):
    id: int
    filename: str
    sha256: str
    status: str
    risk_score: int
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True