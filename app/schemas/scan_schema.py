from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class ScanCreate(BaseModel):
    target_url: str

class ScanResponse(BaseModel):
    id: int
    target_url: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True