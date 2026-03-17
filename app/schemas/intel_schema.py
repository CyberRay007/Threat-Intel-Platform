from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


VALID_IOC_TYPES = {"ip", "domain", "url", "hash", "file_hash", "email", "cve"}


class IOCCreate(BaseModel):
    type: str = Field(..., description="ip | domain | url | hash | file_hash | email | cve")
    value: str = Field(..., min_length=1)
    threat_actor_id: Optional[int] = None
    source: Optional[str] = None


class IOCUpdate(BaseModel):
    threat_actor_id: Optional[int] = None
    source: Optional[str] = None


class IOCResponse(BaseModel):
    id: int
    type: str
    value: str
    threat_actor_id: Optional[int] = None
    source: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    confidence: Optional[float] = None
    source_reliability: Optional[float] = None

    class Config:
        from_attributes = True


class ThreatActorCreate(BaseModel):
    name: str = Field(..., min_length=1)
    description: Optional[str] = None
    origin: Optional[str] = None
    aliases: Optional[List[str]] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class ThreatActorUpdate(BaseModel):
    description: Optional[str] = None
    origin: Optional[str] = None
    aliases: Optional[List[str]] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


class ThreatActorResponse(BaseModel):
    id: int
    name: str
    description: Optional[str] = None
    origin: Optional[str] = None
    aliases: Optional[List[str]] = []
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True
