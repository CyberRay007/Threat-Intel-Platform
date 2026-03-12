from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class EventIngestRequest(BaseModel):
    source: str = "api"
    event_type: str = "generic"
    payload: Dict[str, Any] = Field(default_factory=dict)


class AlertResponse(BaseModel):
    id: int
    fingerprint: str
    observable_type: str
    observable_value: str
    severity: str
    title: str
    description: str
    matched_count: int
    status: str
    first_seen_at: datetime
    last_seen_at: datetime
    occurrence_count: int
    created_at: datetime

    class Config:
        from_attributes = True


class EventIngestResponse(BaseModel):
    event_id: int
    source: str
    event_type: str
    status: str
    created_at: datetime
    extracted_observables: Dict[str, List[str]]
    matched_iocs: Dict[str, List[Dict[str, Any]]]
    alerts: List[AlertResponse]


class EventEnqueueResponse(BaseModel):
    event_id: int
    status: str


class AlertListResponse(BaseModel):
    page: int
    total: int
    limit: int
    alerts: List[AlertResponse]


class AlertTriageRequest(BaseModel):
    status: str = Field(..., description="open|in_progress|resolved|false_positive")
    note: Optional[str] = None


class AlertTriageResponse(BaseModel):
    alert_id: int
    status: str
    updated_at: datetime
    note_applied: bool


class AlertInvestigationResponse(BaseModel):
    alert: AlertResponse
    recent_events: List[Dict[str, Any]]
    observables: Dict[str, List[str]]
    ioc_matches: Dict[str, List[Dict[str, Any]]]
    threat_actor_attribution: List[Dict[str, Any]]
