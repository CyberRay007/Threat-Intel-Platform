from datetime import datetime
from collections import defaultdict
import asyncio

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, AlertHistory, Event, IOC, ThreatActor, User
from app.database.session import get_db
from app.dependencies import require_permission
from app.schemas.detection_schema import (
    AlertInvestigationResponse,
    AlertListResponse,
    AlertTriageRequest,
    AlertTriageResponse,
    EventEnqueueResponse,
    EventIngestRequest,
)
from app.services.intel_enrichment import attribute_observable
from app.tasks.celery_worker import celery_app


router = APIRouter()
VALID_TRIAGE_STATUS = {"open", "in_progress", "resolved", "false_positive"}


@router.post("/detection/events", response_model=EventEnqueueResponse)
async def ingest_event(
    request: EventIngestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("alerts:write")),
):
    event = Event(
        org_id=current_user.org_id,
        user_id=current_user.id,
        source=request.source,
        domain=request.payload.get("domain"),
        url=request.payload.get("url"),
        ip=request.payload.get("ip"),
        file_hash=request.payload.get("file_hash"),
        raw_event=request.payload,
        event_type=request.event_type,
        status="queued",
    )
    db.add(event)
    await db.commit()
    await db.refresh(event)

    try:
        await asyncio.wait_for(
            asyncio.to_thread(
                celery_app.send_task,
                "app.tasks.celery_worker.process_detection_event_task",
                args=[event.id],
            ),
            timeout=3,
        )
    except Exception as exc:
        event.status = "queue_failed"
        await db.commit()
        raise HTTPException(
            status_code=503,
            detail={
                "message": "event stored but failed to enqueue detection task",
                "event_id": event.id,
                "enqueue_error": str(exc),
            },
        )

    return EventEnqueueResponse(
        event_id=event.id,
        status="queued",
    )


@router.get("/detection/alerts", response_model=AlertListResponse)
async def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    observable_type: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    page: int = 1,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("alerts:read")),
):
    limit = max(1, min(limit, 200))
    page = max(1, page)
    offset = (page - 1) * limit

    base_query = select(Alert).where(Alert.org_id == current_user.org_id)
    count_query = select(func.count()).select_from(Alert).where(Alert.org_id == current_user.org_id)

    if status:
        base_query = base_query.where(Alert.status == status)
        count_query = count_query.where(Alert.status == status)
    if severity:
        base_query = base_query.where(Alert.severity == severity)
        count_query = count_query.where(Alert.severity == severity)
    if observable_type:
        base_query = base_query.where(Alert.observable_type == observable_type)
        count_query = count_query.where(Alert.observable_type == observable_type)
    if start_date:
        base_query = base_query.where(Alert.created_at >= start_date)
        count_query = count_query.where(Alert.created_at >= start_date)
    if end_date:
        base_query = base_query.where(Alert.created_at <= end_date)
        count_query = count_query.where(Alert.created_at <= end_date)

    rows = await db.execute(
        base_query.order_by(Alert.last_seen_at.desc()).limit(limit).offset(offset)
    )
    total = await db.execute(count_query)

    return AlertListResponse(
        total=total.scalar_one(),
        page=page,
        limit=limit,
        alerts=rows.scalars().all(),
    )


@router.get("/detection/alerts/{alert_id}/investigation", response_model=AlertInvestigationResponse)
@router.get("/detection/alerts/{alert_id}/investigate", response_model=AlertInvestigationResponse)
async def investigate_alert(
    alert_id: int,
    events_limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("alerts:read")),
):
    alert_row = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.org_id == current_user.org_id))
    alert = alert_row.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")

    events_limit = max(1, min(events_limit, 200))
    events_row = await db.execute(
        select(Event)
        .where(Event.alert_id == alert_id, Event.org_id == current_user.org_id)
        .order_by(Event.created_at.desc())
        .limit(events_limit)
    )
    events = events_row.scalars().all()

    observables = {
        "domain": sorted({e.domain for e in events if e.domain}),
        "url": sorted({e.url for e in events if e.url}),
        "ip": sorted({e.ip for e in events if e.ip}),
        "file_hash": sorted({e.file_hash for e in events if e.file_hash}),
    }

    ioc_matches: dict[str, list[dict]] = {"domain": [], "url": [], "ip": [], "file_hash": []}
    type_filters = {
        "domain": ["domain"],
        "url": ["url"],
        "ip": ["ip"],
        "file_hash": ["file_hash", "hash"],
    }
    for ioc_type, values in observables.items():
        if not values:
            continue
        rows = await db.execute(
            select(IOC).where(IOC.type.in_(type_filters[ioc_type]), IOC.value.in_(values))
            .where(IOC.org_id == current_user.org_id)
        )
        ioc_matches[ioc_type] = [
            {
                "ioc_id": m.id,
                "type": "file_hash" if m.type == "hash" else m.type,
                "value": m.value,
                "source": m.source,
                "threat_actor_id": m.threat_actor_id,
            }
            for m in rows.scalars().all()
        ]

    actor_conf = defaultdict(int)
    actor_evidence = defaultdict(set)
    observed_pairs = []
    for ioc_type in ["domain", "url", "ip", "file_hash"]:
        for value in observables[ioc_type][:5]:
            observed_pairs.append((ioc_type, value))

    for ioc_type, value in observed_pairs[:20]:
        attributed = await attribute_observable(db, ioc_type=ioc_type, value=value, org_id=current_user.org_id)
        for actor in attributed.get("actors", []):
            actor_id = actor["id"]
            actor_conf[actor_id] = max(actor_conf[actor_id], actor.get("confidence", 0))
            actor_evidence[actor_id].update(actor.get("evidence", []))

    actor_rows = []
    if actor_conf:
        actors_result = await db.execute(
            select(ThreatActor).where(ThreatActor.id.in_(list(actor_conf.keys())))
        )
        for actor in actors_result.scalars().all():
            if actor is None:
                continue
            actor_rows.append(
                {
                    "id": actor.id,
                    "name": actor.name,
                    "origin": actor.origin,
                    "confidence": actor_conf.get(actor.id, 0),
                    "evidence": sorted(actor_evidence.get(actor.id, set())),
                }
            )

    actor_rows.sort(key=lambda x: x.get("confidence", 0), reverse=True)

    recent_events = [
        {
            "event_id": e.id,
            "event_type": e.event_type,
            "status": e.status,
            "source": e.source,
            "domain": e.domain,
            "url": e.url,
            "ip": e.ip,
            "file_hash": e.file_hash,
            "created_at": e.created_at,
        }
        for e in events
    ]

    return AlertInvestigationResponse(
        alert=alert,
        recent_events=recent_events,
        observables=observables,
        ioc_matches=ioc_matches,
        threat_actor_attribution=actor_rows,
    )


@router.get("/detection/events")
async def list_events(
    status: str | None = None,
    event_type: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    page: int = 1,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("alerts:read")),
):
    limit = max(1, min(limit, 500))
    page = max(1, page)
    offset = (page - 1) * limit

    base = select(Event).where(Event.org_id == current_user.org_id)
    count_q = select(func.count()).select_from(Event).where(Event.org_id == current_user.org_id)

    if status:
        base = base.where(Event.status == status)
        count_q = count_q.where(Event.status == status)
    if event_type:
        base = base.where(Event.event_type == event_type)
        count_q = count_q.where(Event.event_type == event_type)
    if start_date:
        base = base.where(Event.created_at >= start_date)
        count_q = count_q.where(Event.created_at >= start_date)
    if end_date:
        base = base.where(Event.created_at <= end_date)
        count_q = count_q.where(Event.created_at <= end_date)

    rows = await db.execute(base.order_by(Event.created_at.desc()).limit(limit).offset(offset))
    total = await db.execute(count_q)

    items = [
        {
            "id": e.id,
            "timestamp": e.created_at,
            "source": e.source,
            "event_type": e.event_type,
            "status": e.status,
            "observable": e.domain or e.url or e.ip or e.file_hash,
            "detection_result": "alerted" if e.alert_id else "clean",
            "alert_id": e.alert_id,
        }
        for e in rows.scalars().all()
    ]

    return {
        "page": page,
        "limit": limit,
        "total": total.scalar_one(),
        "events": items,
    }


@router.post("/detection/alerts/{alert_id}/triage", response_model=AlertTriageResponse)
async def triage_alert(
    alert_id: int,
    request: AlertTriageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("alerts:write")),
):
    new_status = request.status.strip().lower()
    if new_status not in VALID_TRIAGE_STATUS:
        raise HTTPException(
            status_code=400,
            detail={
                "message": "invalid triage status",
                "supported": sorted(VALID_TRIAGE_STATUS),
            },
        )

    row = await db.execute(select(Alert).where(Alert.id == alert_id, Alert.org_id == current_user.org_id))
    alert = row.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")

    alert.status = new_status
    note_applied = False
    if request.note and request.note.strip():
        note_applied = True
        ts = datetime.utcnow().isoformat()
        note_line = f"[{ts}] triage by {current_user.email}: {request.note.strip()}"
        alert.description = f"{(alert.description or '').rstrip()}\n{note_line}".strip()

    alert.last_seen_at = datetime.utcnow()
    db.add(
        AlertHistory(
            org_id=current_user.org_id,
            alert_id=alert.id,
            action="triage_update",
            performed_by=current_user.id,
            details={"status": new_status, "note": request.note or ""},
        )
    )
    await db.commit()

    return AlertTriageResponse(
        alert_id=alert.id,
        status=alert.status,
        updated_at=alert.last_seen_at,
        note_applied=note_applied,
    )


@router.get("/detection/triage/queue", response_model=AlertListResponse)
async def triage_queue(
    status: str = "open",
    page: int = 1,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("alerts:read")),
):
    limit = max(1, min(limit, 200))
    page = max(1, page)
    offset = (page - 1) * limit

    sev_rank = case(
        (Alert.severity == "critical", 4),
        (Alert.severity == "high", 3),
        (Alert.severity == "medium", 2),
        else_=1,
    )

    rows = await db.execute(
        select(Alert)
        .where(Alert.status == status, Alert.org_id == current_user.org_id)
        .order_by(sev_rank.desc(), Alert.last_seen_at.desc())
        .limit(limit)
        .offset(offset)
    )
    total = await db.execute(select(func.count()).select_from(Alert).where(Alert.status == status, Alert.org_id == current_user.org_id))

    return AlertListResponse(
        page=page,
        total=total.scalar_one(),
        limit=limit,
        alerts=rows.scalars().all(),
    )


@router.get("/detection/events/stats")
async def event_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("alerts:read")),
):
    total = await db.execute(select(func.count()).select_from(Event).where(Event.org_id == current_user.org_id))
    alerts_created = await db.execute(select(func.count()).select_from(Alert).where(Alert.org_id == current_user.org_id))
    open_alerts = await db.execute(select(func.count()).select_from(Alert).where(Alert.status == "open", Alert.org_id == current_user.org_id))

    total_events = total.scalar_one()
    alerts_created_count = alerts_created.scalar_one()
    alert_rate = (alerts_created_count / total_events) if total_events else 0.0

    return {
        "total_events": total_events,
        "alerts_created": alerts_created_count,
        "open_alerts": open_alerts.scalar_one(),
        "alert_rate": round(alert_rate, 6),
    }


@router.post("/detection/events/replay")
async def replay_event_backlog(
    limit: int = 200,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("alerts:write")),
):
    rows = await db.execute(
        select(Event.id)
        .where(Event.status.in_(["queued", "queue_failed"]), Event.org_id == current_user.org_id)
        .order_by(Event.created_at.asc())
        .limit(limit)
    )
    event_ids = [r[0] for r in rows.all()]

    enqueued = 0
    failed = 0
    errors: list[str] = []
    for event_id in event_ids:
        try:
            await asyncio.wait_for(
                asyncio.to_thread(
                    celery_app.send_task,
                    "app.tasks.celery_worker.process_detection_event_task",
                    args=[event_id],
                ),
                timeout=3,
            )
            enqueued += 1
        except Exception as exc:
            failed += 1
            errors.append(f"event_id={event_id}: enqueue_error={exc}")

    return {
        "picked": len(event_ids),
        "enqueued": enqueued,
        "failed": failed,
        "errors": errors[:10],
    }
