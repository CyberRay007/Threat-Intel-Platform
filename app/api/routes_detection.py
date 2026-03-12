from datetime import datetime
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, Event, IOC, ThreatActor, User
from app.database.session import get_db
from app.dependencies import get_current_user
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
    current_user: User = Depends(get_current_user),
):
    event = Event(
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
        task = celery_app.send_task(
            "app.tasks.celery_worker.process_detection_event_task",
            args=[event.id],
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
    current_user: User = Depends(get_current_user),
):
    limit = max(1, min(limit, 200))
    page = max(1, page)
    offset = (page - 1) * limit

    base_query = select(Alert)
    count_query = select(func.count()).select_from(Alert)

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
async def investigate_alert(
    alert_id: int,
    events_limit: int = 50,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    alert_row = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = alert_row.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")

    events_limit = max(1, min(events_limit, 200))
    events_row = await db.execute(
        select(Event)
        .where(Event.alert_id == alert_id)
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
        attributed = await attribute_observable(db, ioc_type=ioc_type, value=value)
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


@router.post("/detection/alerts/{alert_id}/triage", response_model=AlertTriageResponse)
async def triage_alert(
    alert_id: int,
    request: AlertTriageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
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

    row = await db.execute(select(Alert).where(Alert.id == alert_id))
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
    current_user: User = Depends(get_current_user),
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
        .where(Alert.status == status)
        .order_by(sev_rank.desc(), Alert.last_seen_at.desc())
        .limit(limit)
        .offset(offset)
    )
    total = await db.execute(select(func.count()).select_from(Alert).where(Alert.status == status))

    return AlertListResponse(
        page=page,
        total=total.scalar_one(),
        limit=limit,
        alerts=rows.scalars().all(),
    )


@router.get("/detection/events/stats")
async def event_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = await db.execute(select(func.count()).select_from(Event))
    alerts_created = await db.execute(select(func.count()).select_from(Alert))
    open_alerts = await db.execute(select(func.count()).select_from(Alert).where(Alert.status == "open"))

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
    current_user: User = Depends(get_current_user),
):
    rows = await db.execute(
        select(Event.id)
        .where(Event.status.in_(["queued", "queue_failed"]))
        .order_by(Event.created_at.asc())
        .limit(limit)
    )
    event_ids = [r[0] for r in rows.all()]

    enqueued = 0
    failed = 0
    errors: list[str] = []
    for event_id in event_ids:
        try:
            celery_app.send_task(
                "app.tasks.celery_worker.process_detection_event_task",
                args=[event_id],
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
