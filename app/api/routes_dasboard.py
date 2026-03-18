from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, Campaign, Event, IOC, IOCRelationship, MalwareFamily, ThreatActor, User
from app.database.session import get_db
from app.dependencies import require_permission
from app.core.metrics import get_feed_metrics, get_queue_lag_snapshot
from app.utils.response import ok


router = APIRouter()


@router.get("/dashboard/summary")
async def dashboard_summary(
	db: AsyncSession = Depends(get_db),
	current_user: User = Depends(require_permission("alerts:read")),
):
	now = datetime.utcnow()
	today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
	seven_days_ago = today_start - timedelta(days=6)

	total_events = await db.execute(select(func.count()).select_from(Event).where(Event.org_id == current_user.org_id))
	alerts_created = await db.execute(select(func.count()).select_from(Alert).where(Alert.org_id == current_user.org_id))
	open_alerts = await db.execute(select(func.count()).select_from(Alert).where(Alert.status == "open", Alert.org_id == current_user.org_id))

	total_events_count = total_events.scalar_one()
	alerts_created_count = alerts_created.scalar_one()
	alert_rate = (alerts_created_count / total_events_count) if total_events_count else 0.0

	events_today = await db.execute(
		select(func.count()).select_from(Event).where(Event.created_at >= today_start, Event.org_id == current_user.org_id)
	)
	alerts_today = await db.execute(
		select(func.count()).select_from(Alert).where(Alert.created_at >= today_start, Alert.org_id == current_user.org_id)
	)

	events_series = await db.execute(
		select(func.date(Event.created_at), func.count())
		.where(Event.created_at >= seven_days_ago, Event.org_id == current_user.org_id)
		.group_by(func.date(Event.created_at))
		.order_by(func.date(Event.created_at))
	)
	event_map = {str(day): count for day, count in events_series.all()}
	events_over_time = []
	for i in range(7):
		d = seven_days_ago + timedelta(days=i)
		key = str(d.date())
		events_over_time.append({"date": key, "events": event_map.get(key, 0)})

	severity_rows = await db.execute(
		select(Alert.severity, func.count()).where(Alert.org_id == current_user.org_id).group_by(Alert.severity).order_by(Alert.severity)
	)
	alerts_by_severity = [{"severity": s or "unknown", "count": c} for s, c in severity_rows.all()]

	source_rows = await db.execute(
		select(IOC.source, func.count()).where(IOC.org_id == current_user.org_id).group_by(IOC.source).order_by(func.count().desc())
	)
	ioc_feed_distribution = [
		{"source": source or "unknown", "count": count} for source, count in source_rows.all()
	]

	recent_alert_rows = await db.execute(
		select(Alert).where(Alert.org_id == current_user.org_id).order_by(Alert.last_seen_at.desc()).limit(10)
	)
	recent_alerts = [
		{
			"id": alert.id,
			"observable": f"{alert.observable_type}:{alert.observable_value}",
			"observable_type": alert.observable_type,
			"observable_value": alert.observable_value,
			"severity": alert.severity,
			"status": alert.status,
			"occurrences": alert.occurrence_count,
			"first_seen": alert.first_seen_at,
			"last_seen": alert.last_seen_at,
		}
		for alert in recent_alert_rows.scalars().all()
	]

	return {
		"metrics": {
			"total_events_processed_today": events_today.scalar_one(),
			"alerts_generated_today": alerts_today.scalar_one(),
			"open_alerts": open_alerts.scalar_one(),
			"alert_rate": round(alert_rate, 6),
		},
		"events_over_time": events_over_time,
		"alerts_by_severity": alerts_by_severity,
		"ioc_feed_distribution": ioc_feed_distribution,
		"recent_alerts": recent_alerts,
	}


@router.get("/dashboard/security-overview")
async def security_overview(
	db: AsyncSession = Depends(get_db),
	current_user: User = Depends(require_permission("alerts:read")),
):
	now = datetime.utcnow()
	today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

	total_events = await db.execute(select(func.count()).select_from(Event).where(Event.org_id == current_user.org_id))
	alerts_today = await db.execute(
		select(func.count()).select_from(Alert).where(Alert.created_at >= today_start, Alert.org_id == current_user.org_id)
	)
	open_alerts = await db.execute(
		select(func.count()).select_from(Alert).where(Alert.status == "open", Alert.org_id == current_user.org_id)
	)

	family_rows = await db.execute(
		select(MalwareFamily.name, func.count(IOCRelationship.id))
		.join(IOCRelationship, IOCRelationship.malware_family_id == MalwareFamily.id)
		.where(MalwareFamily.org_id == current_user.org_id, IOCRelationship.org_id == current_user.org_id)
		.group_by(MalwareFamily.name)
		.order_by(func.count(IOCRelationship.id).desc())
		.limit(10)
	)

	actor_rows = await db.execute(
		select(ThreatActor.name, func.count(IOCRelationship.id))
		.join(IOCRelationship, IOCRelationship.threat_actor_id == ThreatActor.id)
		.where(ThreatActor.org_id == current_user.org_id, IOCRelationship.org_id == current_user.org_id)
		.group_by(ThreatActor.name)
		.order_by(func.count(IOCRelationship.id).desc())
		.limit(10)
	)

	domain_rows = await db.execute(
		select(IOC.value, func.count(IOC.id))
		.where(IOC.type == "domain", IOC.org_id == current_user.org_id)
		.group_by(IOC.value)
		.order_by(func.count(IOC.id).desc())
		.limit(10)
	)

	feed_rows = await db.execute(
		select(IOC.source, func.count()).where(IOC.org_id == current_user.org_id).group_by(IOC.source).order_by(func.count().desc())
	)

	campaign_rows = await db.execute(
		select(Campaign.name, func.count(IOCRelationship.id))
		.join(IOCRelationship, IOCRelationship.campaign_id == Campaign.id)
		.where(Campaign.org_id == current_user.org_id, IOCRelationship.org_id == current_user.org_id)
		.group_by(Campaign.name)
		.order_by(func.count(IOCRelationship.id).desc())
		.limit(10)
	)

	return {
		"total_events": total_events.scalar_one(),
		"alerts_today": alerts_today.scalar_one(),
		"open_alerts": open_alerts.scalar_one(),
		"top_malware_families": [
			{"name": name, "count": count}
			for name, count in family_rows.all()
		],
		"top_threat_actors": [
			{"name": name, "count": count}
			for name, count in actor_rows.all()
		],
		"top_domains_detected": [
			{"domain": domain, "count": count}
			for domain, count in domain_rows.all()
		],
		"top_campaigns": [
			{"name": name, "count": count}
			for name, count in campaign_rows.all()
		],
		"ioc_feed_distribution": [
			{"source": source or "unknown", "count": count}
			for source, count in feed_rows.all()
		],
	}


@router.get("/dashboard/metrics")
async def pipeline_metrics(
	current_user: User = Depends(require_permission("admin:all")),
):
	"""
	Live pipeline health snapshot.

	Returns feed ingestion success/failure rates and detection queue lag.
	Every field that breaches a hard threshold is flagged in the response.
	"""
	return ok({
		"feed_metrics": get_feed_metrics(str(current_user.org_id)),
		"queue_lag": get_queue_lag_snapshot(str(current_user.org_id)),
	})
