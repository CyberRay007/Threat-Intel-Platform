from datetime import datetime, timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, Campaign, Event, IOC, IOCRelationship, MalwareFamily, ThreatActor, User
from app.database.session import get_db
from app.dependencies import get_current_user


router = APIRouter()


@router.get("/dashboard/summary")
async def dashboard_summary(
	db: AsyncSession = Depends(get_db),
	current_user: User = Depends(get_current_user),
):
	now = datetime.utcnow()
	today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
	seven_days_ago = today_start - timedelta(days=6)

	total_events = await db.execute(select(func.count()).select_from(Event))
	alerts_created = await db.execute(select(func.count()).select_from(Alert))
	open_alerts = await db.execute(select(func.count()).select_from(Alert).where(Alert.status == "open"))

	total_events_count = total_events.scalar_one()
	alerts_created_count = alerts_created.scalar_one()
	alert_rate = (alerts_created_count / total_events_count) if total_events_count else 0.0

	events_today = await db.execute(
		select(func.count()).select_from(Event).where(Event.created_at >= today_start)
	)
	alerts_today = await db.execute(
		select(func.count()).select_from(Alert).where(Alert.created_at >= today_start)
	)

	events_series = await db.execute(
		select(func.date(Event.created_at), func.count())
		.where(Event.created_at >= seven_days_ago)
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
		select(Alert.severity, func.count()).group_by(Alert.severity).order_by(Alert.severity)
	)
	alerts_by_severity = [{"severity": s or "unknown", "count": c} for s, c in severity_rows.all()]

	source_rows = await db.execute(
		select(IOC.source, func.count()).group_by(IOC.source).order_by(func.count().desc())
	)
	ioc_feed_distribution = [
		{"source": source or "unknown", "count": count} for source, count in source_rows.all()
	]

	recent_alert_rows = await db.execute(
		select(Alert).order_by(Alert.last_seen_at.desc()).limit(10)
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
	current_user: User = Depends(get_current_user),
):
	now = datetime.utcnow()
	today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

	total_events = await db.execute(select(func.count()).select_from(Event))
	alerts_today = await db.execute(
		select(func.count()).select_from(Alert).where(Alert.created_at >= today_start)
	)
	open_alerts = await db.execute(
		select(func.count()).select_from(Alert).where(Alert.status == "open")
	)

	family_rows = await db.execute(
		select(MalwareFamily.name, func.count(IOCRelationship.id))
		.join(IOCRelationship, IOCRelationship.malware_family_id == MalwareFamily.id)
		.group_by(MalwareFamily.name)
		.order_by(func.count(IOCRelationship.id).desc())
		.limit(10)
	)

	actor_rows = await db.execute(
		select(ThreatActor.name, func.count(IOCRelationship.id))
		.join(IOCRelationship, IOCRelationship.threat_actor_id == ThreatActor.id)
		.group_by(ThreatActor.name)
		.order_by(func.count(IOCRelationship.id).desc())
		.limit(10)
	)

	domain_rows = await db.execute(
		select(IOC.value, func.count(IOC.id))
		.where(IOC.type == "domain")
		.group_by(IOC.value)
		.order_by(func.count(IOC.id).desc())
		.limit(10)
	)

	feed_rows = await db.execute(
		select(IOC.source, func.count()).group_by(IOC.source).order_by(func.count().desc())
	)

	campaign_rows = await db.execute(
		select(Campaign.name, func.count(IOCRelationship.id))
		.join(IOCRelationship, IOCRelationship.campaign_id == Campaign.id)
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
