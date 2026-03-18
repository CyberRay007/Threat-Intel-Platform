import os

from celery import Celery
from dotenv import load_dotenv

load_dotenv()

CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", CELERY_BROKER_URL)

celery_app = Celery(
	"threat_intel_platform",
	broker=CELERY_BROKER_URL,
	backend=CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
	timezone="UTC",
	enable_utc=True,
	task_serializer="json",
	result_serializer="json",
	accept_content=["json"],
	beat_schedule={
		# Pull phishing feeds every hour.
		"ingest-openphish-hourly": {
			"task": "app.tasks.celery_worker.ingest_single_feed_task",
			"schedule": 3600.0,
			"args": ("openphish",),
		},
		# Pull broader feeds every 6 hours.
		"ingest-all-feeds-6h": {
			"task": "app.tasks.celery_worker.ingest_all_feeds_task",
			"schedule": 21600.0,
		},
		# Replay queued/failed detection events every 5 minutes.
		"replay-detection-backlog-5m": {
			"task": "app.tasks.celery_worker.process_detection_backlog_task",
			"schedule": 300.0,
			"args": (200,),
		},
		# Check every feed for staleness every 15 minutes.
		"check-feed-staleness-15m": {
			"task": "app.tasks.celery_worker.check_feed_staleness_task",
			"schedule": 900.0,
		},
	},
)


@celery_app.task(name="app.tasks.celery_worker.ingest_all_feeds_task")
def ingest_all_feeds_task(limit_per_source=None):
	from app.tasks.intel_tasks import ingest_all_feeds

	return ingest_all_feeds(limit_per_source=limit_per_source)


@celery_app.task(name="app.tasks.celery_worker.ingest_single_feed_task")
def ingest_single_feed_task(source: str, limit=None):
	from app.tasks.intel_tasks import ingest_single_feed

	return ingest_single_feed(source=source, limit=limit)


@celery_app.task(name="app.tasks.celery_worker.process_detection_event_task")
def process_detection_event_task(event_id: int):
	from app.tasks.detection_tasks import process_event_task

	return process_event_task(event_id=event_id)


@celery_app.task(name="app.tasks.celery_worker.process_detection_backlog_task")
def process_detection_backlog_task(limit: int = 100):
	from app.tasks.detection_tasks import process_detection_backlog_task as run_backlog

	return run_backlog(limit=limit)


@celery_app.task(name="app.tasks.celery_worker.check_feed_staleness_task")
def check_feed_staleness_task():
	from app.tasks.intel_tasks import check_feed_staleness_all

	check_feed_staleness_all()
