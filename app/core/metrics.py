"""
Observability: metrics collection and hard-threshold alerting.

Tracks:
  - Feed ingestion success/failure rates
  - Detection queue lag
  - Alert generation rate
  - Pipeline delays

Hard triggers (production non-negotiable):
  - Feed failure rate > 10 % in any 5-minute window  → log CRITICAL
  - Queue lag > 120 seconds                          → log CRITICAL
  - No successful feed ingest for > 90 minutes       → log CRITICAL
  - Detection pipeline delay > 60 seconds            → log CRITICAL

Metrics are exposed in-process and can be scraped by Prometheus or
forwarded to any OTLP-compatible backend.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional

from app.core.logging import logger

# ---------------------------------------------------------------------------
# Thresholds (change via environment in production)
# ---------------------------------------------------------------------------

import os

FEED_FAILURE_RATE_THRESHOLD = float(os.getenv("METRIC_FEED_FAILURE_RATE", "0.10"))  # 10 %
FEED_FAILURE_WINDOW_SECONDS = int(os.getenv("METRIC_FEED_FAILURE_WINDOW", "300"))   # 5 min
FEED_STALE_THRESHOLD_SECONDS = int(os.getenv("METRIC_FEED_STALE_SECONDS", "5400"))  # 90 min
QUEUE_LAG_THRESHOLD_SECONDS  = int(os.getenv("METRIC_QUEUE_LAG_SECONDS", "120"))    # 2 min
PIPELINE_DELAY_THRESHOLD     = int(os.getenv("METRIC_PIPELINE_DELAY_SECONDS", "60")) # 60 sec


# ---------------------------------------------------------------------------
# Internal counters (in-process; replace with Redis for multi-worker deploy)
# ---------------------------------------------------------------------------

@dataclass
class _FeedWindow:
    window_start: float = field(default_factory=time.time)
    success: int = 0
    failure: int = 0


_feed_windows: dict[tuple[str, str], _FeedWindow] = {}
_last_successful_ingest: dict[tuple[str, str], float] = {}   # (org_id, source) -> epoch
_queue_submitted_at: dict[int, tuple[float, str]] = {}       # event_id -> (epoch, org_id)
_lock = Lock()


# ---------------------------------------------------------------------------
# Feed ingestion metrics
# ---------------------------------------------------------------------------

def record_feed_ingest(org_id: str, source: str, *, success: bool) -> None:
    """Call this after every feed ingestion attempt."""
    now = time.time()
    with _lock:
        key = (org_id, source)
        win = _feed_windows.get(key)
        if win is None or (now - win.window_start) > FEED_FAILURE_WINDOW_SECONDS:
            win = _FeedWindow(window_start=now)
            _feed_windows[key] = win

        if success:
            win.success += 1
            _last_successful_ingest[key] = now
        else:
            win.failure += 1

        total = win.success + win.failure
        failure_rate = win.failure / total if total > 0 else 0.0

        logger.info(
            "feed_ingest_metric",
            extra={"extra_payload": {
                "event": "feed_ingest_metric",
                "org_id": org_id,
                "source": source,
                "success": success,
                "window_failure_rate": round(failure_rate, 4),
                "window_success": win.success,
                "window_failure": win.failure,
            }},
        )

        if failure_rate > FEED_FAILURE_RATE_THRESHOLD and total >= 5:
            logger.critical(
                "ALERT: feed failure rate exceeded threshold",
                extra={"extra_payload": {
                    "event": "feed_failure_rate_alert",
                    "org_id": org_id,
                    "source": source,
                    "failure_rate": round(failure_rate, 4),
                    "threshold": FEED_FAILURE_RATE_THRESHOLD,
                    "window_seconds": FEED_FAILURE_WINDOW_SECONDS,
                }},
            )


def check_feed_staleness(org_id: str, source: str) -> None:
    """Call periodically (e.g., from Celery beat health task)."""
    now = time.time()
    with _lock:
        last = _last_successful_ingest.get((org_id, source))
    if last is None:
        return
    age = now - last
    if age > FEED_STALE_THRESHOLD_SECONDS:
        logger.critical(
            "ALERT: feed stale — no successful ingest within threshold",
            extra={"extra_payload": {
                "event": "feed_stale_alert",
                "org_id": org_id,
                "source": source,
                "seconds_since_last_success": round(age),
                "threshold_seconds": FEED_STALE_THRESHOLD_SECONDS,
            }},
        )


def get_feed_metrics(org_id: str) -> dict:
    """Return current in-memory feed metrics snapshot."""
    now = time.time()
    with _lock:
        snapshot = {}
        for (metric_org_id, source), win in _feed_windows.items():
            if str(metric_org_id) != str(org_id):
                continue
            total = win.success + win.failure
            key = (metric_org_id, source)
            snapshot[source] = {
                "window_success": win.success,
                "window_failure": win.failure,
                "failure_rate": round(win.failure / total, 4) if total else 0.0,
                "last_success_ago_seconds": round(now - _last_successful_ingest[key]) if key in _last_successful_ingest else None,
            }
    return snapshot


# ---------------------------------------------------------------------------
# Detection queue lag metrics
# ---------------------------------------------------------------------------

def record_event_queued(event_id: int, org_id: str) -> None:
    """Call when a detection event is enqueued."""
    with _lock:
        _queue_submitted_at[event_id] = (time.time(), org_id)


def record_event_processed(event_id: int) -> None:
    """Call when a detection event finishes processing."""
    now = time.time()
    with _lock:
        entry = _queue_submitted_at.pop(event_id, None)
    if entry is None:
        return
    submitted, org_id = entry
    lag = now - submitted
    logger.info(
        "detection_pipeline_metric",
        extra={"extra_payload": {
            "event": "detection_pipeline_metric",
            "event_id": event_id,
            "org_id": org_id,
            "processing_lag_seconds": round(lag, 2),
        }},
    )
    if lag > PIPELINE_DELAY_THRESHOLD:
        logger.critical(
            "ALERT: detection pipeline delay exceeded threshold",
            extra={"extra_payload": {
                "event": "pipeline_delay_alert",
                "event_id": event_id,
                "org_id": org_id,
                "lag_seconds": round(lag, 2),
                "threshold_seconds": PIPELINE_DELAY_THRESHOLD,
            }},
        )


def get_queue_lag_snapshot(org_id: str) -> dict:
    """Return oldest pending event age (a proxy for queue lag)."""
    now = time.time()
    with _lock:
        org_entries = [
            (event_id, submitted_at)
            for event_id, (submitted_at, metric_org_id) in _queue_submitted_at.items()
            if str(metric_org_id) == str(org_id)
        ]
        if not org_entries:
            return {"pending_events": 0, "oldest_lag_seconds": 0}
        oldest_lag = max(now - submitted for _, submitted in org_entries)
        pending = len(org_entries)

    if oldest_lag > QUEUE_LAG_THRESHOLD_SECONDS:
        logger.critical(
            "ALERT: queue lag exceeded threshold",
            extra={"extra_payload": {
                "event": "queue_lag_alert",
                "org_id": org_id,
                "oldest_lag_seconds": round(oldest_lag, 2),
                "threshold_seconds": QUEUE_LAG_THRESHOLD_SECONDS,
                "pending_events": pending,
            }},
        )

    return {
        "pending_events": pending,
        "oldest_lag_seconds": round(oldest_lag, 2),
        "threshold_seconds": QUEUE_LAG_THRESHOLD_SECONDS,
        "breach": oldest_lag > QUEUE_LAG_THRESHOLD_SECONDS,
    }
