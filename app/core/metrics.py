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


_feed_windows: dict[str, _FeedWindow] = {}
_last_successful_ingest: dict[str, float] = {}   # source -> epoch
_queue_submitted_at: dict[int, float] = {}        # event_id -> epoch
_lock = Lock()


# ---------------------------------------------------------------------------
# Feed ingestion metrics
# ---------------------------------------------------------------------------

def record_feed_ingest(source: str, *, success: bool) -> None:
    """Call this after every feed ingestion attempt."""
    now = time.time()
    with _lock:
        win = _feed_windows.get(source)
        if win is None or (now - win.window_start) > FEED_FAILURE_WINDOW_SECONDS:
            win = _FeedWindow(window_start=now)
            _feed_windows[source] = win

        if success:
            win.success += 1
            _last_successful_ingest[source] = now
        else:
            win.failure += 1

        total = win.success + win.failure
        failure_rate = win.failure / total if total > 0 else 0.0

        logger.info(
            "feed_ingest_metric",
            extra={"extra_payload": {
                "event": "feed_ingest_metric",
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
                    "source": source,
                    "failure_rate": round(failure_rate, 4),
                    "threshold": FEED_FAILURE_RATE_THRESHOLD,
                    "window_seconds": FEED_FAILURE_WINDOW_SECONDS,
                }},
            )


def check_feed_staleness(source: str) -> None:
    """Call periodically (e.g., from Celery beat health task)."""
    now = time.time()
    with _lock:
        last = _last_successful_ingest.get(source)
    if last is None:
        return
    age = now - last
    if age > FEED_STALE_THRESHOLD_SECONDS:
        logger.critical(
            "ALERT: feed stale — no successful ingest within threshold",
            extra={"extra_payload": {
                "event": "feed_stale_alert",
                "source": source,
                "seconds_since_last_success": round(age),
                "threshold_seconds": FEED_STALE_THRESHOLD_SECONDS,
            }},
        )


def get_feed_metrics() -> dict:
    """Return current in-memory feed metrics snapshot."""
    now = time.time()
    with _lock:
        snapshot = {}
        for source, win in _feed_windows.items():
            total = win.success + win.failure
            snapshot[source] = {
                "window_success": win.success,
                "window_failure": win.failure,
                "failure_rate": round(win.failure / total, 4) if total else 0.0,
                "last_success_ago_seconds": round(now - _last_successful_ingest[source]) if source in _last_successful_ingest else None,
            }
    return snapshot


# ---------------------------------------------------------------------------
# Detection queue lag metrics
# ---------------------------------------------------------------------------

def record_event_queued(event_id: int) -> None:
    """Call when a detection event is enqueued."""
    with _lock:
        _queue_submitted_at[event_id] = time.time()


def record_event_processed(event_id: int) -> None:
    """Call when a detection event finishes processing."""
    now = time.time()
    with _lock:
        submitted = _queue_submitted_at.pop(event_id, None)
    if submitted is None:
        return
    lag = now - submitted
    logger.info(
        "detection_pipeline_metric",
        extra={"extra_payload": {
            "event": "detection_pipeline_metric",
            "event_id": event_id,
            "processing_lag_seconds": round(lag, 2),
        }},
    )
    if lag > PIPELINE_DELAY_THRESHOLD:
        logger.critical(
            "ALERT: detection pipeline delay exceeded threshold",
            extra={"extra_payload": {
                "event": "pipeline_delay_alert",
                "event_id": event_id,
                "lag_seconds": round(lag, 2),
                "threshold_seconds": PIPELINE_DELAY_THRESHOLD,
            }},
        )


def get_queue_lag_snapshot() -> dict:
    """Return oldest pending event age (a proxy for queue lag)."""
    now = time.time()
    with _lock:
        if not _queue_submitted_at:
            return {"pending_events": 0, "oldest_lag_seconds": 0}
        oldest_lag = max(now - t for t in _queue_submitted_at.values())
        pending = len(_queue_submitted_at)

    if oldest_lag > QUEUE_LAG_THRESHOLD_SECONDS:
        logger.critical(
            "ALERT: queue lag exceeded threshold",
            extra={"extra_payload": {
                "event": "queue_lag_alert",
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
