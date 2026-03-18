"""
Splunk integration adapter stub.

Sends IOCs and alerts to a Splunk HTTP Event Collector (HEC) endpoint.
Config is loaded from environment variables.
"""

from __future__ import annotations

import json
import os
from typing import Any

import requests

from app.services.integrations.base import IntegrationAdapter, PushResult
from app.core.logging import logger

SPLUNK_HEC_URL   = os.getenv("SPLUNK_HEC_URL", "")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN", "")
SPLUNK_TIMEOUT   = int(os.getenv("SPLUNK_TIMEOUT", "5"))


class SplunkAdapter(IntegrationAdapter):
    name = "splunk"

    def __init__(self, hec_url: str = SPLUNK_HEC_URL, hec_token: str = SPLUNK_HEC_TOKEN):
        self.hec_url = hec_url.rstrip("/")
        self.headers = {"Authorization": f"Splunk {hec_token}", "Content-Type": "application/json"}

    def health_check(self) -> bool:
        if not self.hec_url:
            return False
        try:
            resp = requests.get(f"{self.hec_url}/services/collector/health", headers=self.headers, timeout=SPLUNK_TIMEOUT)
            return resp.status_code == 200
        except Exception as exc:
            logger.warning("splunk_health_check_failed", extra={"extra_payload": {"error": str(exc)}})
            return False

    def _post_events(self, events: list[dict]) -> PushResult:
        if not self.hec_url:
            return PushResult(success=False, error="SPLUNK_HEC_URL not configured")
        payload = "\n".join(json.dumps({"event": e, "sourcetype": "threat_intel_platform"}) for e in events)
        try:
            resp = requests.post(
                f"{self.hec_url}/services/collector/event",
                data=payload,
                headers=self.headers,
                timeout=SPLUNK_TIMEOUT,
            )
            if resp.status_code in (200, 201):
                return PushResult(success=True, pushed=len(events), raw_response=resp.json())
            return PushResult(success=False, failed=len(events), error=resp.text[:300])
        except Exception as exc:
            logger.warning("splunk_push_failed", extra={"extra_payload": {"error": str(exc)}})
            return PushResult(success=False, failed=len(events), error=str(exc))

    def push_iocs(self, iocs: list[dict]) -> PushResult:
        events = [{"type": "ioc", **i} for i in iocs]
        return self._post_events(events)

    def push_alerts(self, alerts: list[dict]) -> PushResult:
        events = [{"type": "alert", **a} for a in alerts]
        return self._post_events(events)
