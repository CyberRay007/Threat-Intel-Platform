"""
Elastic integration adapter stub.

Sends IOCs and alerts to an Elasticsearch index via the Bulk API.
Config is loaded from environment variables.
"""

from __future__ import annotations

import json
import os

import requests

from app.services.integrations.base import IntegrationAdapter, PushResult
from app.core.logging import logger

ELASTIC_URL      = os.getenv("ELASTIC_URL", "")
ELASTIC_API_KEY  = os.getenv("ELASTIC_API_KEY", "")
ELASTIC_IOC_IDX  = os.getenv("ELASTIC_IOC_INDEX", "tip-iocs")
ELASTIC_ALERT_IDX = os.getenv("ELASTIC_ALERT_INDEX", "tip-alerts")
ELASTIC_TIMEOUT  = int(os.getenv("ELASTIC_TIMEOUT", "5"))


class ElasticAdapter(IntegrationAdapter):
    name = "elastic"

    def __init__(
        self,
        url: str = ELASTIC_URL,
        api_key: str = ELASTIC_API_KEY,
        ioc_index: str = ELASTIC_IOC_IDX,
        alert_index: str = ELASTIC_ALERT_IDX,
    ):
        self.url = url.rstrip("/")
        self.headers = {
            "Authorization": f"ApiKey {api_key}",
            "Content-Type": "application/json",
        }
        self.ioc_index = ioc_index
        self.alert_index = alert_index

    def health_check(self) -> bool:
        if not self.url:
            return False
        try:
            resp = requests.get(f"{self.url}/_cluster/health", headers=self.headers, timeout=ELASTIC_TIMEOUT)
            return resp.status_code == 200
        except Exception as exc:
            logger.warning("elastic_health_check_failed", extra={"extra_payload": {"error": str(exc)}})
            return False

    def _bulk(self, index: str, docs: list[dict]) -> PushResult:
        if not self.url:
            return PushResult(success=False, error="ELASTIC_URL not configured")
        lines = []
        for doc in docs:
            lines.append(json.dumps({"index": {"_index": index}}))
            lines.append(json.dumps(doc))
        payload = "\n".join(lines) + "\n"
        try:
            resp = requests.post(
                f"{self.url}/_bulk",
                data=payload,
                headers=self.headers,
                timeout=ELASTIC_TIMEOUT,
            )
            body = resp.json()
            if resp.status_code in (200, 201) and not body.get("errors"):
                return PushResult(success=True, pushed=len(docs))
            failed = sum(1 for item in body.get("items", []) if list(item.values())[0].get("error"))
            return PushResult(success=False, pushed=len(docs) - failed, failed=failed, raw_response=body)
        except Exception as exc:
            logger.warning("elastic_push_failed", extra={"extra_payload": {"error": str(exc)}})
            return PushResult(success=False, failed=len(docs), error=str(exc))

    def push_iocs(self, iocs: list[dict]) -> PushResult:
        return self._bulk(self.ioc_index, iocs)

    def push_alerts(self, alerts: list[dict]) -> PushResult:
        return self._bulk(self.alert_index, alerts)
