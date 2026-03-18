from __future__ import annotations

import json
from typing import Any

import requests

from app.config import (
    OPENSEARCH_IOC_INDEX,
    OPENSEARCH_PASSWORD,
    OPENSEARCH_TIMEOUT,
    OPENSEARCH_URL,
    OPENSEARCH_USERNAME,
    OPENSEARCH_VERIFY_SSL,
)
from app.core.logging import logger


IOC_INDEX_MAPPING: dict[str, Any] = {
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
        "analysis": {
            "normalizer": {
                "lowercase_normalizer": {
                    "type": "custom",
                    "char_filter": [],
                    "filter": ["lowercase"],
                }
            }
        },
    },
    "mappings": {
        "dynamic": "strict",
        "properties": {
            "id": {"type": "integer"},
            "org_id": {"type": "keyword"},
            "type": {"type": "keyword", "normalizer": "lowercase_normalizer"},
            "value": {"type": "keyword", "normalizer": "lowercase_normalizer"},
            "value_text": {"type": "text"},
            "tags": {"type": "keyword", "normalizer": "lowercase_normalizer"},
            "source": {"type": "keyword", "normalizer": "lowercase_normalizer"},
            "threat_actor_id": {"type": "integer"},
            "threat_actor_name": {
                "type": "text",
                "fields": {
                    "keyword": {"type": "keyword", "normalizer": "lowercase_normalizer"},
                },
            },
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "confidence": {"type": "float"},
            "source_reliability": {"type": "float"},
            "relationship_count": {"type": "integer"},
        },
    },
}


class OpenSearchBackend:
    def __init__(self) -> None:
        self.base_url = OPENSEARCH_URL.rstrip("/")
        self.timeout = OPENSEARCH_TIMEOUT
        self.verify_ssl = OPENSEARCH_VERIFY_SSL
        self.auth = (OPENSEARCH_USERNAME, OPENSEARCH_PASSWORD) if OPENSEARCH_USERNAME else None

    def is_configured(self) -> bool:
        return bool(self.base_url)

    def _request(self, method: str, path: str, *, json_body: Any | None = None, data: str | None = None) -> Any:
        if not self.is_configured():
            raise RuntimeError("OpenSearch URL is not configured")
        url = f"{self.base_url}{path}"
        headers = {"Content-Type": "application/json"}
        response = requests.request(
            method=method,
            url=url,
            json=json_body,
            data=data,
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
            auth=self.auth,
        )
        if response.status_code >= 400:
            raise RuntimeError(f"OpenSearch {method} {path} failed: {response.status_code} {response.text[:300]}")
        if not response.text:
            return {}
        return response.json()

    def health_check(self) -> bool:
        if not self.is_configured():
            return False
        try:
            self._request("GET", "/_cluster/health")
            return True
        except Exception as exc:
            logger.warning("opensearch_health_check_failed", extra={"extra_payload": {"error": str(exc)}})
            return False

    def ensure_ioc_index(self) -> None:
        try:
            self._request("HEAD", f"/{OPENSEARCH_IOC_INDEX}")
        except Exception:
            self._request("PUT", f"/{OPENSEARCH_IOC_INDEX}", json_body=IOC_INDEX_MAPPING)
            logger.info(
                "opensearch_ioc_index_created",
                extra={"extra_payload": {"event": "opensearch_ioc_index_created", "index": OPENSEARCH_IOC_INDEX}},
            )

    def bulk_upsert_iocs(self, docs: list[dict[str, Any]]) -> dict[str, Any]:
        if not docs:
            return {"indexed": 0}
        self.ensure_ioc_index()
        lines: list[str] = []
        for doc in docs:
            document_id = f"{doc['org_id']}:{doc['id']}"
            lines.append(json.dumps({"index": {"_index": OPENSEARCH_IOC_INDEX, "_id": document_id}}))
            lines.append(json.dumps(doc, default=str))
        body = self._request("POST", "/_bulk", data="\n".join(lines) + "\n")
        failed = sum(1 for item in body.get("items", []) if list(item.values())[0].get("error"))
        return {"indexed": len(docs) - failed, "failed": failed}

    def delete_ioc_document(self, *, org_id: str, ioc_id: int) -> None:
        self.ensure_ioc_index()
        document_id = f"{org_id}:{ioc_id}"
        try:
            self._request("DELETE", f"/{OPENSEARCH_IOC_INDEX}/_doc/{document_id}")
        except Exception as exc:
            if "404" not in str(exc):
                raise

    def search_iocs(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.ensure_ioc_index()
        return self._request("POST", f"/{OPENSEARCH_IOC_INDEX}/_search", json_body=payload)


opensearch_backend = OpenSearchBackend()