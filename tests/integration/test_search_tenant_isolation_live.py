import uuid

from app.config import OPENSEARCH_IOC_INDEX
from app.services.search_backend import opensearch_backend


def _index_doc(doc_id: int, org_id: str, value: str) -> None:
    opensearch_backend.bulk_upsert_iocs(
        [
            {
                "id": doc_id,
                "org_id": org_id,
                "type": "domain",
                "value": value,
                "value_text": value,
                "tags": ["tenant-test"],
                "source": "integration_test",
                "threat_actor_id": None,
                "threat_actor_name": "",
                "first_seen": "2026-03-18T00:00:00Z",
                "last_seen": "2026-03-18T00:00:00Z",
                "confidence": 0.9,
                "source_reliability": 0.8,
                "relationship_count": 0,
            }
        ]
    )


def _search(org_id: str, q: str):
    return opensearch_backend.search_iocs(
        {
            "from": 0,
            "size": 50,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [{"term": {"org_id": org_id}}],
                    "must": [
                        {
                            "simple_query_string": {
                                "query": q,
                                "fields": ["value_text", "value", "tags", "source"],
                            }
                        }
                    ],
                }
            },
        }
    )


def test_opensearch_tenant_isolation_live():
    opensearch_backend.ensure_ioc_index()

    org_a = f"org-a-{uuid.uuid4().hex[:6]}"
    org_b = f"org-b-{uuid.uuid4().hex[:6]}"
    shared_value = f"shared-{uuid.uuid4().hex[:6]}.example"

    _index_doc(900001, org_a, shared_value)
    _index_doc(900002, org_b, shared_value)
    opensearch_backend._request("POST", f"/{OPENSEARCH_IOC_INDEX}/_refresh")

    result_a = _search(org_a, shared_value)
    result_b = _search(org_b, shared_value)

    hits_a = [h.get("_source", {}) for h in result_a.get("hits", {}).get("hits", [])]
    hits_b = [h.get("_source", {}) for h in result_b.get("hits", {}).get("hits", [])]

    assert hits_a, "Expected at least one hit for org A"
    assert hits_b, "Expected at least one hit for org B"
    assert all(doc.get("org_id") == org_a for doc in hits_a)
    assert all(doc.get("org_id") == org_b for doc in hits_b)
