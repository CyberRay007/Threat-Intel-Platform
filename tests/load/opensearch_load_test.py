from __future__ import annotations

import argparse
import random
import string
import time
from datetime import datetime, timedelta

from app.services.search_backend import opensearch_backend


def _rand_domain() -> str:
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + ".example"


def _gen_doc(i: int, org_id: str) -> dict:
    ioc_type = ["domain", "ip", "url", "file_hash"][i % 4]
    if ioc_type == "ip":
        value = f"172.{(i // 255) % 255}.{i % 255}.{(i * 13) % 255}"
    elif ioc_type == "url":
        value = f"http://{_rand_domain()}/p/{i}"
    elif ioc_type == "file_hash":
        value = f"{i:064x}"[-64:]
    else:
        value = _rand_domain()

    ts = (datetime.utcnow() - timedelta(days=i % 90)).isoformat()
    return {
        "id": i + 1,
        "org_id": org_id,
        "type": ioc_type,
        "value": value,
        "value_text": value,
        "tags": [f"tag{i % 20}", "load-test"],
        "source": ["urlhaus", "otx", "internal", "phishtank"][i % 4],
        "threat_actor_id": None,
        "threat_actor_name": "",
        "first_seen": ts,
        "last_seen": ts,
        "confidence": round(0.5 + ((i % 50) / 100), 2),
        "source_reliability": 0.8,
        "relationship_count": i % 5,
    }


def run(total: int, org_id: str, batch_size: int) -> None:
    opensearch_backend.ensure_ioc_index()

    start = time.perf_counter()
    indexed = 0
    for offset in range(0, total, batch_size):
        batch = [_gen_doc(i, org_id) for i in range(offset, min(offset + batch_size, total))]
        result = opensearch_backend.bulk_upsert_iocs(batch)
        indexed += result.get("indexed", 0)
    elapsed = time.perf_counter() - start

    print(f"indexed={indexed}")
    print(f"elapsed_sec={elapsed:.2f}")
    print(f"throughput_docs_per_sec={indexed / max(elapsed, 0.001):.1f}")

    # Warmup
    for _ in range(5):
        opensearch_backend.search_iocs({
            "from": 0,
            "size": 100,
            "track_total_hits": True,
            "query": {"bool": {"filter": [{"term": {"org_id": org_id}}], "must": [{"match_all": {}}]}},
            "aggs": {"by_type": {"terms": {"field": "type"}}, "by_source": {"terms": {"field": "source"}}},
        })

    lat = []
    for idx in range(30):
        t0 = time.perf_counter()
        payload = {
            "from": 0,
            "size": 100,
            "track_total_hits": True,
            "query": {
                "bool": {
                    "filter": [
                        {"term": {"org_id": org_id}},
                        {"range": {"confidence": {"gte": 0.7}}},
                    ],
                    "must": [{"simple_query_string": {"query": ".example" if idx % 2 == 0 else "tag1", "fields": ["value_text", "tags", "source"]}}],
                }
            },
            "aggs": {"by_type": {"terms": {"field": "type"}}, "by_source": {"terms": {"field": "source"}}},
        }
        opensearch_backend.search_iocs(payload)
        lat.append((time.perf_counter() - t0) * 1000)

    lat.sort()
    p50 = lat[len(lat) // 2]
    p95 = lat[int(len(lat) * 0.95) - 1]
    p99 = lat[int(len(lat) * 0.99) - 1]
    avg = sum(lat) / len(lat)

    print(f"search_avg_ms={avg:.2f}")
    print(f"search_p50_ms={p50:.2f}")
    print(f"search_p95_ms={p95:.2f}")
    print(f"search_p99_ms={p99:.2f}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--total", type=int, default=100000)
    parser.add_argument("--org-id", type=str, default="load-test-org")
    parser.add_argument("--batch-size", type=int, default=5000)
    args = parser.parse_args()
    run(args.total, args.org_id, args.batch_size)


if __name__ == "__main__":
    main()
