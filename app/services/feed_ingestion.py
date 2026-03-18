from __future__ import annotations

import ipaddress
import csv
import gzip
import json
import re
from datetime import datetime
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.models import IOC, IOCRelationship, IOCGraphRelationship, ThreatActor, MalwareFamily, Campaign, Organization, FeedHealth


SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}$")

CANONICAL_IOC_TYPES = {
    "domain": "domain",
    "url": "url",
    "ip": "ip",
    "hash": "file_hash",
    "file_hash": "file_hash",
}


@dataclass
class FeedResult:
    source: str
    fetched: int = 0
    normalized: int = 0
    inserted: int = 0
    skipped: int = 0
    errors: int = 0
    error_message: Optional[str] = None


FEEDS: Dict[str, Dict[str, str]] = {
    # Phishing feeds
    "phishtank": {
        "url": "https://data.phishtank.com/data/online-valid.json.gz",
        "fallback_url": "https://data.phishtank.com/data/online-valid.csv.gz",
        "format": "json",
        "max_items": "5000",
    },
    "openphish": {
        "url": "https://openphish.com/feed.txt",
        "format": "lines",
        "max_items": "5000",
    },
    # Malware feeds
    "malwarebazaar": {
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "format": "lines",
    },
    "abusech_urlhaus": {
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "format": "lines",
        "max_items": "10000",
    },
    # Threat feeds
    "alienvault_otx": {
        "url": "https://otx.alienvault.com/api/v1/pulses/activity",
        "format": "otx_pulses",
        "requires_api_key": "true",
    },
    "emergingthreats": {
        "url": "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
        "format": "lines",
    },
}


GRAPH_SOURCE_MAP: Dict[str, Dict[str, str]] = {
    "phishtank": {
        "entity": "campaign",
        "name": "Phishing-Campaign-Tracked",
        "relationship_type": "part_of_campaign",
    },
    "openphish": {
        "entity": "campaign",
        "name": "Phishing-Campaign-Tracked",
        "relationship_type": "part_of_campaign",
    },
    "abusech_urlhaus": {
        "entity": "campaign",
        "name": "URLhaus-Malware-Campaign",
        "relationship_type": "part_of_campaign",
    },
    "malwarebazaar": {
        "entity": "malware_family",
        "name": "MalwareBazaar-Observed-Family",
        "relationship_type": "associated_with_family",
    },
    "emergingthreats": {
        "entity": "threat_actor",
        "name": "EmergingThreats-Tracked-Actor",
        "relationship_type": "associated_with_actor",
    },
    "alienvault_otx": {
        "entity": "threat_actor",
        "name": "OTX-Tracked-Actor",
        "relationship_type": "associated_with_actor",
    },
}

DOMAIN_FAMILY_SOURCES = {"phishtank", "openphish", "abusech_urlhaus"}
DOMAIN_FAMILY_NAME = "WebThreat-Infrastructure-Family"


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _normalize_domain(value: str) -> Optional[str]:
    v = value.strip().lower().strip(".")
    if DOMAIN_RE.match(v):
        return v
    return None


def _normalize_url(value: str) -> Optional[str]:
    v = value.strip()
    parsed = urlparse(v)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return v
    return None


def _normalize_hash(value: str) -> Optional[str]:
    v = value.strip().lower()
    if SHA256_RE.match(v) or MD5_RE.match(v):
        return v
    return None


def canonicalize_ioc_type(ioc_type: str) -> str:
    return CANONICAL_IOC_TYPES.get(ioc_type, ioc_type)


def normalize_indicator(raw: str) -> Optional[Tuple[str, str]]:
    candidate = raw.strip()
    if not candidate or candidate.startswith("#"):
        return None

    if _is_ip(candidate):
        return (canonicalize_ioc_type("ip"), candidate)

    url = _normalize_url(candidate)
    if url:
        return (canonicalize_ioc_type("url"), url)

    domain = _normalize_domain(candidate)
    if domain:
        return (canonicalize_ioc_type("domain"), domain)

    file_hash = _normalize_hash(candidate)
    if file_hash:
        return (canonicalize_ioc_type("file_hash"), file_hash)

    return None


def normalize_indicators(raw: str) -> List[Tuple[str, str]]:
    """Return one or more canonical indicators extracted from a raw token.

    For URLs, we keep both the URL indicator and its hostname as a domain indicator.
    """
    candidate = raw.strip()
    if not candidate or candidate.startswith("#"):
        return []

    if _is_ip(candidate):
        return [(canonicalize_ioc_type("ip"), candidate)]

    url = _normalize_url(candidate)
    if url:
        out: List[Tuple[str, str]] = [(canonicalize_ioc_type("url"), url)]
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").strip().lower().strip(".")
        normalized_domain = _normalize_domain(hostname) if hostname else None
        if normalized_domain:
            out.append((canonicalize_ioc_type("domain"), normalized_domain))
        return out

    domain = _normalize_domain(candidate)
    if domain:
        return [(canonicalize_ioc_type("domain"), domain)]

    file_hash = _normalize_hash(candidate)
    if file_hash:
        return [(canonicalize_ioc_type("file_hash"), file_hash)]

    return []


def _extract_from_phishtank(payload: Any) -> List[str]:
    indicators: List[str] = []
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                url = item.get("url")
                if isinstance(url, str) and url:
                    indicators.append(url)
    return indicators


def _extract_from_lines(lines: Iterable[str]) -> List[str]:
    indicators: List[str] = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # Split on common separators and keep likely indicator tokens.
        tokens = re.split(r"[\s,;]+", line)
        for tok in tokens:
            if tok and not tok.startswith("#"):
                indicators.append(tok)
    return indicators


def _extract_from_csv_text(text: str) -> List[str]:
    indicators: List[str] = []
    for row in csv.reader(text.splitlines()):
        for cell in row:
            cell = cell.strip()
            if not cell:
                continue
            if cell.startswith("http://") or cell.startswith("https://"):
                indicators.append(cell)
    return indicators


def fetch_feed(source: str, timeout: int = 20, otx_api_key: Optional[str] = None) -> List[str]:
    cfg = FEEDS[source]
    urls = [cfg["url"]]
    fallback = cfg.get("fallback_url")
    if fallback:
        urls.append(fallback)

    headers: Dict[str, str] = {}
    if source == "alienvault_otx" and otx_api_key:
        headers["X-OTX-API-KEY"] = otx_api_key

    last_exc: Optional[Exception] = None
    for url in urls:
        try:
            resp = requests.get(url, timeout=timeout, headers=headers)
            resp.raise_for_status()

            body_text: Optional[str] = None
            content_type = (resp.headers.get("content-type") or "").lower()
            if url.endswith(".gz") or "application/gzip" in content_type:
                body_text = gzip.decompress(resp.content).decode("utf-8", errors="replace")

            if cfg["format"] == "otx_pulses":
                # AlienVault OTX pulse activity — extract individual indicators
                otx_data = resp.json()
                otx_indicators: List[str] = []
                supported = {"IPv4", "IPv6", "domain", "hostname", "URL",
                             "FileHash-MD5", "FileHash-SHA256", "FileHash-SHA1"}
                for pulse in otx_data.get("results", []):
                    for ind in pulse.get("indicators", []):
                        itype = ind.get("type", "")
                        value = ind.get("indicator", "").strip()
                        if value and itype in supported:
                            otx_indicators.append(value)
                return otx_indicators

            if cfg["format"] == "json":
                try:
                    if body_text is not None:
                        return _extract_from_phishtank(json.loads(body_text))
                    return _extract_from_phishtank(resp.json())
                except Exception:
                    # Some providers return CSV/text under fallback URLs.
                    return _extract_from_csv_text(body_text if body_text is not None else resp.text)

            text_payload = body_text if body_text is not None else resp.text
            return _extract_from_lines(text_payload.splitlines())
        except Exception as exc:
            last_exc = exc

    if last_exc:
        raise last_exc
    return []


def _chunks(items: List[Tuple[str, str]], size: int) -> Iterable[List[Tuple[str, str]]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def _row_chunks(items: List[Dict[str, Any]], size: int) -> Iterable[List[Dict[str, Any]]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


async def _get_or_create_default_org_id(db: AsyncSession):
    row = await db.execute(select(Organization).order_by(Organization.created_at.asc()).limit(1))
    org = row.scalar_one_or_none()
    if org:
        return org.id
    org = Organization(name="system-default")
    db.add(org)
    await db.flush()
    return org.id


async def _insert_missing_iocs(db: AsyncSession, source: str, indicators: List[Tuple[str, str]], org_id) -> int:
    if not indicators:
        return 0

    inserted = 0
    for batch in _chunks(indicators, 300):
        rows = [
            {
                "org_id": org_id,
                "type": canonicalize_ioc_type(t),
                "value": v,
                "source": source,
                "first_seen": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
                "confidence": 0.7,
                "source_reliability": 0.7,
            }
            for t, v in batch
        ]
        stmt = pg_insert(IOC).values(rows).on_conflict_do_nothing(index_elements=["type", "value"])
        result = await db.execute(stmt)
        inserted += int(result.rowcount or 0)

    await db.commit()

    return inserted


def _compute_freshness(last_success_at: Optional[datetime]) -> float:
    """Return freshness score in [0.0, 1.0] based on age since last success."""
    if not last_success_at:
        return 0.0
    age_seconds = max(0.0, (datetime.utcnow() - last_success_at).total_seconds())
    # Fresh for first hour; decays linearly to zero by 24 hours.
    if age_seconds <= 3600:
        return 1.0
    if age_seconds >= 86400:
        return 0.0
    return round(1.0 - ((age_seconds - 3600) / (86400 - 3600)), 4)


async def _update_feed_health(
    db: AsyncSession,
    source: str,
    *,
    success: bool,
    error_message: Optional[str] = None,
) -> None:
    row = await db.execute(select(FeedHealth).where(FeedHealth.source == source))
    health = row.scalar_one_or_none()
    if health is None:
        health = FeedHealth(source=source)
        db.add(health)
        await db.flush()

    now = datetime.utcnow()
    if success:
        health.last_success_at = now
        health.success_count = int((health.success_count or 0) + 1)
    else:
        health.last_failure_at = now
        health.error_count = int((health.error_count or 0) + 1)
        health.last_failure_message = (error_message or "")[:1000]

    health.freshness_score = _compute_freshness(health.last_success_at)
    health.updated_at = now


async def _upsert_named_entity(db: AsyncSession, entity_type: str, name: str, org_id) -> int:
    if entity_type == "threat_actor":
        stmt = (
            pg_insert(ThreatActor)
            .values({"name": name, "org_id": org_id})
            .on_conflict_do_update(index_elements=["name"], set_={"name": name})
            .returning(ThreatActor.id)
        )
    elif entity_type == "malware_family":
        stmt = (
            pg_insert(MalwareFamily)
            .values({"name": name, "org_id": org_id})
            .on_conflict_do_update(index_elements=["name"], set_={"name": name})
            .returning(MalwareFamily.id)
        )
    elif entity_type == "campaign":
        stmt = (
            pg_insert(Campaign)
            .values({"name": name, "org_id": org_id})
            .on_conflict_do_update(index_elements=["name"], set_={"name": name})
            .returning(Campaign.id)
        )
    else:
        raise ValueError(f"unknown entity_type '{entity_type}'")

    result = await db.execute(stmt)
    entity_id = result.scalar_one()
    await db.flush()
    return int(entity_id)


async def _attach_graph_relationships(
    db: AsyncSession,
    source: str,
    indicators: List[Tuple[str, str]],
    org_id,
) -> int:
    cfg = GRAPH_SOURCE_MAP.get(source)
    if not cfg or not indicators:
        return 0

    entity_type = cfg["entity"]
    relationship_type = cfg["relationship_type"]
    entity_id = await _upsert_named_entity(db, entity_type=entity_type, name=cfg["name"], org_id=org_id)

    # Resolve IOC ids for normalized (type, value) pairs.
    by_type: Dict[str, List[str]] = {}
    for ioc_type, ioc_value in indicators:
        by_type.setdefault(canonicalize_ioc_type(ioc_type), []).append(ioc_value)

    rows_to_insert: List[Dict[str, Any]] = []
    domain_family_entity_id: Optional[int] = None
    if source in DOMAIN_FAMILY_SOURCES:
        domain_family_entity_id = await _upsert_named_entity(
            db,
            entity_type="malware_family",
            name=DOMAIN_FAMILY_NAME,
            org_id=org_id,
        )
    for ioc_type, values in by_type.items():
        for part in _chunks(values, 500):
            q = await db.execute(
                select(IOC.id, IOC.type, IOC.value).where(IOC.type == ioc_type, IOC.value.in_(part), IOC.org_id == org_id)
            )
            for ioc_id, resolved_type, _ in q.all():
                rel_row: Dict[str, Any] = {
                    "org_id": org_id,
                    "ioc_id": ioc_id,
                    "relationship_type": relationship_type,
                    "related_entity_type": entity_type,
                    "related_entity_id": entity_id,
                    "threat_actor_id": None,
                    "malware_family_id": None,
                    "campaign_id": None,
                    "source": source,
                    "confidence": 70,
                }
                if entity_type == "threat_actor":
                    rel_row["threat_actor_id"] = entity_id
                elif entity_type == "malware_family":
                    rel_row["malware_family_id"] = entity_id
                elif entity_type == "campaign":
                    rel_row["campaign_id"] = entity_id
                rows_to_insert.append(rel_row)

                # Also map known malicious domains to a malware-family bucket
                # to support graph queries like "domains sharing malware family".
                if domain_family_entity_id is not None and resolved_type == "domain":
                    rows_to_insert.append(
                        {
                            "org_id": org_id,
                            "ioc_id": ioc_id,
                            "relationship_type": "associated_with_family",
                            "related_entity_type": "malware_family",
                            "related_entity_id": domain_family_entity_id,
                            "threat_actor_id": None,
                            "malware_family_id": domain_family_entity_id,
                            "campaign_id": None,
                            "source": source,
                            "confidence": 65,
                        }
                    )

    if not rows_to_insert:
        return 0

    inserted = 0
    for rel_batch in _row_chunks(rows_to_insert, 100):
        stmt = (
            pg_insert(IOCRelationship)
            .values(rel_batch)
            .on_conflict_do_nothing(
                index_elements=["ioc_id", "relationship_type", "related_entity_type", "related_entity_id"]
            )
        )
        rel_result = await db.execute(stmt)
        inserted += int(rel_result.rowcount or 0)

    return inserted


async def _attach_ioc_graph_edges(
    db: AsyncSession,
    indicators: List[Tuple[str, str]],
    org_id,
) -> int:
    """Create IOC->IOC edges for graph investigations (e.g., URL -> DOMAIN)."""
    url_to_domain: List[Tuple[str, str]] = []
    domain_set = {v for t, v in indicators if t == "domain"}
    for ioc_type, value in indicators:
        if ioc_type != "url":
            continue
        try:
            parsed = urlparse(value)
            host = (parsed.netloc or "").lower().strip(".")
            if host and host in domain_set:
                url_to_domain.append((value, host))
        except Exception:
            continue

    if not url_to_domain:
        return 0

    unique_values = sorted({v for pair in url_to_domain for v in pair})
    value_to_id: Dict[str, int] = {}
    for value_part in _chunks(unique_values, 500):
        rows = await db.execute(select(IOC.id, IOC.value).where(IOC.value.in_(value_part), IOC.org_id == org_id))
        for ioc_id, ioc_value in rows.all():
            value_to_id[ioc_value] = ioc_id

    edge_rows: List[Dict[str, Any]] = []
    for src_url, dst_domain in url_to_domain:
        src_id = value_to_id.get(src_url)
        dst_id = value_to_id.get(dst_domain)
        if not src_id or not dst_id or src_id == dst_id:
            continue
        edge_rows.append(
            {
                "org_id": org_id,
                "source_ioc_id": src_id,
                "target_ioc_id": dst_id,
                "relationship_type": "shares_infrastructure",
                "confidence": 70,
            }
        )

    if not edge_rows:
        return 0

    inserted = 0
    for batch in _row_chunks(edge_rows, 100):
        stmt = (
            pg_insert(IOCGraphRelationship)
            .values(batch)
            .on_conflict_do_nothing(
                index_elements=["source_ioc_id", "target_ioc_id", "relationship_type"]
            )
        )
        result = await db.execute(stmt)
        inserted += int(result.rowcount or 0)

    return inserted


async def ingest_source(
    db: AsyncSession,
    source: str,
    limit: Optional[int] = None,
    timeout: int = 20,
    otx_api_key: Optional[str] = None,
    org_id=None,
) -> FeedResult:
    if org_id is None:
        org_id = await _get_or_create_default_org_id(db)

    result = FeedResult(source=source)
    try:
        if FEEDS[source].get("requires_api_key") == "true" and not otx_api_key:
            result.error_message = "skipped_missing_otx_api_key"
            await _update_feed_health(db, source, success=False, error_message=result.error_message)
            await db.commit()
            return result

        raw_items = fetch_feed(source=source, timeout=max(timeout, 45), otx_api_key=otx_api_key)
        source_cap = FEEDS[source].get("max_items")
        if source_cap:
            raw_items = raw_items[: int(source_cap)]
        if limit is not None:
            raw_items = raw_items[:limit]

        result.fetched = len(raw_items)

        normalized: List[Tuple[str, str]] = []
        seen: set[Tuple[str, str]] = set()
        for raw in raw_items:
            expanded = normalize_indicators(raw)
            if not expanded:
                result.skipped += 1
                continue

            any_new = False
            for normalized_ioc in expanded:
                if normalized_ioc in seen:
                    result.skipped += 1
                    continue
                seen.add(normalized_ioc)
                normalized.append(normalized_ioc)
                any_new = True

            if not any_new:
                result.skipped += 1

        result.normalized = len(normalized)
        result.inserted = await _insert_missing_iocs(db, source=source, indicators=normalized, org_id=org_id)
        try:
            await _attach_graph_relationships(db, source=source, indicators=normalized, org_id=org_id)
            await _attach_ioc_graph_edges(db, indicators=normalized, org_id=org_id)
        except Exception as rel_exc:
            # Keep IOC ingestion successful even if relationship enrichment fails.
            result.error_message = f"relationship_enrichment_failed: {rel_exc}"
        await _update_feed_health(db, source, success=True)
        await db.commit()
        return result
    except Exception as exc:
        await db.rollback()
        result.errors = 1
        result.error_message = str(exc)
        # Retry inside same session to persist failure metadata.
        await _update_feed_health(db, source, success=False, error_message=result.error_message)
        await db.commit()
        return result


async def ingest_all_sources(
    db: AsyncSession,
    limit_per_source: Optional[int] = None,
    timeout: int = 20,
    otx_api_key: Optional[str] = None,
    org_id=None,
) -> Dict[str, Any]:
    feed_results: List[FeedResult] = []
    for source in FEEDS.keys():
        res = await ingest_source(
            db,
            source=source,
            limit=limit_per_source,
            timeout=timeout,
            otx_api_key=otx_api_key,
            org_id=org_id,
        )
        feed_results.append(res)

    summary = {
        "sources": [r.__dict__ for r in feed_results],
        "totals": {
            "fetched": sum(r.fetched for r in feed_results),
            "normalized": sum(r.normalized for r in feed_results),
            "inserted": sum(r.inserted for r in feed_results),
            "skipped": sum(r.skipped for r in feed_results),
            "errors": sum(r.errors for r in feed_results),
        },
    }
    return summary
