from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Set
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Alert, Event, IOC


SHA256_RE = re.compile(r"^[a-fA-F0-9]{64}$")
MD5_RE = re.compile(r"^[a-fA-F0-9]{32}$")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
DOMAIN_RE = re.compile(r"\b(?=.{1,253}\b)(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _chunk(values: List[str], size: int = 500) -> Iterable[List[str]]:
    for i in range(0, len(values), size):
        yield values[i : i + size]


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _flatten_text(payload: Any) -> str:
    if payload is None:
        return ""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        return " ".join(_flatten_text(v) for v in payload.values())
    if isinstance(payload, list):
        return " ".join(_flatten_text(v) for v in payload)
    return str(payload)


def extract_observables(payload: Dict[str, Any]) -> Dict[str, List[str]]:
    text_blob = _flatten_text(payload)

    urls: Set[str] = set(URL_RE.findall(text_blob))
    ips: Set[str] = {ip for ip in IP_RE.findall(text_blob) if _valid_ip(ip)}
    hashes: Set[str] = set()
    domains: Set[str] = set()

    for token in re.split(r"[\s,;]+", text_blob):
        t = token.strip().strip("\"'()[]{}<>").lower()
        if not t:
            continue
        if SHA256_RE.match(t) or MD5_RE.match(t):
            hashes.add(t)

    for domain in DOMAIN_RE.findall(text_blob):
        d = domain.strip(".").lower()
        if d and not d.startswith("http"):
            domains.add(d)

    for url in list(urls):
        parsed = urlparse(url)
        if parsed.netloc:
            domains.add(parsed.netloc.lower())

    return {
        "domain": sorted(domains),
        "url": sorted(urls),
        "ip": sorted(ips),
        "file_hash": sorted(hashes),
    }


async def _match_type(db: AsyncSession, ioc_type: str, values: List[str]) -> List[Dict[str, Any]]:
    if not values:
        return []

    matches: List[Dict[str, Any]] = []
    for part in _chunk(values):
        rows = await db.execute(
            select(IOC).where(IOC.type == ioc_type, IOC.value.in_(part))
        )
        for ioc in rows.scalars().all():
            matches.append(
                {
                    "ioc_id": ioc.id,
                    "type": ioc.type,
                    "value": ioc.value,
                    "source": ioc.source,
                    "threat_actor_id": ioc.threat_actor_id,
                }
            )

    return matches


async def match_observables(db: AsyncSession, observables: Dict[str, List[str]]) -> Dict[str, List[Dict[str, Any]]]:
    return {
        "domain": await _match_type(db, "domain", observables.get("domain", [])),
        "url": await _match_type(db, "url", observables.get("url", [])),
        "ip": await _match_type(db, "ip", observables.get("ip", [])),
        "file_hash": await _match_type(db, "file_hash", observables.get("file_hash", [])),
    }


def _severity(total_matches: int) -> str:
    if total_matches >= 10:
        return "critical"
    if total_matches >= 5:
        return "high"
    if total_matches >= 2:
        return "medium"
    return "low"


def _fingerprint(observable_type: str, observable_value: str) -> str:
    return hashlib.sha256(f"{observable_type}:{observable_value}".encode("utf-8")).hexdigest()


def _pick_primary_condition(matches: Dict[str, List[Dict[str, Any]]]) -> Dict[str, str] | None:
    # Stable order to make aggregation deterministic.
    for observable_type in ["domain", "url", "ip", "file_hash"]:
        candidates = matches.get(observable_type, [])
        if candidates:
            first = candidates[0]
            return {
                "observable_type": observable_type,
                "observable_value": first["value"],
            }
    return None


async def process_event(
    db: AsyncSession,
    event: Event,
) -> Event:
    payload = event.raw_event or {}
    observables = extract_observables(payload)

    # Keep first-seen observables denormalized for indexed investigation queries.
    event.domain = observables.get("domain", [None])[0] if observables.get("domain") else None
    event.url = observables.get("url", [None])[0] if observables.get("url") else None
    event.ip = observables.get("ip", [None])[0] if observables.get("ip") else None
    event.file_hash = observables.get("file_hash", [None])[0] if observables.get("file_hash") else None
    matches = await match_observables(db, observables)
    total = sum(len(v) for v in matches.values())
    now = datetime.utcnow()

    event.extracted_observables = observables
    event.matched_iocs = matches
    event.status = "processed"

    if total > 0:
        primary = _pick_primary_condition(matches)
        if primary:
            observable_type = primary["observable_type"]
            observable_value = primary["observable_value"]
            fingerprint = _fingerprint(observable_type, observable_value)

            existing = await db.execute(
                select(Alert).where(Alert.fingerprint == fingerprint)
            )
            alert = existing.scalar_one_or_none()
            if alert:
                # Re-open previously closed alerts when the same fingerprint reappears.
                if alert.status in {"resolved", "false_positive"}:
                    alert.status = "open"
                alert.last_seen_at = now
                alert.occurrence_count += 1
                alert.matched_count = total
                alert.description = f"Matched {total} IOC(s) across extracted observables."
                event.alert_id = alert.id
            else:
                alert = Alert(
                    fingerprint=fingerprint,
                    observable_type=observable_type,
                    observable_value=observable_value,
                    severity=_severity(total),
                    title=f"IOC match detected: {observable_type}",
                    description=f"Matched {total} IOC(s) across extracted observables.",
                    matched_count=total,
                    status="open",
                    first_seen_at=now,
                    last_seen_at=now,
                    occurrence_count=1,
                )
                db.add(alert)
                await db.flush()
                event.alert_id = alert.id

    await db.commit()
    await db.refresh(event)
    return event
