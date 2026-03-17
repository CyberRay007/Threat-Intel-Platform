from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Campaign, IOC, IOCRelationship, MalwareFamily, ThreatActor


IOC_TYPE_ALIASES = {
    "hash": "file_hash",
    "filehash": "file_hash",
}


def normalize_ioc_type(ioc_type: str) -> str:
    t = (ioc_type or "").strip().lower()
    return IOC_TYPE_ALIASES.get(t, t)


def normalize_ioc_value(ioc_type: str, value: str) -> str:
    t = normalize_ioc_type(ioc_type)
    v = (value or "").strip()
    if t in {"domain", "url", "ip"}:
        return v.lower().strip(".")
    return v.lower()


def _ioc_db_types(ioc_type: str) -> List[str]:
    t = normalize_ioc_type(ioc_type)
    if t == "file_hash":
        # Backward compatibility for older rows that stored file hashes as "hash"
        return ["file_hash", "hash"]
    return [t]


async def _get_ioc(db: AsyncSession, ioc_type: str, value: str, org_id=None) -> Optional[IOC]:
    value_norm = normalize_ioc_value(ioc_type, value)
    ioc_types = _ioc_db_types(ioc_type)
    query = select(IOC).where(IOC.type.in_(ioc_types), IOC.value == value_norm)
    if org_id is not None:
        query = query.where(IOC.org_id == org_id)
    row = await db.execute(query)
    return row.scalar_one_or_none()


async def enrich_ioc(db: AsyncSession, ioc_type: str, value: str, org_id=None) -> Dict[str, Any]:
    ioc = await _get_ioc(db, ioc_type, value, org_id=org_id)
    if not ioc:
        return {
            "exists": False,
            "ioc_type": normalize_ioc_type(ioc_type),
            "value": normalize_ioc_value(ioc_type, value),
            "source": None,
            "threat_actor": None,
            "campaigns": [],
            "malware_families": [],
            "relationships": [],
        }

    rel_rows = await db.execute(
        select(IOCRelationship).where(IOCRelationship.ioc_id == ioc.id)
    )
    relationships = rel_rows.scalars().all()

    actor_ids = sorted({r.threat_actor_id for r in relationships if r.threat_actor_id is not None})
    family_ids = sorted({r.malware_family_id for r in relationships if r.malware_family_id is not None})
    campaign_ids = sorted({r.campaign_id for r in relationships if r.campaign_id is not None})

    actor_map: Dict[int, ThreatActor] = {}
    family_map: Dict[int, MalwareFamily] = {}
    campaign_map: Dict[int, Campaign] = {}

    if actor_ids:
        actor_res = await db.execute(select(ThreatActor).where(ThreatActor.id.in_(actor_ids)))
        actor_map = {a.id: a for a in actor_res.scalars().all()}

    if family_ids:
        family_res = await db.execute(select(MalwareFamily).where(MalwareFamily.id.in_(family_ids)))
        family_map = {f.id: f for f in family_res.scalars().all()}

    if campaign_ids:
        campaign_res = await db.execute(select(Campaign).where(Campaign.id.in_(campaign_ids)))
        campaign_map = {c.id: c for c in campaign_res.scalars().all()}

    relationship_items: List[Dict[str, Any]] = []
    for rel in relationships:
        rel_item: Dict[str, Any] = {
            "relationship_type": rel.relationship_type,
            "entity_type": rel.related_entity_type,
            "entity_id": rel.related_entity_id,
            "confidence": rel.confidence,
            "source": rel.source,
        }
        if rel.threat_actor_id and rel.threat_actor_id in actor_map:
            rel_item["entity_name"] = actor_map[rel.threat_actor_id].name
        elif rel.malware_family_id and rel.malware_family_id in family_map:
            rel_item["entity_name"] = family_map[rel.malware_family_id].name
        elif rel.campaign_id and rel.campaign_id in campaign_map:
            rel_item["entity_name"] = campaign_map[rel.campaign_id].name
        relationship_items.append(rel_item)

    direct_actor = None
    if ioc.threat_actor_id and ioc.threat_actor_id in actor_map:
        ta = actor_map[ioc.threat_actor_id]
        direct_actor = {
            "id": ta.id,
            "name": ta.name,
            "origin": ta.origin,
            "aliases": ta.aliases or [],
        }

    return {
        "exists": True,
        "ioc_id": ioc.id,
        "ioc_type": "file_hash" if ioc.type == "hash" else ioc.type,
        "value": ioc.value,
        "source": ioc.source,
        "threat_actor": direct_actor,
        "campaigns": [{"id": c.id, "name": c.name} for c in campaign_map.values()],
        "malware_families": [{"id": f.id, "name": f.name} for f in family_map.values()],
        "relationships": relationship_items,
    }


async def attribute_observable(db: AsyncSession, ioc_type: str, value: str, org_id=None) -> Dict[str, Any]:
    ioc = await _get_ioc(db, ioc_type, value, org_id=org_id)
    if not ioc:
        return {
            "attributed": False,
            "ioc_type": normalize_ioc_type(ioc_type),
            "value": normalize_ioc_value(ioc_type, value),
            "actors": [],
        }

    actor_scores: Dict[int, int] = defaultdict(int)
    actor_evidence: Dict[int, List[str]] = defaultdict(list)

    if ioc.threat_actor_id is not None:
        actor_scores[ioc.threat_actor_id] = max(actor_scores[ioc.threat_actor_id], 85)
        actor_evidence[ioc.threat_actor_id].append("direct_ioc_mapping")

    rel_rows = await db.execute(
        select(IOCRelationship).where(
            IOCRelationship.ioc_id == ioc.id,
            IOCRelationship.threat_actor_id.isnot(None),
        )
    )
    for rel in rel_rows.scalars().all():
        rel_score = min(100, 30 + int(rel.confidence or 0))
        actor_scores[rel.threat_actor_id] = max(actor_scores[rel.threat_actor_id], rel_score)
        actor_evidence[rel.threat_actor_id].append(f"relationship:{rel.relationship_type}")

    if not actor_scores:
        return {
            "attributed": False,
            "ioc_type": "file_hash" if ioc.type == "hash" else ioc.type,
            "value": ioc.value,
            "actors": [],
        }

    actor_ids = list(actor_scores.keys())
    actor_rows = await db.execute(select(ThreatActor).where(ThreatActor.id.in_(actor_ids)))
    actor_map = {a.id: a for a in actor_rows.scalars().all()}

    actors = []
    for actor_id, score in actor_scores.items():
        actor = actor_map.get(actor_id)
        if not actor:
            continue
        actors.append(
            {
                "id": actor.id,
                "name": actor.name,
                "origin": actor.origin,
                "aliases": actor.aliases or [],
                "confidence": score,
                "evidence": sorted(set(actor_evidence.get(actor_id, []))),
            }
        )

    actors.sort(key=lambda a: a["confidence"], reverse=True)

    return {
        "attributed": len(actors) > 0,
        "ioc_type": "file_hash" if ioc.type == "hash" else ioc.type,
        "value": ioc.value,
        "actors": actors,
    }
