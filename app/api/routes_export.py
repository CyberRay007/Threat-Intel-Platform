"""
Export endpoints for search results and IOCs.

Supports:
- STIX 2.1 export (JSON-LD format)
- TAXII 2.1 integration (collections)
- JSON export (custom format)
- CSV export (for analysts and Excel)
"""

from datetime import datetime
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.session import get_db
from app.core.security import get_current_user
from app.core.entitlements import require_entitlement, require_permission
from app.models import User
from app.services.search_service import search_iocs
from app.database.models import IOC, ThreatActor

router = APIRouter(prefix="/api/v1/export", tags=["export"])


# ==============================================================================
# STIX 2.1 Export
# ==============================================================================

def _ioc_to_stix_observable(ioc: IOC, threat_actor: Optional[ThreatActor] = None) -> dict:
    """Convert IOC record to STIX Observable object."""
    
    # Map IOC types to STIX observable types
    stix_type_mapping = {
        "domain": {"type": "domain-name", "value_field": "value"},
        "ip": {"type": "ipv4-addr", "value_field": "value"},
        "url": {"type": "url", "value_field": "value"},
        "file_hash": {"type": "file", "value_field": "hashes.MD5"},  # Simplified
    }
    
    stix_config = stix_type_mapping.get(ioc.type, {"type": "x-custom-ioc", "value_field": "value"})
    
    observable = {
        "id": f"observable--{ioc.id}",
        "type": "observed-data",
        "created": ioc.first_seen.isoformat() if ioc.first_seen else datetime.utcnow().isoformat(),
        "modified": ioc.last_seen.isoformat() if ioc.last_seen else datetime.utcnow().isoformat(),
        "object_refs": [f"observable--{ioc.id}-1"],
    }
    
    # Add objects
    objects = {
        "0": {
            "type": stix_config["type"],
            "value": ioc.value,
        }
    }
    observable["objects"] = objects
    
    return observable


def _ioc_to_stix_indicator(ioc: IOC, threat_actor: Optional[ThreatActor] = None) -> dict:
    """Convert IOC to STIX Indicator object."""
    
    # Build pattern (simplified STIX pattern language)
    # Example: [domain-name:value = 'malware.com']
    
    stix_pattern_mapping = {
        "domain": "[domain-name:value",
        "ip": "[ipv4-addr:value",
        "url": "[url:value",
        "file_hash": "[file:hashes.MD5",
    }
    
    pattern_prefix = stix_pattern_mapping.get(ioc.type, "[x-custom-ioc:value")
    pattern = f"{pattern_prefix} = '{ioc.value}']"
    
    indicator = {
        "id": f"indicator--{UUID(int=ioc.id).hex}",
        "type": "indicator",
        "created": ioc.first_seen.isoformat() if ioc.first_seen else datetime.utcnow().isoformat(),
        "modified": ioc.last_seen.isoformat() if ioc.last_seen else datetime.utcnow().isoformat(),
        "name": f"{ioc.type.upper()}: {ioc.value}",
        "description": f"Confidence: {ioc.confidence}, Source Reliability: {ioc.source_reliability}, Source: {ioc.source}",
        "pattern": pattern,
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": ioc.first_seen.isoformat() if ioc.first_seen else datetime.utcnow().isoformat(),
        "labels": ["malicious-activity"],
    }
    
    # Add relationships to threat actor if applicable
    if threat_actor:
        indicator["created_by_ref"] = f"identity--{threat_actor.id}"
    
    return indicator


@router.get("/stix2.1/indicators", name="export_stix21_indicators")
async def export_stix21_indicators(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    q: str = Query("", description="Search query"),
    ioc_type: Optional[str] = Query(None, alias="type", description="Filter by IOC type"),
    min_confidence: Optional[float] = Query(None, description="Minimum confidence level"),
):
    """
    Export search results as STIX 2.1 Indicators.
    
    Returns STIX 2.1 JSON-LD format suitable for threat intelligence sharing.
    Can be consumed by SIEM/SOAR platforms and other threat intelligence tools.
    """
    
    # Check entitlements
    require_permission("intel:read")(current_user)
    require_entitlement("search_intelligence")(current_user)
    
    # Search IOCs
    search_results = await search_iocs(
        db=db,
        org_id=str(current_user.org_id),
        query=q,
        ioc_type=ioc_type,
        min_confidence=min_confidence
    )
    
    # Build STIX bundle
    indicators = []
    identities = set()
    
    for result in search_results.get("results", []):
        ioc_id = result["id"]
        threat_actor_id = result.get("threat_actor_id")
        
        # Fetch full IOC
        ioc = await db.get(IOC, ioc_id)
        if not ioc:
            continue
        
        threat_actor = None
        if threat_actor_id:
            threat_actor = await db.get(ThreatActor, threat_actor_id)
            if threat_actor:
                identities.add(threat_actor.id)
        
        indicator = _ioc_to_stix_indicator(ioc, threat_actor)
        indicators.append(indicator)
    
    # Build STIX identity objects for threat actors
    identity_objects = []
    for actor_id in identities:
        actor = await db.get(ThreatActor, actor_id)
        if actor:
            identity = {
                "id": f"identity--{actor_id}",
                "type": "identity",
                "created": datetime.utcnow().isoformat(),
                "modified": datetime.utcnow().isoformat(),
                "name": actor.name,
                "description": actor.description,
                "identity_class": "threat-actor",
            }
            identity_objects.append(identity)
    
    # Create STIX bundle
    bundle = {
        "type": "bundle",
        "id": f"bundle--{UUID().hex}",
        "objects": identity_objects + indicators,
    }
    
    return bundle


# ==============================================================================
# JSON Export
# ==============================================================================

@router.get("/json")
async def export_json(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    q: str = Query("", description="Search query"),
    ioc_type: Optional[str] = Query(None, alias="type"),
    min_confidence: Optional[float] = Query(None),
    include_metadata: bool = Query(True, description="Include full IOC metadata"),
):
    """
    Export search results as JSON.
    
    Includes:
    - IOC details (type, value, confidence, source)
    - Associated threat actors
    - Tags and relationships
    - Timeline (first_seen, last_seen)
    """
    
    require_permission("intel:read")(current_user)
    require_entitlement("search_intelligence")(current_user)
    
    # Search IOCs
    search_results = await search_iocs(
        db=db,
        org_id=str(current_user.org_id),
        query=q,
        ioc_type=ioc_type,
        min_confidence=min_confidence
    )
    
    results = []
    for ioc_data in search_results.get("results", []):
        if include_metadata:
            results.append(ioc_data)
        else:
            # Minimal format
            results.append({
                "id": ioc_data["id"],
                "type": ioc_data["type"],
                "value": ioc_data["value"],
                "confidence": ioc_data["confidence"],
            })
    
    return {
        "meta": {
            "export_date": datetime.utcnow().isoformat(),
            "org_id": str(current_user.org_id),
            "result_count": len(results),
            "query_string": q,
        },
        "data": results,
    }


# ==============================================================================
# CSV Export
# ==============================================================================

@router.get("/csv")
async def export_csv(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    q: str = Query("", description="Search query"),
    ioc_type: Optional[str] = Query(None, alias="type"),
):
    """
    Export search results as CSV.
    
    Columns: id, type, value, confidence, source, source_reliability, threat_actor, tags, first_seen, last_seen
    """
    
    require_permission("intel:read")(current_user)
    require_entitlement("search_intelligence")(current_user)
    
    search_results = await search_iocs(
        db=db,
        org_id=str(current_user.org_id),
        query=q,
        ioc_type=ioc_type
    )
    
    import csv
    import io
    
    output = io.StringIO()
    writer = csv.DictWriter(
        output,
        fieldnames=[
            "id", "type", "value", "confidence", "source_reliability",
            "source", "threat_actor", "tags_list", "first_seen", "last_seen"
        ]
    )
    writer.writeheader()
    
    for ioc_data in search_results.get("results", []):
        writer.writerow({
            "id": ioc_data["id"],
            "type": ioc_data["type"],
            "value": ioc_data["value"],
            "confidence": f"{ioc_data['confidence']:.3f}",
            "source_reliability": f"{ioc_data['source_reliability']:.3f}",
            "source": ioc_data["source"],
            "threat_actor": ioc_data.get("threat_actor_name", "N/A"),
            "tags_list": ";".join(ioc_data.get("tags", [])),
            "first_seen": ioc_data["first_seen"],
            "last_seen": ioc_data["last_seen"],
        })
    
    return {
        "content_type": "text/csv",
        "body": output.getvalue(),
        "filename": f"ioc-export-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"
    }


# ==============================================================================
# TAXII 2.1 Collections Integration
# ==============================================================================

class TAXIICollectionDesc(dict):
    """TAXII 2.1 Collection description object."""
    pass


@router.get("/taxii2.1/discovery", name="taxii_discovery")
async def taxii_discovery(current_user: User = Depends(get_current_user)):
    """
    TAXII 2.1 Server Discovery endpoint.
    
    Lists available TAXII collections for IOC sharing.
    """
    
    require_entitlement("search_intelligence")(current_user)
    
    return {
        "title": f"TIP TAXII API - {current_user.organization.name}",
        "description": "Threat Intelligence Platform TAXII 2.1 API",
        "contact": "security@example.com",
        "api_roots": [
            f"/api/v1/export/taxii2.1/api_roots/{current_user.org_id}"
        ],
    }


@router.get("/taxii2.1/collections", name="taxii_collections")
async def taxii_collections(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    TAXII 2.1 Collections endpoint.
    
    Returns list of available collections for this organization.
    """
    
    require_entitlement("search_intelligence")(current_user)
    
    return {
        "collections": [
            {
                "id": "iocs",
                "title": "Organization IOCs",
                "description": f"All IOCs for {current_user.organization.name}",
                "can_read": True,
                "can_write": current_user.role in ["admin"],
            },
            {
                "id": "iocs_high_confidence",
                "title": "High Confidence IOCs",
                "description": "IOCs with >= 0.8 confidence",
                "can_read": True,
                "can_write": False,
            },
        ]
    }


@router.post("/taxii2.1/collections/iocs/objects", name="taxii_add_objects")
async def taxii_add_objects(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    TAXII 2.1 Add Objects endpoint.
    
    Ingest STIX objects from external TAXII servers.
    """
    
    require_permission("intel:write")(current_user)
    
    return {
        "success": 0,
        "failures": [],
    }
