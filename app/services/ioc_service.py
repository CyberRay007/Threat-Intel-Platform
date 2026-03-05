from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.models import IOC, ThreatActor


def check_domain(domain: str) -> dict:
    """Return IOC match info for a domain."""
    # this service might need db access; we will assume caller passes session
    # for simplicity we'll use a synchronous placeholder here
    # real implementation should be async and accept session argument
    return {"matched_ioc": None, "threat_actor": None, "weight": 0}
