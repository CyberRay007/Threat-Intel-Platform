from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.models import IOC, ThreatActor


async def check_domain(db: AsyncSession, domain: str) -> dict:
    """Return IOC match info for a domain."""
    result = await db.execute(
        select(IOC).where(IOC.value == domain, IOC.type == "domain")
    )
    ioc = result.scalar_one_or_none()
    if ioc:
        threat_actor = None
        if ioc.threat_actor_id:
            ta_result = await db.execute(
                select(ThreatActor).where(ThreatActor.id == ioc.threat_actor_id)
            )
            threat_actor = ta_result.scalar_one_or_none()
        return {
            "matched_ioc": ioc.value,
            "threat_actor": threat_actor.name if threat_actor else None,
            "weight": 50  # high risk for IOC match
        }
    return {"matched_ioc": None, "threat_actor": None, "weight": 0}


def check_ioc_match(db, value):
    # deprecated, use check_domain
    pass
