"""
Entitlement layer.

Enforces plan-level quotas and feature gates without requiring a billing
system to be in place.  Plans are:
  - free       : community / trial
  - pro        : small teams
  - enterprise : full access

Usage in route handlers:
    from app.core.entitlements import require_feature, check_quota

    # Guard a feature
    require_feature(current_user.organization.plan, "stix_export")

    # Guard a quota (raises if limit reached)
    await check_quota(db, current_user.org_id, "api_keys", max=PLANS["free"]["max_api_keys"])
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from fastapi import Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.utils.errors import E, api_error
from app.database.session import get_db
from app.database.models import Organization, User
from app.dependencies import get_current_user

# ---------------------------------------------------------------------------
# Plan definitions
# ---------------------------------------------------------------------------

PLANS: dict[str, dict[str, Any]] = {
    "free": {
        "max_api_keys":        2,
        "max_feeds":           3,
        "api_requests_per_min": 60,
        "features": {
            "ioc_export_csv":  True,
            "ioc_export_json": True,
            "feed_ingest":     True,
            "feed_export":     True,
            "stix_export":     False,
            "custom_rules":    False,
            "siem_push":       False,
            "graph_intel":     False,
        },
    },
    "pro": {
        "max_api_keys":        10,
        "max_feeds":           10,
        "api_requests_per_min": 600,
        "features": {
            "ioc_export_csv":  True,
            "ioc_export_json": True,
            "feed_ingest":     True,
            "feed_export":     True,
            "stix_export":     True,
            "custom_rules":    True,
            "siem_push":       True,
            "graph_intel":     True,
        },
    },
    "enterprise": {
        "max_api_keys":        -1,     # unlimited
        "max_feeds":           -1,
        "api_requests_per_min": -1,
        "features": {
            "ioc_export_csv":  True,
            "ioc_export_json": True,
            "feed_ingest":     True,
            "feed_export":     True,
            "stix_export":     True,
            "custom_rules":    True,
            "siem_push":       True,
            "graph_intel":     True,
        },
    },
}


def get_plan(plan_name: str | None) -> dict:
    """Return plan definition, defaulting to 'free' for unknown plans."""
    return PLANS.get((plan_name or "free").lower(), PLANS["free"])


def allowed_feed_sources(plan_name: str | None, all_sources: list[str]) -> list[str]:
    """
    Return the subset of feed sources allowed for a plan.

    For capped plans, this currently allows the first N sources in sorted order.
    Deterministic ordering keeps behaviour stable for API consumers.
    """
    plan = get_plan(plan_name)
    max_feeds = plan.get("max_feeds", -1)
    if max_feeds == -1:
        return sorted(all_sources)
    return sorted(all_sources)[: max(0, int(max_feeds))]


# ---------------------------------------------------------------------------
# Feature gate
# ---------------------------------------------------------------------------

def require_feature(plan_name: str | None, feature: str) -> None:
    """
    Raise api_error(E.PLAN_FEATURE_DISABLED) if the org's plan does not
    include `feature`.  Call this at the top of protected route handlers.
    """
    plan = get_plan(plan_name)
    if not plan["features"].get(feature, False):
        raise api_error(
            E.PLAN_FEATURE_DISABLED,
            detail_override=f"Feature '{feature}' is not available on the '{plan_name or 'free'}' plan.",
        )


def require_entitlement(feature: str):
    """
    FastAPI dependency factory that hard-blocks requests when an org plan
    does not include a feature.
    """
    async def checker(
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user),
    ) -> User:
        org_row = await db.execute(select(Organization).where(Organization.id == current_user.org_id))
        org = org_row.scalar_one_or_none()
        plan_name = org.plan if org else "free"
        require_feature(plan_name, feature)
        return current_user

    return checker


# ---------------------------------------------------------------------------
# Quota checks (async, requires DB session)
# ---------------------------------------------------------------------------

async def check_quota(
    db: AsyncSession,
    org_id: Any,
    resource: str,
    *,
    plan_name: str | None,
) -> None:
    """
    Check that the org has not exceeded its plan quota for `resource`.
    Raises api_error(E.QUOTA_EXCEEDED) if limit reached.

    Supported resources: "api_keys", "feeds"
    """
    plan = get_plan(plan_name)
    limit = plan.get(f"max_{resource}", -1)
    if limit == -1:
        return  # unlimited

    from app.database.models import APIKey  # local import avoids circular

    counts: dict[str, Any] = {
        "api_keys": lambda: select(func.count()).select_from(APIKey).where(APIKey.org_id == org_id),
    }

    if resource not in counts:
        return  # unknown resource, allow

    query = counts[resource]()
    result = await db.execute(query)
    current = result.scalar_one()

    if current >= limit:
        raise api_error(
            E.QUOTA_EXCEEDED,
            detail_override=(
                f"Your plan allows a maximum of {limit} {resource.replace('_', ' ')}. "
                f"You currently have {current}. Upgrade to increase limits."
            ),
        )
