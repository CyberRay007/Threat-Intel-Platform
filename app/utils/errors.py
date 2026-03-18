"""
Error taxonomy.

Every error raised through the API must use a code from this module.
Machine-readable codes allow integrators to branch on error type
without parsing human-readable messages.

Usage:
    from app.utils.errors import E, api_error
    raise api_error(E.IOC_NOT_FOUND)
"""

from __future__ import annotations

from dataclasses import dataclass
from fastapi import HTTPException


@dataclass(frozen=True)
class _ErrorDef:
    code: str
    message: str
    http_status: int


class E:
    # Auth
    AUTH_TOKEN_MISSING     = _ErrorDef("AUTH_TOKEN_MISSING",     "Authentication token is missing.",          401)
    AUTH_TOKEN_INVALID     = _ErrorDef("AUTH_TOKEN_INVALID",     "Authentication token is invalid or expired.", 401)
    AUTH_PERMISSION_DENIED = _ErrorDef("AUTH_PERMISSION_DENIED", "Insufficient permissions for this action.", 403)

    # API Keys
    API_KEY_MISSING        = _ErrorDef("API_KEY_MISSING",        "API key header is missing.",                401)
    API_KEY_INVALID        = _ErrorDef("API_KEY_INVALID",        "API key is invalid or revoked.",            401)
    API_KEY_RATE_LIMITED   = _ErrorDef("API_KEY_RATE_LIMITED",   "API key rate limit exceeded.",              429)
    API_KEY_NOT_FOUND      = _ErrorDef("API_KEY_NOT_FOUND",      "API key not found.",                        404)

    # IOC
    IOC_NOT_FOUND          = _ErrorDef("IOC_NOT_FOUND",          "IOC not found.",                            404)
    IOC_DUPLICATE          = _ErrorDef("IOC_DUPLICATE",          "IOC with this type and value already exists.", 409)

    # Alerts
    ALERT_NOT_FOUND        = _ErrorDef("ALERT_NOT_FOUND",        "Alert not found.",                          404)
    ALERT_STATUS_INVALID   = _ErrorDef("ALERT_STATUS_INVALID",   "Invalid alert triage status.",              400)

    # Actors / campaigns
    ACTOR_NOT_FOUND        = _ErrorDef("ACTOR_NOT_FOUND",        "Threat actor not found.",                   404)
    ACTOR_DUPLICATE        = _ErrorDef("ACTOR_DUPLICATE",        "Threat actor with this name already exists.", 409)
    CAMPAIGN_NOT_FOUND     = _ErrorDef("CAMPAIGN_NOT_FOUND",     "Campaign not found.",                       404)

    # Feed / ingestion
    FEED_SOURCE_UNKNOWN    = _ErrorDef("FEED_SOURCE_UNKNOWN",    "Unknown feed source.",                      400)

    # Entitlement
    QUOTA_EXCEEDED         = _ErrorDef("QUOTA_EXCEEDED",         "Organisational quota exceeded for this resource.", 402)
    PLAN_FEATURE_DISABLED  = _ErrorDef("PLAN_FEATURE_DISABLED",  "This feature is not available on your current plan.", 402)

    # Infrastructure
    SERVICE_UNAVAILABLE    = _ErrorDef("SERVICE_UNAVAILABLE",    "A downstream service is temporarily unavailable.", 503)
    VALIDATION_ERROR       = _ErrorDef("VALIDATION_ERROR",       "Request validation failed.",                422)


def api_error(defn: _ErrorDef, *, detail_override: str | None = None) -> HTTPException:
    """
    Raise a FastAPI HTTPException whose detail dict carries both
    machine-readable code and human-readable message.

    The RequestContextMiddleware or a custom exception handler should
    serialize this into the standard envelope before sending to client.
    """
    return HTTPException(
        status_code=defn.http_status,
        detail={"code": defn.code, "message": detail_override or defn.message},
    )
