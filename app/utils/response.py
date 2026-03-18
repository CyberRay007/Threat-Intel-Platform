"""
Standard response envelope.

All API responses must use one of these helpers so every consumer gets
a consistent shape:

Success:
    {
        "data": <payload>,
        "error": null,
        "meta": {
            "request_id": "<uuid>",
            "pagination": {...}   # optional
        }
    }

Error:
    {
        "data": null,
        "error": {
            "code": "<MACHINE_READABLE>",
            "message": "<human readable>"
        },
        "meta": {
            "request_id": "<uuid>"
        }
    }
"""

from __future__ import annotations

import uuid
from typing import Any, Optional

from fastapi.responses import JSONResponse


def _meta(pagination: Optional[dict] = None) -> dict:
    m: dict = {"request_id": str(uuid.uuid4())}
    if pagination:
        m["pagination"] = pagination
    return m


def ok(
    data: Any,
    *,
    status_code: int = 200,
    page: Optional[int] = None,
    limit: Optional[int] = None,
    total: Optional[int] = None,
) -> JSONResponse:
    """Return a successful enveloped response."""
    pagination = None
    if total is not None:
        pagination = {"page": page, "limit": limit, "total": total}
    body = {"data": data, "error": None, "meta": _meta(pagination)}
    return JSONResponse(content=body, status_code=status_code)


def err(
    code: str,
    message: str,
    *,
    status_code: int = 400,
) -> JSONResponse:
    """Return a standardised error response."""
    body = {
        "data": None,
        "error": {"code": code, "message": message},
        "meta": _meta(),
    }
    return JSONResponse(content=body, status_code=status_code)


def paginated(
    items: list,
    *,
    page: int,
    limit: int,
    total: int,
) -> JSONResponse:
    """Convenience wrapper for paginated list responses."""
    return ok(items, page=page, limit=limit, total=total)
