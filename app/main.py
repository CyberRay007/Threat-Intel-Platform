import uuid
import json

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import time

from app.core.jwt import decode_access_token
from app.core.logging import logger, reset_log_context, set_log_context
from app.api import routes_auth, routes_scan, routes_intel, routes_detection, routes_dasboard, routes_search

app = FastAPI(title="Threat Intel Platform")


def _error_envelope(code: str, message: str, status_code: int, request_id: str | None = None) -> JSONResponse:
	body = {
		"data": None,
		"error": {
			"code": code,
			"message": message,
		},
		"meta": {
			"request_id": request_id or str(uuid.uuid4()),
		},
	}
	return JSONResponse(status_code=status_code, content=body)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
	request_id = getattr(request.state, "request_id", None)
	if isinstance(exc.detail, dict) and "code" in exc.detail and "message" in exc.detail:
		return _error_envelope(exc.detail["code"], exc.detail["message"], exc.status_code, request_id=request_id)
	return _error_envelope("HTTP_ERROR", str(exc.detail), exc.status_code, request_id=request_id)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
	request_id = getattr(request.state, "request_id", None)
	return _error_envelope("VALIDATION_ERROR", "Request validation failed", 422, request_id=request_id)


class RequestContextMiddleware(BaseHTTPMiddleware):
	async def dispatch(self, request, call_next):
		started = time.time()
		request.state.request_id = str(uuid.uuid4())
		request.state.org_id = None
		log_tokens = None
		auth_header = request.headers.get("authorization", "")
		if auth_header.lower().startswith("bearer "):
			token = auth_header.split(" ", 1)[1].strip()
			try:
				payload = decode_access_token(token)
				request.state.org_id = payload.get("org_id")
			except Exception:
				if request.url.path.startswith("/api") or request.url.path.startswith("/scans"):
					return _error_envelope(
						"AUTH_TOKEN_INVALID",
						"Authentication token is invalid or expired.",
						401,
						request_id=request.state.request_id,
					)
		log_tokens = set_log_context(request_id=request.state.request_id, org_id=str(request.state.org_id) if request.state.org_id else None)
		try:
			response = await call_next(request)

			# Enforce a consistent success envelope for JSON API responses.
			if (
				response.status_code < 400
				and response.media_type == "application/json"
				and request.url.path not in {"/openapi.json", "/docs", "/redoc"}
			):
				chunks = []
				async for chunk in response.body_iterator:
					chunks.append(chunk)
				raw = b"".join(chunks)
				try:
					payload = json.loads(raw.decode("utf-8")) if raw else None
				except Exception:
					payload = None

				already_enveloped = isinstance(payload, dict) and {"data", "error", "meta"}.issubset(payload.keys())
				headers = dict(response.headers)
				headers.pop("content-length", None)
				headers["X-Request-ID"] = request.state.request_id
				if already_enveloped:
					meta = payload.get("meta") if isinstance(payload.get("meta"), dict) else {}
					meta["request_id"] = request.state.request_id
					payload["meta"] = meta
					response = JSONResponse(
						status_code=response.status_code,
						content=payload,
						headers=headers,
					)
				else:
					response = JSONResponse(
						status_code=response.status_code,
						content={
							"data": payload,
							"error": None,
							"meta": {"request_id": request.state.request_id},
						},
						headers=headers,
					)
			else:
				response.headers["X-Request-ID"] = request.state.request_id
			latency_ms = round((time.time() - started) * 1000, 2)
			logger.info(
				"http_request",
				extra={
					"extra_payload": {
						"path": request.url.path,
						"method": request.method,
						"status_code": response.status_code,
						"latency_ms": latency_ms,
					}
				},
			)
			return response
		finally:
			reset_log_context(log_tokens)


app.add_middleware(RequestContextMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(routes_auth.router, prefix="/auth")
app.include_router(routes_scan.router, prefix="/scans")
app.include_router(routes_intel.router, prefix="/api")
app.include_router(routes_detection.router, prefix="/api")
app.include_router(routes_dasboard.router, prefix="/api")
app.include_router(routes_search.router, prefix="/api")
app.include_router(routes_auth.router, prefix="/api/v1/auth")
app.include_router(routes_scan.router, prefix="/api/v1/scans")
app.include_router(routes_intel.router, prefix="/api/v1")
app.include_router(routes_detection.router, prefix="/api/v1")
app.include_router(routes_dasboard.router, prefix="/api/v1")
app.include_router(routes_search.router, prefix="/api/v1")


# Keep interactive docs focused on the core analyst flow.
CORE_DOC_PATHS = {
	"/auth/register",
	"/auth/login",
	"/scans/scan",
	"/scans/scan/{scan_id}",
	"/scans/scan/file",
	"/scans/scan/file/{file_scan_id}",
}


def custom_openapi():
	if app.openapi_schema:
		return app.openapi_schema

	full_schema = get_openapi(
		title=app.title,
		version="1.0.0",
		description=(
			"Core SOC workflow docs: register, login, authorize, submit URL/file scans, "
			"then retrieve scan results."
		),
		routes=app.routes,
	)

	filtered_paths = {}
	for path, path_data in full_schema.get("paths", {}).items():
		if path in CORE_DOC_PATHS:
			filtered_paths[path] = path_data
	full_schema["paths"] = filtered_paths

	app.openapi_schema = full_schema
	return app.openapi_schema


app.openapi = custom_openapi