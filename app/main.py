from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
import time

from app.core.jwt import decode_access_token
from app.core.logging import logger
from app.api import routes_auth, routes_scan, routes_intel, routes_detection, routes_dasboard

app = FastAPI(title="Threat Intel Platform")


class RequestContextMiddleware(BaseHTTPMiddleware):
	async def dispatch(self, request, call_next):
		started = time.time()
		request.state.org_id = None
		auth_header = request.headers.get("authorization", "")
		if auth_header.lower().startswith("bearer "):
			token = auth_header.split(" ", 1)[1].strip()
			try:
				payload = decode_access_token(token)
				request.state.org_id = payload.get("org_id")
			except Exception:
				if request.url.path.startswith("/api") or request.url.path.startswith("/scans"):
					return JSONResponse(status_code=401, content={"detail": "invalid token"})

		response = await call_next(request)
		latency_ms = round((time.time() - started) * 1000, 2)
		logger.info(
			"http_request",
			extra={
				"extra_payload": {
					"path": request.url.path,
					"method": request.method,
					"status_code": response.status_code,
					"latency_ms": latency_ms,
					"org_id": request.state.org_id,
				}
			},
		)
		return response


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
app.include_router(routes_auth.router, prefix="/api/v1/auth")
app.include_router(routes_scan.router, prefix="/api/v1/scans")
app.include_router(routes_intel.router, prefix="/api/v1")
app.include_router(routes_detection.router, prefix="/api/v1")
app.include_router(routes_dasboard.router, prefix="/api/v1")


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