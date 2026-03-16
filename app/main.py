from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi
from app.api import routes_auth, routes_scan, routes_intel, routes_detection, routes_dasboard

app = FastAPI(title="Threat Intel Platform")

app.include_router(routes_auth.router, prefix="/auth")
app.include_router(routes_scan.router, prefix="/scans")
app.include_router(routes_intel.router, prefix="/api")
app.include_router(routes_detection.router, prefix="/api")
app.include_router(routes_dasboard.router, prefix="/api")


# Keep interactive docs focused on the core analyst flow.
CORE_DOC_PATHS = {
	"/auth/register",
	"/auth/login",
	"/scans/scan",
	"/scans/scan/{scan_id}",
	"/scans/scan/file",
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