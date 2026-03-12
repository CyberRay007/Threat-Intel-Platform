from fastapi import FastAPI
from app.api import routes_auth, routes_scan, routes_intel, routes_detection

app = FastAPI(title="Threat Intel Platform")

app.include_router(routes_auth.router, prefix="/auth")
app.include_router(routes_scan.router, prefix="/scans")
app.include_router(routes_intel.router, prefix="/api")
app.include_router(routes_detection.router, prefix="/api")