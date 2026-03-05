from fastapi import FastAPI
from app.api import routes_auth, routes_scan

app = FastAPI(title="Threat Intel Platform")

app.include_router(routes_auth.router, prefix="/auth")
app.include_router(routes_scan.router, prefix="/scans")