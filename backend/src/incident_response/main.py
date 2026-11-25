from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from incident_response.api.routes import router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AI IT Incident Response",
        description="Triage et diagnostic contrôlé d'incidents IT.",
        version="0.1.0",
    )
    app.include_router(router, prefix="/api/v1")
    dashboard_dir = Path(__file__).resolve().parents[3] / "frontend"
    if dashboard_dir.is_dir():
        app.mount("/dashboard", StaticFiles(directory=dashboard_dir, html=True), name="dashboard")
    return app


app = create_app()
