from fastapi import FastAPI

from incident_response.api.routes import router


def create_app() -> FastAPI:
    app = FastAPI(
        title="AI IT Incident Response",
        description="Triage et diagnostic contrôlé d'incidents IT.",
        version="0.1.0",
    )
    app.include_router(router, prefix="/api/v1")
    return app


app = create_app()
