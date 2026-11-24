from fastapi import APIRouter

from incident_response import __version__
from incident_response.api.incident_routes import router as incident_router
from incident_response.api.monitoring_routes import router as monitoring_router
from incident_response.schemas.health import HealthResponse

router = APIRouter()
router.include_router(incident_router, prefix="/incidents")
router.include_router(monitoring_router, prefix="/monitoring", tags=["monitoring"])


@router.get("/health", response_model=HealthResponse, tags=["system"])
def health_check() -> HealthResponse:
    return HealthResponse(version=__version__)
