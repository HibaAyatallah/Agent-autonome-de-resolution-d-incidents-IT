from fastapi import APIRouter, HTTPException

from incident_response.monitoring.models import MonitoringSnapshot
from incident_response.monitoring.service import collect_snapshot

router = APIRouter()


@router.get("/snapshot", response_model=MonitoringSnapshot)
def get_monitoring_snapshot() -> MonitoringSnapshot:
    try:
        return collect_snapshot()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=500, detail="Invalid monitoring configuration.") from exc
