from threading import Lock

from fastapi import APIRouter, HTTPException, Query

from incident_response.memory.repository import IncidentMemoryRepository
from incident_response.memory.schemas import IncidentHistoryResponse
from incident_response.orchestration.models import IncidentAssessment, IncidentInput
from incident_response.orchestration.workflow import IncidentWorkflow

router = APIRouter()
workflow: IncidentWorkflow | None = None
workflow_lock = Lock()


def get_workflow() -> IncidentWorkflow:
    global workflow
    if workflow is None:
        with workflow_lock:
            if workflow is None:
                workflow = IncidentWorkflow(memory_repository=IncidentMemoryRepository())
    return workflow


@router.post("/diagnose", response_model=IncidentAssessment, tags=["incidents"])
def diagnose_incident(incident: IncidentInput) -> IncidentAssessment:
    return get_workflow().run(incident)


@router.get("/history", response_model=IncidentHistoryResponse, tags=["incidents"])
def list_incident_history(
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
    q: str | None = Query(default=None, max_length=200),
    priority: str | None = Query(default=None, pattern="^(P1|P2|P3|P4|UNASSESSED)$"),
    category: str | None = Query(default=None, max_length=64),
) -> IncidentHistoryResponse:
    try:
        repository = get_workflow().memory_repository
        if repository is None:
            return IncidentHistoryResponse(items=[], total=0, limit=limit, offset=offset)
        return repository.list_history(
            limit=limit,
            offset=offset,
            query=q,
            priority=priority,
            category=category,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
