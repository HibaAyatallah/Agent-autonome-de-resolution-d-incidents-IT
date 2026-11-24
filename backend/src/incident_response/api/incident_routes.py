from fastapi import APIRouter

from incident_response.orchestration.models import IncidentAssessment, IncidentInput
from incident_response.orchestration.workflow import IncidentWorkflow

router = APIRouter()
workflow = IncidentWorkflow()


@router.post("/diagnose", response_model=IncidentAssessment, tags=["incidents"])
def diagnose_incident(incident: IncidentInput) -> IncidentAssessment:
    return workflow.run(incident)
