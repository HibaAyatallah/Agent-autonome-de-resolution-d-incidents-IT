import hmac
from datetime import UTC, datetime
from threading import Lock
from uuid import UUID

from fastapi import APIRouter, Header, HTTPException, Query

from incident_response.memory.repository import IncidentMemoryRepository
from incident_response.memory.schemas import IncidentHistoryResponse
from incident_response.orchestration.models import IncidentAssessment, IncidentInput
from incident_response.orchestration.workflow import IncidentWorkflow
from incident_response.remediation.models import (
    ApprovalStatus,
    ProposedRemediationPlan,
    RemediationDecision,
)
from incident_response.remediation.settings import RemediationApprovalSettings

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


@router.get(
    "/{incident_id}/remediation-plan",
    response_model=ProposedRemediationPlan,
    tags=["incidents"],
)
def get_incident_remediation_plan(incident_id: UUID) -> ProposedRemediationPlan:
    repository = get_workflow().memory_repository
    if repository is None:
        raise HTTPException(status_code=503, detail="Incident memory is not configured.")
    plan = repository.get_remediation_plan(str(incident_id))
    if plan is None:
        raise HTTPException(
            status_code=404, detail="No remediation plan is stored for this incident."
        )
    return plan


@router.post(
    "/{incident_id}/remediation-plan/decision",
    response_model=ProposedRemediationPlan,
    tags=["incidents"],
)
def decide_incident_remediation_plan(
    incident_id: UUID,
    request: RemediationDecision,
    approval_token: str | None = Header(default=None, alias="X-Approval-Token"),
) -> ProposedRemediationPlan:
    settings = RemediationApprovalSettings()
    expected_token = settings.token.get_secret_value()
    if len(expected_token) < 32 or not settings.reviewer_id:
        raise HTTPException(
            status_code=503,
            detail="Human decision recording is disabled until approval credentials are configured.",
        )
    if approval_token is None or not hmac.compare_digest(approval_token, expected_token):
        raise HTTPException(status_code=401, detail="Invalid approval credentials.")

    repository = get_workflow().memory_repository
    if repository is None:
        raise HTTPException(status_code=503, detail="Incident memory is not configured.")
    decision = ApprovalStatus.APPROVED if request.decision == "approve" else ApprovalStatus.REJECTED
    try:
        plan = repository.record_remediation_decision(
            str(incident_id),
            decision=decision,
            reviewer_id=settings.reviewer_id,
            note=request.note,
            decided_at=datetime.now(UTC),
        )
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    if plan is None:
        raise HTTPException(
            status_code=404, detail="No remediation plan is stored for this incident."
        )
    return plan


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
