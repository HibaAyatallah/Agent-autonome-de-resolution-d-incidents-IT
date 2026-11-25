from pydantic import BaseModel, Field

from incident_response.remediation.models import ProposedRemediationPlan


class IncidentHistoryItem(BaseModel):
    incident_id: str
    created_at: str
    origin: str
    description: str
    categories: list[str] = Field(default_factory=list)
    priority: str
    workflow_status: str
    diagnosis_summary: str
    findings: list[dict] = Field(default_factory=list)
    hypotheses: list[dict] = Field(default_factory=list)
    proposed_remediation: ProposedRemediationPlan | None = None
    final_status: str | None = None


class IncidentHistoryResponse(BaseModel):
    items: list[IncidentHistoryItem]
    total: int
    limit: int
    offset: int
