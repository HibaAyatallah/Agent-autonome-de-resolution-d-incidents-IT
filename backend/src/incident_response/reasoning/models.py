from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

from incident_response.agents.models import FindingSeverity


class ReasoningStatus(StrEnum):
    ANALYZED = "analyzed"
    INSUFFICIENT_DATA = "insufficient_data"


class ConfidenceLevel(StrEnum):
    LOW = "low"
    MODERATE = "moderate"


class ReasoningEvidence(BaseModel):
    agent_id: str
    finding_code: str
    finding_title: str
    severity: FindingSeverity
    source: str
    field: str
    value: str | int | float | bool | None
    unit: str | None = None


class SimilarIncidentReference(BaseModel):
    incident_id: str
    similarity: float = Field(ge=0, le=1)
    categories: list[str] = Field(default_factory=list)
    priority: str
    workflow_status: str
    hypothesis_ids: list[str] = Field(default_factory=list)
    final_status: str | None = None


class CauseHypothesis(BaseModel):
    hypothesis_id: str
    title: str
    explanation: str
    confidence: ConfidenceLevel
    confidence_rationale: str
    supporting_evidence: list[ReasoningEvidence] = Field(default_factory=list)
    counter_evidence: list[ReasoningEvidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    next_diagnostic_checks: list[str] = Field(default_factory=list)


class ReasoningAssessment(BaseModel):
    status: ReasoningStatus
    summary: str
    hypotheses: list[CauseHypothesis] = Field(default_factory=list)
    data_gaps: list[str] = Field(default_factory=list)
    similar_incidents: list[SimilarIncidentReference] = Field(default_factory=list)
