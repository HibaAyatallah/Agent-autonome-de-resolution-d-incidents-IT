from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from incident_response.agents.models import AgentReport
from incident_response.monitoring.models import MonitoringSnapshot
from incident_response.reasoning.models import ReasoningAssessment


class IncidentOrigin(StrEnum):
    USER = "user"
    MONITORING = "monitoring"
    DATASET = "dataset"
    SIMULATION = "simulation"


class IncidentPriority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    P4 = "P4"
    UNASSESSED = "unassessed"


class WorkflowStatus(StrEnum):
    RECEIVED = "received"
    DIAGNOSING = "diagnosing"
    DIAGNOSED = "diagnosed"
    DEGRADED = "degraded"


class IncidentInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    incident_id: UUID = Field(default_factory=uuid4)
    origin: IncidentOrigin = IncidentOrigin.USER
    description: str = Field(min_length=1, max_length=2000)
    alert_records: list[dict[str, object]] = Field(default_factory=list, max_length=5000)
    monitoring_snapshot: MonitoringSnapshot | None = None


class WorkflowEvent(BaseModel):
    event_type: str
    actor: str
    message: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IncidentWorkflowState(BaseModel):
    incident: IncidentInput
    status: WorkflowStatus = WorkflowStatus.RECEIVED
    priority: IncidentPriority = IncidentPriority.UNASSESSED
    categories: list[str] = Field(default_factory=list)
    agent_reports: dict[str, AgentReport] = Field(default_factory=dict)
    events: list[WorkflowEvent] = Field(default_factory=list)


class IncidentAssessment(BaseModel):
    incident_id: UUID
    origin: IncidentOrigin
    status: WorkflowStatus
    priority: IncidentPriority
    categories: list[str]
    description: str
    summary: str
    agent_reports: dict[str, AgentReport]
    reasoning: ReasoningAssessment
    events: list[WorkflowEvent]
