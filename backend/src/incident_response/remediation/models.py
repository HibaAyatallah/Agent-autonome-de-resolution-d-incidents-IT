from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from incident_response.reasoning.models import ReasoningEvidence


class RemediationPlanStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class ApprovalStatus(StrEnum):
    PENDING_APPROVAL = "pending_approval"
    NOT_REQUIRED = "not_required"


class ExecutionStatus(StrEnum):
    NOT_EXECUTED = "not_executed"


class RiskLevel(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ProposedActionType(StrEnum):
    REVIEW_RESOURCE_METRICS = "review_resource_metrics"
    VERIFY_NETWORK_REACHABILITY = "verify_network_reachability"
    REVIEW_NETWORK_LATENCY = "review_network_latency"


class ResourceMetric(StrEnum):
    CPU = "cpu"
    RAM = "ram"
    DISK = "disk"


class ResourceReviewParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    parameter_type: Literal["resource_review"] = "resource_review"
    metric: ResourceMetric
    observed_percent: float = Field(ge=0, le=100)
    threshold_percent: float = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_observation_exceeds_threshold(self) -> ResourceReviewParameters:
        if self.observed_percent <= self.threshold_percent:
            raise ValueError("A resource review requires an observation above its threshold.")
        return self


class NetworkReachabilityParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    parameter_type: Literal["network_reachability"] = "network_reachability"
    target_name: str = Field(min_length=1, max_length=100)
    reachable: Literal[False]


class NetworkLatencyParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    parameter_type: Literal["network_latency"] = "network_latency"
    target_name: str = Field(min_length=1, max_length=100)
    latency_ms: float = Field(ge=0)


AllowedActionParameters = Annotated[
    ResourceReviewParameters | NetworkReachabilityParameters | NetworkLatencyParameters,
    Field(discriminator="parameter_type"),
]


class ProposedRemediationAction(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: str
    hypothesis_id: str
    action_type: ProposedActionType
    title: str
    description: str
    rationale: str
    parameters: AllowedActionParameters
    evidence: list[ReasoningEvidence] = Field(min_length=1)
    risk_level: RiskLevel
    risk_explanation: str
    approval_required: Literal[True] = True
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_action_parameters(self) -> ProposedRemediationAction:
        expected = {
            ProposedActionType.REVIEW_RESOURCE_METRICS: "resource_review",
            ProposedActionType.VERIFY_NETWORK_REACHABILITY: "network_reachability",
            ProposedActionType.REVIEW_NETWORK_LATENCY: "network_latency",
        }[self.action_type]
        if self.parameters.parameter_type != expected:
            raise ValueError("Action type does not match its allow-listed parameter model.")
        if self.risk_level != RiskLevel.LOW:
            raise ValueError("This phase only proposes low-risk, read-only recommendations.")
        return self


class BlockedRecommendation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    hypothesis_id: str
    reason: str
    evidence: list[ReasoningEvidence] = Field(default_factory=list)


class ProposedRemediationPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    plan_id: UUID = Field(default_factory=uuid4)
    incident_id: UUID
    status: RemediationPlanStatus
    summary: str
    approval_status: ApprovalStatus
    approval_required: bool
    execution_status: Literal[ExecutionStatus.NOT_EXECUTED] = ExecutionStatus.NOT_EXECUTED
    actions: list[ProposedRemediationAction] = Field(default_factory=list)
    blocked_recommendations: list[BlockedRecommendation] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_plan_state(self) -> ProposedRemediationPlan:
        has_actions = bool(self.actions)
        expected_status = (
            RemediationPlanStatus.PENDING_APPROVAL
            if has_actions
            else RemediationPlanStatus.INSUFFICIENT_EVIDENCE
        )
        expected_approval = (
            ApprovalStatus.PENDING_APPROVAL if has_actions else ApprovalStatus.NOT_REQUIRED
        )
        if self.status != expected_status or self.approval_status != expected_approval:
            raise ValueError(
                "Plan and approval states must match the presence of proposed actions."
            )
        if self.approval_required != has_actions:
            raise ValueError("Approval is required exactly when the plan contains actions.")
        return self
