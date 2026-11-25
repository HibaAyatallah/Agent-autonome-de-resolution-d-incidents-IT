import unittest
from uuid import uuid4

from incident_response.agents.models import FindingSeverity
from incident_response.reasoning.models import (
    CauseHypothesis,
    ConfidenceLevel,
    ReasoningAssessment,
    ReasoningEvidence,
    ReasoningStatus,
)
from incident_response.remediation.models import (
    ApprovalStatus,
    ExecutionStatus,
    ProposedActionType,
    ProposedRemediationAction,
    ProposedRemediationPlan,
    RemediationPlanStatus,
    ResourceReviewParameters,
    RiskLevel,
)
from incident_response.remediation.planner import RemediationPlanner
from pydantic import ValidationError


class RemediationPlannerTests(unittest.TestCase):
    def make_hypothesis(self, hypothesis_id: str, evidence: list[ReasoningEvidence]):
        return CauseHypothesis(
            hypothesis_id=hypothesis_id,
            title="Cause possible",
            explanation="Signal compatible avec cette hypothèse.",
            confidence=ConfidenceLevel.MODERATE,
            confidence_rationale="Observation directe, causalité non confirmée.",
            supporting_evidence=evidence,
            limitations=["Corrélation temporelle non établie."],
        )

    def test_direct_resource_evidence_proposes_low_risk_action_pending_approval(self) -> None:
        evidence = [
            ReasoningEvidence(
                agent_id="system",
                finding_code="resource_cpu_high",
                finding_title="CPU élevée",
                severity=FindingSeverity.CRITICAL,
                source="host_metrics",
                field="cpu_percent",
                value=97,
                unit="percent",
            ),
            ReasoningEvidence(
                agent_id="system",
                finding_code="resource_cpu_high",
                finding_title="CPU élevée",
                severity=FindingSeverity.CRITICAL,
                source="monitoring_rule",
                field="threshold_percent",
                value=95,
                unit="percent",
            ),
        ]
        reasoning = ReasoningAssessment(
            status=ReasoningStatus.ANALYZED,
            summary="Hypothèse de pression CPU.",
            hypotheses=[self.make_hypothesis("system_resource_pressure", evidence)],
        )

        plan = RemediationPlanner().build(uuid4(), reasoning)

        self.assertEqual(plan.status, RemediationPlanStatus.PENDING_APPROVAL)
        self.assertEqual(plan.approval_status, ApprovalStatus.PENDING_APPROVAL)
        self.assertTrue(plan.approval_required)
        self.assertEqual(plan.execution_status, ExecutionStatus.NOT_EXECUTED)
        self.assertEqual(len(plan.actions), 1)
        action = plan.actions[0]
        self.assertEqual(action.action_type, ProposedActionType.REVIEW_RESOURCE_METRICS)
        self.assertEqual(action.hypothesis_id, "system_resource_pressure")
        self.assertEqual(action.risk_level, RiskLevel.LOW)
        self.assertTrue(action.approval_required)
        self.assertEqual(len(action.evidence), 2)
        self.assertEqual(action.parameters.observed_percent, 97)
        self.assertIn("corréler", action.description)

    def test_dataset_ssh_alert_alone_blocks_remediation_recommendation(self) -> None:
        evidence = [
            ReasoningEvidence(
                agent_id="security",
                finding_code="security_ssh_failure_alerts",
                finding_title="Alerte SSH",
                severity=FindingSeverity.WARNING,
                source="dataset_alerts",
                field="ssh_alert_event_count",
                value=282,
            )
        ]
        reasoning = ReasoningAssessment(
            status=ReasoningStatus.ANALYZED,
            summary="Signal SSH historique.",
            hypotheses=[self.make_hypothesis("ssh_authentication_signal", evidence)],
        )

        plan = RemediationPlanner().build(uuid4(), reasoning)

        self.assertEqual(plan.status, RemediationPlanStatus.INSUFFICIENT_EVIDENCE)
        self.assertEqual(plan.approval_status, ApprovalStatus.NOT_REQUIRED)
        self.assertFalse(plan.approval_required)
        self.assertEqual(plan.actions, [])
        self.assertEqual(plan.execution_status, ExecutionStatus.NOT_EXECUTED)
        self.assertIn("lignes d'authentification brutes", plan.blocked_recommendations[0].reason)

    def test_insufficient_diagnostic_data_returns_empty_plan(self) -> None:
        reasoning = ReasoningAssessment(
            status=ReasoningStatus.INSUFFICIENT_DATA,
            summary="Aucune hypothèse disponible.",
            data_gaps=["Métriques hôte indisponibles."],
        )

        plan = RemediationPlanner().build(uuid4(), reasoning)

        self.assertEqual(plan.status, RemediationPlanStatus.INSUFFICIENT_EVIDENCE)
        self.assertEqual(plan.actions, [])
        self.assertEqual(plan.execution_status, ExecutionStatus.NOT_EXECUTED)

    def test_action_allowlist_rejects_shell_and_unlisted_parameters(self) -> None:
        with self.assertRaises(ValidationError):
            ProposedRemediationAction.model_validate(
                {
                    "action_id": "arbitrary",
                    "action_type": "execute_shell",
                    "title": "Run command",
                    "description": "Run arbitrary command",
                    "rationale": "Untrusted",
                    "parameters": {"parameter_type": "resource_review", "command": "whoami"},
                    "evidence": [],
                    "risk_level": "high",
                    "risk_explanation": "Unknown",
                }
            )

        with self.assertRaises(ValidationError):
            ResourceReviewParameters.model_validate(
                {
                    "parameter_type": "resource_review",
                    "metric": "cpu",
                    "observed_percent": 97,
                    "threshold_percent": 95,
                    "command": "whoami",
                }
            )

    def test_plan_cannot_claim_approval_or_execution(self) -> None:
        with self.assertRaises(ValidationError):
            ProposedRemediationPlan.model_validate(
                {
                    "incident_id": str(uuid4()),
                    "status": "pending_approval",
                    "summary": "Invalid state",
                    "approval_status": "approved",
                    "approval_required": True,
                    "execution_status": "executed",
                    "actions": [],
                }
            )


if __name__ == "__main__":
    unittest.main()
