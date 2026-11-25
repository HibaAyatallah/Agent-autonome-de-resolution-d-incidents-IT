import json
import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi import HTTPException
from incident_response.api.incident_routes import (
    decide_incident_remediation_plan,
    diagnose_incident,
    get_incident_remediation_plan,
    list_incident_history,
)
from incident_response.main import create_app
from incident_response.memory.repository import IncidentMemoryRepository
from incident_response.monitoring.models import SystemMetrics
from incident_response.monitoring.simulation import simulate_snapshot
from incident_response.orchestration.models import IncidentInput, IncidentOrigin
from incident_response.orchestration.workflow import IncidentWorkflow
from incident_response.remediation.models import (
    ApprovalStatus,
    ExecutionStatus,
    RemediationDecision,
    RemediationPlanStatus,
)


class RemediationApiTests(unittest.TestCase):
    def repository(self, directory: str) -> IncidentMemoryRepository:
        return IncidentMemoryRepository(database_url=f"sqlite:///{directory}/incidents.sqlite")

    def test_diagnosis_returns_and_persists_review_plan_for_direct_metric_evidence(self) -> None:
        with TemporaryDirectory() as directory, self.repository(directory) as repository:
            workflow = IncidentWorkflow(memory_repository=repository)
            snapshot = simulate_snapshot(
                SystemMetrics(
                    hostname="test-host",
                    cpu_percent=97,
                    ram_percent=40,
                    ram_available_bytes=1000,
                    disk_percent=50,
                    disk_free_bytes=2000,
                )
            )
            incident = IncidentInput(
                origin=IncidentOrigin.MONITORING,
                description="CPU usage alert",
                monitoring_snapshot=snapshot,
            )

            with patch("incident_response.api.incident_routes.get_workflow", return_value=workflow):
                assessment = diagnose_incident(incident)
                stored_plan = get_incident_remediation_plan(incident.incident_id)
                history = list_incident_history(
                    limit=20,
                    offset=0,
                    q=None,
                    priority=None,
                    category=None,
                )

            self.assertEqual(
                assessment.remediation_plan.status, RemediationPlanStatus.PENDING_APPROVAL
            )
            self.assertEqual(
                assessment.remediation_plan.execution_status, ExecutionStatus.NOT_EXECUTED
            )
            self.assertTrue(assessment.remediation_plan.actions[0].approval_required)
            self.assertIn(
                "remediation_plan_proposed",
                [event.event_type for event in assessment.events],
            )
            self.assertEqual(stored_plan.plan_id, assessment.remediation_plan.plan_id)
            self.assertEqual(
                history.items[0].proposed_remediation.plan_id,
                assessment.remediation_plan.plan_id,
            )
            self.assertIn(
                "/api/v1/incidents/{incident_id}/remediation-plan", create_app().openapi()["paths"]
            )

    def test_dataset_alert_only_returns_insufficient_evidence_and_no_action(self) -> None:
        with TemporaryDirectory() as directory, self.repository(directory) as repository:
            workflow = IncidentWorkflow(memory_repository=repository)
            incident = IncidentInput(
                origin=IncidentOrigin.DATASET,
                description="Échecs SSH observés par la source",
                alert_records=[
                    {
                        "source_type": "log",
                        "alert_name": "SSH Authentication Failure",
                        "source_record_id": "Datos finales:2",
                    }
                ],
            )

            with patch("incident_response.api.incident_routes.get_workflow", return_value=workflow):
                assessment = diagnose_incident(incident)
                stored_plan = get_incident_remediation_plan(incident.incident_id)

            self.assertEqual(
                assessment.remediation_plan.status, RemediationPlanStatus.INSUFFICIENT_EVIDENCE
            )
            self.assertEqual(assessment.remediation_plan.actions, [])
            self.assertEqual(
                assessment.remediation_plan.execution_status, ExecutionStatus.NOT_EXECUTED
            )
            self.assertEqual(stored_plan.actions, [])

    def test_approval_is_authenticated_persisted_and_never_executes(self) -> None:
        with TemporaryDirectory() as directory, self.repository(directory) as repository:
            workflow = IncidentWorkflow(memory_repository=repository)
            incident = IncidentInput(
                origin=IncidentOrigin.MONITORING,
                description="CPU usage alert",
                monitoring_snapshot=simulate_snapshot(
                    SystemMetrics(
                        hostname="test-host",
                        cpu_percent=97,
                        ram_percent=40,
                        ram_available_bytes=1000,
                        disk_percent=50,
                        disk_free_bytes=2000,
                    )
                ),
            )
            with patch("incident_response.api.incident_routes.get_workflow", return_value=workflow):
                assessment = diagnose_incident(incident)
                with patch.dict(
                    "os.environ",
                    {
                        "REMEDIATION_APPROVAL_TOKEN": "private-test-token-that-is-at-least-32",
                        "REMEDIATION_APPROVER_ID": "on-call-reviewer",
                    },
                ):
                    decided = decide_incident_remediation_plan(
                        incident.incident_id,
                        RemediationDecision(decision="approve", note="Reviewed evidence"),
                        approval_token="private-test-token-that-is-at-least-32",
                    )
                loaded = get_incident_remediation_plan(incident.incident_id)

                self.assertEqual(decided.approval_status, ApprovalStatus.APPROVED)
                self.assertEqual(decided.approval_decided_by, "on-call-reviewer")
                self.assertIsNotNone(decided.approval_decided_at)
                self.assertEqual(decided.execution_status, ExecutionStatus.NOT_EXECUTED)
                self.assertEqual(loaded.approval_status, ApprovalStatus.APPROVED)
                self.assertEqual(
                    assessment.remediation_plan.execution_status, ExecutionStatus.NOT_EXECUTED
                )
                with (
                    patch.dict(
                        "os.environ",
                        {
                            "REMEDIATION_APPROVAL_TOKEN": "private-test-token-that-is-at-least-32",
                            "REMEDIATION_APPROVER_ID": "on-call-reviewer",
                        },
                    ),
                    self.assertRaises(HTTPException) as caught,
                ):
                    decide_incident_remediation_plan(
                        incident.incident_id,
                        RemediationDecision(decision="reject"),
                        approval_token="private-test-token-that-is-at-least-32",
                    )
                self.assertEqual(caught.exception.status_code, 409)

    def test_decision_endpoint_is_disabled_without_credentials(self) -> None:
        with patch("incident_response.api.incident_routes.RemediationApprovalSettings") as settings:
            settings.return_value.token.get_secret_value.return_value = ""
            settings.return_value.reviewer_id = ""
            settings.return_value.reviewers = []
            with self.assertRaises(HTTPException) as caught:
                decide_incident_remediation_plan(
                    "00000000-0000-0000-0000-000000000001",
                    RemediationDecision(decision="approve"),
                )
        self.assertEqual(caught.exception.status_code, 503)

    def test_individual_reviewer_token_sets_server_identity(self) -> None:
        token_a = "reviewer-a-token-with-at-least-32-characters"
        token_b = "reviewer-b-token-with-at-least-32-characters"
        reviewers = [
            {"reviewer_id": "reviewer-a", "token": token_a},
            {"reviewer_id": "reviewer-b", "token": token_b},
        ]
        with TemporaryDirectory() as directory, self.repository(directory) as repository:
            workflow = IncidentWorkflow(memory_repository=repository)
            incident = IncidentInput(
                origin=IncidentOrigin.MONITORING,
                description="CPU usage alert",
                monitoring_snapshot=simulate_snapshot(
                    SystemMetrics(
                        hostname="test-host",
                        cpu_percent=97,
                        ram_percent=40,
                        ram_available_bytes=1000,
                        disk_percent=50,
                        disk_free_bytes=2000,
                    )
                ),
            )
            with patch("incident_response.api.incident_routes.get_workflow", return_value=workflow):
                diagnose_incident(incident)
                with patch.dict(
                    "os.environ",
                    {"REMEDIATION_REVIEWERS": json.dumps(reviewers)},
                ):
                    with self.assertRaises(HTTPException) as invalid:
                        decide_incident_remediation_plan(
                            incident.incident_id,
                            RemediationDecision(decision="approve"),
                            approval_token="unknown-reviewer-token",
                        )
                    self.assertEqual(invalid.exception.status_code, 401)
                    decision = decide_incident_remediation_plan(
                        incident.incident_id,
                        RemediationDecision(decision="approve"),
                        approval_token=token_b,
                    )

            self.assertEqual(decision.approval_decided_by, "reviewer-b")
            self.assertEqual(decision.execution_status, ExecutionStatus.NOT_EXECUTED)

    def test_dashboard_renders_plan_fields_using_text_nodes(self) -> None:
        from pathlib import Path

        dashboard = Path(__file__).parents[2] / "frontend" / "index.html"
        source = dashboard.read_text(encoding="utf-8")
        self.assertIn("item.proposed_remediation", source)
        self.assertIn("action.evidence", source)
        self.assertIn("action.parameters", source)
        self.assertIn("action.hypothesis_id", source)
        self.assertIn("action.risk_level", source)
        self.assertIn("action.approval_required", source)
        self.assertIn("plan.execution_status", source)
        self.assertIn("el.textContent = text", source)
        self.assertIn("X-Approval-Token", source)
        self.assertIn("submitDecision(incidentId, decision, controls)", source)
        self.assertNotIn("localStorage", source)
        self.assertNotIn("sessionStorage", source)


if __name__ == "__main__":
    unittest.main()
