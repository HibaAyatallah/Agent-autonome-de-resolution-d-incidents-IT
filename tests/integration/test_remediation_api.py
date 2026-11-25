import unittest
from tempfile import TemporaryDirectory
from unittest.mock import patch

from incident_response.api.incident_routes import (
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
    ExecutionStatus,
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


if __name__ == "__main__":
    unittest.main()
