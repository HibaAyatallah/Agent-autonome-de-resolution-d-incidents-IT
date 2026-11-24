import unittest
from unittest.mock import patch

from incident_response.agents.coordinator import CoordinatorAgent
from incident_response.agents.models import AgentStatus
from incident_response.api.incident_routes import diagnose_incident
from incident_response.main import create_app
from incident_response.monitoring.models import SystemMetrics
from incident_response.monitoring.simulation import simulate_snapshot
from incident_response.orchestration.models import (
    IncidentInput,
    IncidentOrigin,
    IncidentPriority,
    WorkflowStatus,
)
from incident_response.orchestration.workflow import IncidentWorkflow
from incident_response.reasoning.models import ConfidenceLevel, ReasoningStatus


class OrchestrationTests(unittest.TestCase):
    def test_workflow_runs_agents_and_aggregates_structured_reports(self) -> None:
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
            origin=IncidentOrigin.DATASET,
            description="Alerte d'échecs SSH et surcharge CPU",
            alert_records=[
                {
                    "source_type": "log",
                    "alert_name": "SSH Authentication Failure",
                    "summary": "Failure alert from source",
                    "source_record_id": "Datos finales:2",
                },
                {
                    "source_type": "usage",
                    "alert_name": "Network Usage",
                    "summary": "Network usage exceeded threshold.",
                    "source_record_id": "Datos finales:8",
                },
            ],
            monitoring_snapshot=snapshot,
        )

        assessment = IncidentWorkflow().run(incident)

        self.assertEqual(assessment.status, WorkflowStatus.DIAGNOSED)
        self.assertEqual(assessment.priority, IncidentPriority.P1)
        self.assertEqual(assessment.categories, ["logs", "network", "security", "system"])
        self.assertEqual(set(assessment.agent_reports), {"logs", "system", "network", "security"})
        self.assertEqual(assessment.agent_reports["logs"].status, AgentStatus.OK)
        self.assertEqual(assessment.agent_reports["system"].status, AgentStatus.OK)
        self.assertEqual(assessment.agent_reports["security"].status, AgentStatus.OK)
        self.assertEqual(assessment.agent_reports["network"].status, AgentStatus.OK)
        self.assertEqual(assessment.events[0].event_type, "incident_received")
        self.assertIn("Aucune cause racine", assessment.summary)
        self.assertEqual(assessment.reasoning.status, ReasoningStatus.ANALYZED)
        self.assertTrue(assessment.reasoning.hypotheses)
        self.assertIn("reasoning_completed", [event.event_type for event in assessment.events])

    def test_diagnose_api_contract_and_route_handler(self) -> None:
        app = create_app()
        self.assertIn("/api/v1/incidents/diagnose", app.openapi()["paths"])
        request = IncidentInput(description="Incident utilisateur")
        assessment = diagnose_incident(request)
        self.assertEqual(assessment.incident_id, request.incident_id)
        self.assertEqual(assessment.status, WorkflowStatus.DIAGNOSED)
        self.assertEqual(assessment.reasoning.status, ReasoningStatus.INSUFFICIENT_DATA)

    def test_missing_diagnostics_are_reported_as_no_data(self) -> None:
        assessment = IncidentWorkflow().run(IncidentInput(description="Serveur lent"))
        self.assertEqual(assessment.status, WorkflowStatus.DIAGNOSED)
        self.assertEqual(assessment.priority, IncidentPriority.UNASSESSED)
        self.assertEqual(assessment.categories, ["general"])
        self.assertTrue(all(r.status == AgentStatus.NO_DATA for r in assessment.agent_reports.values()))

    def test_normal_system_snapshot_gets_provisional_p3(self) -> None:
        snapshot = simulate_snapshot(
            SystemMetrics(
                hostname="test-host",
                cpu_percent=20,
                ram_percent=40,
                ram_available_bytes=1000,
                disk_percent=50,
                disk_free_bytes=2000,
            )
        )
        assessment = IncidentWorkflow().run(
            IncidentInput(description="Contrôle planifié", monitoring_snapshot=snapshot)
        )
        self.assertEqual(assessment.priority, IncidentPriority.P3)
        self.assertEqual(assessment.categories, ["system"])

    def test_usage_alerts_are_not_misclassified_as_log_alerts(self) -> None:
        assessment = IncidentWorkflow().run(
            IncidentInput(
                origin=IncidentOrigin.DATASET,
                description="Dépassement du seuil réseau",
                alert_records=[
                    {
                        "source_type": "usage",
                        "alert_name": "Network Usage",
                        "summary": "Network usage above threshold.",
                    }
                ],
            )
        )
        self.assertEqual(assessment.categories, ["network"])
        self.assertEqual(assessment.agent_reports["logs"].status, AgentStatus.NO_DATA)
        self.assertEqual(assessment.agent_reports["network"].status, AgentStatus.OK)
        self.assertEqual(assessment.priority, IncidentPriority.P2)
        hypothesis = assessment.reasoning.hypotheses[0]
        self.assertEqual(hypothesis.hypothesis_id, "network_usage_alert")
        self.assertEqual(hypothesis.confidence, ConfidenceLevel.LOW)
        self.assertEqual(hypothesis.supporting_evidence[0].source, "dataset_alerts")

    def test_agent_exception_is_retried_then_isolated_from_other_agents(self) -> None:
        coordinator = CoordinatorAgent(max_agent_attempts=2)
        real_analyze = coordinator.logs_agent.analyze
        calls = 0

        def fail_once(records):
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("temporary issue")
            return real_analyze(records)

        incident = IncidentInput(
            description="Log alert",
            alert_records=[{"source_type": "log", "alert_name": "DatasourceNoData"}],
        )
        with patch.object(coordinator.logs_agent, "analyze", side_effect=fail_once):
            assessment = coordinator.run(incident)

        self.assertEqual(calls, 2)
        self.assertEqual(assessment.status, WorkflowStatus.DIAGNOSED)
        self.assertEqual(assessment.agent_reports["logs"].status, AgentStatus.OK)
        self.assertIn("agent_retried", [event.event_type for event in assessment.events])

    def test_persistent_agent_failure_marks_assessment_degraded(self) -> None:
        coordinator = CoordinatorAgent(max_agent_attempts=2)
        incident = IncidentInput(description="Log alert")
        with patch.object(coordinator.logs_agent, "analyze", side_effect=RuntimeError("failure")):
            assessment = coordinator.run(incident)
        self.assertEqual(assessment.status, WorkflowStatus.DEGRADED)
        self.assertEqual(assessment.agent_reports["logs"].status, AgentStatus.ERROR)
        self.assertIn("logs", assessment.summary)

    def test_agent_timeout_marks_workflow_degraded(self) -> None:
        coordinator = CoordinatorAgent(agent_timeout_seconds=0.1, max_agent_attempts=1)

        def slow_agent(records):
            import time

            time.sleep(0.2)
            return coordinator.logs_agent.__class__().analyze(records)

        incident = IncidentInput(description="Slow agent test")
        with patch.object(coordinator.logs_agent, "analyze", side_effect=slow_agent):
            assessment = coordinator.run(incident)

        self.assertEqual(assessment.status, WorkflowStatus.DEGRADED)
        self.assertEqual(assessment.agent_reports["logs"].status, AgentStatus.ERROR)
        self.assertIn("agent_timeout", [event.event_type for event in assessment.events])

    def test_workflow_settings_are_read_from_environment(self) -> None:
        with patch.dict(
            "os.environ",
            {"AGENT_TIMEOUT_SECONDS": "3", "MAX_AGENT_ATTEMPTS": "1"},
        ):
            coordinator = CoordinatorAgent()
        self.assertEqual(coordinator.agent_timeout_seconds, 3)
        self.assertEqual(coordinator.max_agent_attempts, 1)


if __name__ == "__main__":
    unittest.main()
