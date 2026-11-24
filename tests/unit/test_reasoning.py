import unittest

from incident_response.agents.models import (
    AgentFinding,
    AgentReport,
    AgentStatus,
    Evidence,
    FindingSeverity,
)
from incident_response.reasoning.agent import ReasoningAgent
from incident_response.reasoning.models import ConfidenceLevel, ReasoningStatus


def make_report(agent_id: str, code: str, source: str, field: str, value: object) -> AgentReport:
    return AgentReport(
        agent_id=agent_id,
        status=AgentStatus.OK,
        summary="Structured report",
        input_count=1,
        findings=[
            AgentFinding(
                code=code,
                title="Observed alert",
                severity=FindingSeverity.WARNING,
                summary="Alert observed",
                evidence=[Evidence(source=source, field=field, value=value)],
            )
        ],
    )


class ReasoningAgentTests(unittest.TestCase):
    def test_dataset_alerts_produce_low_confidence_hypothesis_with_source_evidence(self) -> None:
        reports = {
            "system": make_report("system", "dataset_cpu_usage", "dataset_alerts", "event_count", 2)
        }

        result = ReasoningAgent().analyze(reports)

        self.assertEqual(result.status, ReasoningStatus.ANALYZED)
        self.assertEqual(len(result.hypotheses), 1)
        hypothesis = result.hypotheses[0]
        self.assertEqual(hypothesis.hypothesis_id, "system_resource_pressure")
        self.assertEqual(hypothesis.confidence, ConfidenceLevel.LOW)
        self.assertEqual(hypothesis.supporting_evidence[0].value, 2)
        self.assertEqual(hypothesis.supporting_evidence[0].source, "dataset_alerts")
        self.assertIn("métriques bruts", hypothesis.confidence_rationale)
        self.assertTrue(hypothesis.next_diagnostic_checks)

    def test_direct_metric_support_is_moderate_but_not_a_confirmed_root_cause(self) -> None:
        reports = {
            "system": make_report("system", "resource_cpu_high", "host_metrics", "cpu_percent", 97)
        }

        hypothesis = ReasoningAgent().analyze(reports).hypotheses[0]

        self.assertEqual(hypothesis.confidence, ConfidenceLevel.MODERATE)
        self.assertEqual(hypothesis.supporting_evidence[0].value, 97)
        self.assertIn("causalité", hypothesis.confidence_rationale)

    def test_duplicate_ssh_agent_views_remain_one_low_confidence_hypothesis(self) -> None:
        reports = {
            "logs": make_report(
                "logs", "log_ssh_auth_failure_alerts", "dataset_alerts", "event_count", 10
            ),
            "security": make_report(
                "security", "security_ssh_failure_alerts", "dataset_alerts", "event_count", 10
            ),
        }

        result = ReasoningAgent().analyze(reports)

        self.assertEqual(len(result.hypotheses), 1)
        hypothesis = result.hypotheses[0]
        self.assertEqual(hypothesis.hypothesis_id, "ssh_authentication_signal")
        self.assertEqual(hypothesis.confidence, ConfidenceLevel.LOW)
        self.assertIn("mêmes événements", hypothesis.confidence_rationale)
        self.assertEqual(len(hypothesis.supporting_evidence), 2)

    def test_no_data_returns_insufficient_data_without_a_cause_hypothesis(self) -> None:
        result = ReasoningAgent().analyze(
            {
                "network": AgentReport(
                    agent_id="network",
                    status=AgentStatus.NO_DATA,
                    summary="Network was not tested",
                    input_count=0,
                )
            }
        )

        self.assertEqual(result.status, ReasoningStatus.INSUFFICIENT_DATA)
        self.assertEqual(result.hypotheses, [])
        self.assertTrue(any("Network was not tested" in gap for gap in result.data_gaps))

    def test_unmapped_alert_does_not_become_a_cause_hypothesis(self) -> None:
        result = ReasoningAgent().analyze(
            {"logs": make_report("logs", "log_alert_observed", "dataset_alerts", "event_count", 1)}
        )

        self.assertEqual(result.status, ReasoningStatus.INSUFFICIENT_DATA)
        self.assertEqual(result.hypotheses, [])


if __name__ == "__main__":
    unittest.main()
