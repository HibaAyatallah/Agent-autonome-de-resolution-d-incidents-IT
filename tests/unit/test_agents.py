import unittest

from incident_response.agents import LogsAgent, NetworkAgent, SecurityAgent, SystemAgent
from incident_response.agents.models import AgentStatus, FindingSeverity
from incident_response.monitoring.models import NetworkProbeResult, SystemMetrics
from incident_response.monitoring.simulation import simulate_snapshot


class AgentTests(unittest.TestCase):
    def test_logs_agent_groups_alert_events_without_claiming_raw_log_access(self) -> None:
        records = [
            {"source_type": "log", "alert_name": "DatasourceNoData", "source_record_id": "row:2"},
            {"source_type": "log", "alert_name": "SSH Authentication Failure", "source_record_id": "row:3"},
            {"source_type": "log", "alert_name": "SSH Authentication Failure", "source_record_id": "row:4"},
            {"source_type": "usage", "alert_name": "CPU Usage", "source_record_id": "row:5"},
        ]

        report = LogsAgent().analyze(records)

        self.assertEqual(report.status, AgentStatus.OK)
        self.assertEqual(report.input_count, 3)
        self.assertEqual(len(report.findings), 2)
        ssh_finding = next(f for f in report.findings if f.code == "log_ssh_auth_failure_alerts")
        self.assertIn("pas nécessairement le nombre d'erreurs", report.limitations[0])
        self.assertEqual(ssh_finding.evidence[1].value, 2)

    def test_logs_agent_marks_empty_input_as_no_data(self) -> None:
        report = LogsAgent().analyze([])
        self.assertEqual(report.status, AgentStatus.NO_DATA)
        self.assertEqual(report.findings, [])

    def test_system_agent_reports_rule_evidence(self) -> None:
        metrics = SystemMetrics(
            hostname="test-host",
            cpu_percent=97,
            ram_percent=40,
            ram_available_bytes=1000,
            disk_percent=50,
            disk_free_bytes=2000,
        )
        snapshot = simulate_snapshot(metrics)

        report = SystemAgent().analyze(snapshot)

        self.assertEqual(report.findings[0].severity, FindingSeverity.CRITICAL)
        self.assertEqual(report.findings[0].evidence[0].value, 97)

    def test_system_agent_reports_dataset_alert_without_inventing_numeric_metrics(self) -> None:
        report = SystemAgent().analyze(
            None,
            [
                {
                    "source_type": "usage",
                    "alert_name": "CPU Usage",
                    "summary": "CPU is above its alert threshold.",
                    "source_record_id": "Datos finales:4",
                },
                {
                    "source_type": "usage",
                    "alert_name": "CPU Usage",
                    "summary": "CPU is above its alert threshold.",
                    "source_record_id": "Datos finales:5",
                },
            ],
        )
        self.assertEqual(report.status, AgentStatus.OK)
        self.assertEqual(len(report.findings), 1)
        self.assertEqual(report.findings[0].severity, FindingSeverity.WARNING)
        self.assertEqual(report.findings[0].evidence[0].value, "CPU Usage")
        self.assertEqual(report.findings[0].evidence[1].value, 2)
        self.assertIn("mesure numérique brute", report.findings[0].limitations[0])

    def test_network_agent_does_not_treat_unconfigured_network_as_healthy(self) -> None:
        report = NetworkAgent().analyze([])
        self.assertEqual(report.status, AgentStatus.NO_DATA)
        self.assertIn("n'a pas été testé", report.summary)

    def test_network_agent_reports_historical_usage_alert_without_inventing_raw_metrics(self) -> None:
        report = NetworkAgent().analyze(
            None,
            [
                {
                    "alert_name": "Network Usage",
                    "summary": "Network usage exceeded the configured threshold.",
                    "source_record_id": "Datos finales:8",
                }
            ],
        )
        self.assertEqual(report.status, AgentStatus.OK)
        self.assertEqual(report.findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("série temporelle", report.findings[0].limitations[0])

    def test_network_agent_reports_unreachable_service_cautiously(self) -> None:
        result = NetworkProbeResult(
            name="api-test",
            host="service.example",
            port=443,
            dns_resolved=True,
            reachable=False,
            error="connection_timeout",
        )
        report = NetworkAgent().analyze([result])
        self.assertEqual(report.findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("ne distingue pas", report.findings[0].summary)

    def test_network_agent_detects_high_latency(self) -> None:
        result = NetworkProbeResult(
            name="api-test",
            host="service.example",
            port=443,
            dns_resolved=True,
            reachable=True,
            latency_ms=750,
        )
        report = NetworkAgent().analyze([result])
        self.assertEqual(report.findings[0].severity, FindingSeverity.WARNING)
        self.assertEqual(report.findings[0].evidence[-1].value, 750)

    def test_security_agent_flags_source_alert_without_confirming_attack(self) -> None:
        records = [
            {
                "alert_name": "SSH Authentication Failure",
                "summary": "More than 4 failures were reported.",
                "labels": {"ip": "203.0.113.10"},
            }
        ]
        report = SecurityAgent().analyze(records)
        encoded = report.model_dump_json()
        self.assertEqual(report.findings[0].severity, FindingSeverity.WARNING)
        self.assertIn("n'établit pas qu'une attaque a réussi", encoded)
        self.assertNotIn("203.0.113.10", encoded)

    def test_security_agent_no_data_is_not_a_clean_security_bill(self) -> None:
        report = SecurityAgent().analyze([])
        self.assertEqual(report.status, AgentStatus.NO_DATA)
        self.assertIn("ne prouve pas l'absence", report.limitations[0])


if __name__ == "__main__":
    unittest.main()
