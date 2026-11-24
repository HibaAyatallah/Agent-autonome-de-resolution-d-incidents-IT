import unittest
from unittest.mock import patch

from incident_response.monitoring.collector import check_tcp_target
from incident_response.monitoring.detector import detect_alerts
from incident_response.monitoring.models import (
    NetworkProbeResult,
    ProcessMetric,
    Severity,
    SystemMetrics,
)
from incident_response.monitoring.settings import DetectionThresholds, NetworkTarget
from incident_response.monitoring.simulation import simulate_snapshot


def metrics(cpu: float = 12, ram: float = 30, disk: float = 40) -> SystemMetrics:
    return SystemMetrics(
        hostname="test-host",
        cpu_percent=cpu,
        ram_percent=ram,
        ram_available_bytes=1024,
        disk_percent=disk,
        disk_free_bytes=2048,
        top_processes=[
            ProcessMetric(pid=7, name="worker", cpu_percent=5, memory_rss_bytes=512)
        ],
    )


class MonitoringTests(unittest.TestCase):
    def test_no_alerts_below_thresholds(self) -> None:
        self.assertEqual(detect_alerts(metrics()), [])

    def test_warning_and_critical_resource_alerts(self) -> None:
        alerts = detect_alerts(metrics(cpu=80, ram=96, disk=90))
        by_metric = {alert.metric: alert for alert in alerts}
        self.assertEqual(by_metric["cpu_percent"].severity, Severity.WARNING)
        self.assertEqual(by_metric["ram_percent"].severity, Severity.CRITICAL)
        self.assertEqual(by_metric["disk_percent"].severity, Severity.WARNING)

    def test_network_failure_alert_only_for_configured_check(self) -> None:
        result = NetworkProbeResult(
            name="test-api",
            host="localhost",
            port=8080,
            dns_resolved=True,
            reachable=False,
            error="connection_failed",
        )
        alerts = detect_alerts(metrics(), [result])
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].category, "network")
        self.assertEqual(alerts[0].severity, Severity.CRITICAL)

    def test_thresholds_reject_invalid_order(self) -> None:
        with self.assertRaises(ValueError):
            DetectionThresholds(cpu_warning=96, cpu_critical=95)

    def test_simulation_uses_same_detection_without_collecting_host_state(self) -> None:
        snapshot = simulate_snapshot(metrics(cpu=97))
        self.assertEqual(snapshot.alerts[0].rule_id, "resource_cpu_high")
        self.assertEqual(snapshot.system.hostname, "test-host")

    def test_network_target_port_validation(self) -> None:
        with self.assertRaises(ValueError):
            NetworkTarget(host="localhost", port=70000, name="invalid")

    @patch("incident_response.monitoring.collector.socket.socket")
    @patch("incident_response.monitoring.collector.socket.getaddrinfo")
    def test_tcp_probe_succeeds_for_resolved_reachable_target(self, getaddrinfo, socket_factory) -> None:
        getaddrinfo.return_value = [
            (2, 1, 6, "", ("192.0.2.1", 443))
        ]
        connection = socket_factory.return_value.__enter__.return_value
        target = NetworkTarget(host="monitor.example", port=443, name="test-api")

        result = check_tcp_target(target)

        self.assertTrue(result.dns_resolved)
        self.assertTrue(result.reachable)
        self.assertIsNotNone(result.latency_ms)
        connection.connect.assert_called_once_with(("192.0.2.1", 443))

    def test_monitoring_thresholds_load_from_environment(self) -> None:
        with patch.dict(
            "os.environ",
            {"MONITOR_CPU_WARNING": "70", "MONITOR_CPU_CRITICAL": "90"},
        ):
            thresholds = DetectionThresholds.from_environment()
        self.assertEqual(thresholds.cpu_warning, 70)
        self.assertEqual(thresholds.cpu_critical, 90)


if __name__ == "__main__":
    unittest.main()
