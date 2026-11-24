import unittest

from incident_response.api.monitoring_routes import get_monitoring_snapshot
from incident_response.main import create_app


class MonitoringApiTests(unittest.TestCase):
    def test_snapshot_endpoint_returns_live_system_metrics(self) -> None:
        app = create_app()
        self.assertIn("/api/v1/monitoring/snapshot", app.openapi()["paths"])

        snapshot = get_monitoring_snapshot()

        self.assertGreaterEqual(snapshot.system.cpu_percent, 0)
        self.assertLessEqual(snapshot.system.cpu_percent, 100)
        self.assertGreaterEqual(snapshot.system.ram_percent, 0)
        self.assertGreaterEqual(snapshot.system.disk_percent, 0)
        self.assertIsInstance(snapshot.alerts, list)
        self.assertEqual(snapshot.network_checks, [])


if __name__ == "__main__":
    unittest.main()
