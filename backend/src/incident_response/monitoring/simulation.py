from incident_response.monitoring.detector import detect_alerts
from incident_response.monitoring.models import (
    MonitoringSnapshot,
    NetworkProbeResult,
    SystemMetrics,
)
from incident_response.monitoring.settings import DetectionThresholds


def simulate_snapshot(
    metrics: SystemMetrics,
    network_checks: list[NetworkProbeResult] | None = None,
    thresholds: DetectionThresholds | None = None,
) -> MonitoringSnapshot:
    """Run detection against caller-supplied data; this function never reads or changes the host."""
    checks = network_checks or []
    alerts = detect_alerts(metrics, checks, thresholds)
    return MonitoringSnapshot(system=metrics, network_checks=checks, alerts=alerts)
