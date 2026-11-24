from incident_response.monitoring.collector import check_tcp_target, collect_system_metrics
from incident_response.monitoring.detector import detect_alerts
from incident_response.monitoring.models import MonitoringSnapshot
from incident_response.monitoring.settings import (
    DetectionThresholds,
    NetworkTarget,
    network_targets_from_environment,
)


def collect_snapshot(
    thresholds: DetectionThresholds | None = None,
    network_targets: list[NetworkTarget] | None = None,
) -> MonitoringSnapshot:
    targets = network_targets if network_targets is not None else network_targets_from_environment()
    metrics = collect_system_metrics()
    checks = [check_tcp_target(target) for target in targets]
    alerts = detect_alerts(metrics, checks, thresholds or DetectionThresholds.from_environment())
    return MonitoringSnapshot(system=metrics, network_checks=checks, alerts=alerts)
