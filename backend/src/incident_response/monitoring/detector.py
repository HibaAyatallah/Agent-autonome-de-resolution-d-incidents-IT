from incident_response.monitoring.models import (
    MonitoringAlert,
    NetworkProbeResult,
    Severity,
    SystemMetrics,
)
from incident_response.monitoring.settings import DetectionThresholds


def detect_alerts(
    metrics: SystemMetrics,
    network_checks: list[NetworkProbeResult] | None = None,
    thresholds: DetectionThresholds | None = None,
) -> list[MonitoringAlert]:
    rules = thresholds or DetectionThresholds()
    alerts: list[MonitoringAlert] = []
    checks = (
        ("cpu", metrics.cpu_percent, rules.cpu_warning, rules.cpu_critical, "CPU"),
        ("ram", metrics.ram_percent, rules.ram_warning, rules.ram_critical, "RAM"),
        ("disk", metrics.disk_percent, rules.disk_warning, rules.disk_critical, "Disque"),
    )
    for rule_id, observed, warning, critical, label in checks:
        if observed >= critical:
            severity, boundary = Severity.CRITICAL, critical
        elif observed >= warning:
            severity, boundary = Severity.WARNING, warning
        else:
            continue
        alerts.append(
            MonitoringAlert(
                rule_id=f"resource_{rule_id}_high",
                severity=severity,
                category="system_resource",
                metric=f"{rule_id}_percent",
                observed_value=observed,
                threshold=boundary,
                summary=f"Utilisation {label} élevée : {observed:.1f} % (seuil {boundary:.1f} %).",
            )
        )

    for check in network_checks or []:
        if not check.reachable:
            reason = "DNS indisponible" if not check.dns_resolved else "service TCP inaccessible"
            alerts.append(
                MonitoringAlert(
                    rule_id=f"network_unreachable_{check.name}",
                    severity=Severity.CRITICAL,
                    category="network",
                    metric="tcp_reachable",
                    observed_value=0,
                    threshold=1,
                    summary=f"La cible réseau configurée {check.name!r} est indisponible ({reason}).",
                )
            )
    return alerts
