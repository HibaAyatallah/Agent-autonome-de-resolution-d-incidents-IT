from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

from incident_response.agents.models import (
    AgentFinding,
    AgentReport,
    AgentStatus,
    Evidence,
    FindingSeverity,
)
from incident_response.monitoring.models import MonitoringSnapshot


class SystemAgent:
    """Explain resource alerts from a monitoring snapshot."""

    agent_id = "system"

    def analyze(
        self,
        snapshot: MonitoringSnapshot | None,
        alert_records: Iterable[Mapping[str, Any]] = (),
    ) -> AgentReport:
        resource_records = [
            record
            for record in alert_records
            if record.get("source_type") == "usage"
            and record.get("alert_name") in {"CPU Usage", "RAM Usage", "Disk Usage"}
        ]
        if snapshot is None and not resource_records:
            return AgentReport(
                agent_id=self.agent_id,
                status=AgentStatus.NO_DATA,
                summary="Aucun instantané système n'a été fourni.",
                input_count=0,
                limitations=["Les métriques de l'hôte doivent être collectées ou fournies."],
            )
        metric_values = (
            {
                "cpu_percent": snapshot.system.cpu_percent,
                "ram_percent": snapshot.system.ram_percent,
                "disk_percent": snapshot.system.disk_percent,
            }
            if snapshot is not None
            else {}
        )
        alerts = (
            [alert for alert in snapshot.alerts if alert.category == "system_resource"]
            if snapshot is not None
            else []
        )
        findings = [
            AgentFinding(
                code=alert.rule_id,
                title=f"Ressource système élevée : {alert.metric}",
                severity=FindingSeverity(alert.severity.value),
                summary=alert.summary,
                evidence=[
                    Evidence(
                        source="host_metrics",
                        field=alert.metric,
                        value=alert.observed_value,
                        unit="percent",
                    ),
                    Evidence(
                        source="monitoring_rule",
                        field="threshold_percent",
                        value=alert.threshold,
                        unit="percent",
                    ),
                ],
            )
            for alert in alerts
        ]
        grouped_records: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for record in resource_records:
            grouped_records[str(record["alert_name"])].append(record)
        for alert_name, source_records in sorted(grouped_records.items()):
            first_record = source_records[0]
            summary = (
                first_record.get("summary")
                or first_record.get("description")
                or "Alerte de ressource reçue."
            )
            sample_ids = [
                str(record["source_record_id"])
                for record in source_records[:5]
                if record.get("source_record_id") is not None
            ]
            findings.append(
                AgentFinding(
                    code=f"dataset_{alert_name.lower().replace(' ', '_')}",
                    title=f"Alerte de ressource du dataset : {alert_name}",
                    severity=FindingSeverity.WARNING,
                    summary=str(summary),
                    evidence=[
                        Evidence(source="dataset_alerts", field="alert_name", value=alert_name),
                        Evidence(
                            source="dataset_alerts",
                            field="event_count",
                            value=len(source_records),
                        ),
                        Evidence(
                            source="dataset_alerts",
                            field="sample_record_ids",
                            value=", ".join(sample_ids) if sample_ids else "not_available",
                        ),
                    ],
                    limitations=[
                        "L'alerte source ne fournit pas la mesure numérique brute de la ressource."
                    ],
                )
            )
        if not findings and snapshot is not None:
            findings = [
                AgentFinding(
                    code="system_resources_below_alert_thresholds",
                    title="Aucune alerte de ressource détectée",
                    severity=FindingSeverity.INFO,
                    summary="Les mesures reçues ne dépassent pas les seuils configurés.",
                    evidence=[
                        Evidence(
                            source="host_metrics",
                            field=metric,
                            value=value,
                            unit="percent",
                        )
                        for metric, value in metric_values.items()
                    ],
                )
            ]

        return AgentReport(
            agent_id=self.agent_id,
            status=AgentStatus.OK,
            summary=(
                f"Mesures de l'hôte {snapshot.system.hostname} analysées."
                if snapshot is not None
                else f"{len(resource_records)} alertes système historiques analysées."
            ),
            input_count=(1 if snapshot is not None else 0) + len(resource_records),
            findings=findings,
            limitations=(
                ["Un instantané ponctuel ne suffit pas à établir une tendance ou la cause racine."]
                if snapshot is not None
                else ["Les alertes historiques ne contiennent pas les métriques brutes de l'hôte."]
            ),
        )
