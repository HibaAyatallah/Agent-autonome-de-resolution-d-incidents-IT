from collections.abc import Iterable, Mapping, Sequence
from typing import Any

from incident_response.agents.models import (
    AgentFinding,
    AgentReport,
    AgentStatus,
    Evidence,
    FindingSeverity,
)
from incident_response.monitoring.models import NetworkProbeResult


class NetworkAgent:
    """Summarize configured DNS/TCP checks; it does not probe unconfigured hosts."""

    agent_id = "network"

    def __init__(self, latency_warning_ms: float = 500.0, latency_critical_ms: float = 2000.0):
        if latency_warning_ms < 0 or latency_warning_ms >= latency_critical_ms:
            raise ValueError("Latency thresholds must satisfy 0 <= warning < critical.")
        self.latency_warning_ms = latency_warning_ms
        self.latency_critical_ms = latency_critical_ms

    def analyze(
        self,
        checks: Sequence[NetworkProbeResult] | None,
        alert_records: Iterable[Mapping[str, Any]] = (),
    ) -> AgentReport:
        network_alerts = [
            record
            for record in alert_records
            if record.get("alert_name") == "Network Usage"
        ]
        checks = list(checks or [])
        if not checks and not network_alerts:
            return AgentReport(
                agent_id=self.agent_id,
                status=AgentStatus.NO_DATA,
                summary="Aucune cible réseau n'est configurée ; le réseau n'a pas été testé.",
                input_count=0,
                limitations=["Configurer explicitement INCIDENT_NETWORK_TARGETS pour activer les contrôles."],
            )

        findings: list[AgentFinding] = []
        for record in network_alerts:
            findings.append(
                AgentFinding(
                    code="dataset_network_usage_alert",
                    title="Alerte de consommation réseau du dataset",
                    severity=FindingSeverity.WARNING,
                    summary=str(
                        record.get("summary")
                        or record.get("description")
                        or "La source a signalé un dépassement du seuil de consommation réseau."
                    ),
                    evidence=[
                        Evidence(source="dataset_alerts", field="alert_name", value="Network Usage"),
                        Evidence(
                            source="dataset_alerts",
                            field="source_record_id",
                            value=record.get("source_record_id"),
                        ),
                    ],
                    limitations=[
                        "L'alerte ne fournit pas de série temporelle ni de mesure réseau brute."
                    ],
                )
            )
        for check in checks:
            evidence = [
                Evidence(source="tcp_probe", field="target_name", value=check.name),
                Evidence(source="tcp_probe", field="dns_resolved", value=check.dns_resolved),
                Evidence(source="tcp_probe", field="reachable", value=check.reachable),
            ]
            if check.latency_ms is not None:
                evidence.append(
                    Evidence(
                        source="tcp_probe",
                        field="latency_ms",
                        value=round(check.latency_ms, 2),
                        unit="ms",
                    )
                )

            if not check.reachable:
                findings.append(
                    AgentFinding(
                        code=f"network_target_unreachable_{check.name}",
                        title=f"Cible indisponible : {check.name}",
                        severity=FindingSeverity.WARNING,
                        summary=(
                            f"La vérification TCP de {check.name} a échoué. "
                            "Cette observation seule ne distingue pas une panne réseau d'un service arrêté."
                        ),
                        evidence=evidence,
                    )
                )
                continue

            latency = check.latency_ms
            if latency is not None and latency >= self.latency_critical_ms:
                severity = FindingSeverity.CRITICAL
                title = f"Latence TCP critique : {check.name}"
            elif latency is not None and latency >= self.latency_warning_ms:
                severity = FindingSeverity.WARNING
                title = f"Latence TCP élevée : {check.name}"
            else:
                continue
            findings.append(
                AgentFinding(
                    code=f"network_latency_high_{check.name}",
                    title=title,
                    severity=severity,
                    summary=f"Latence mesurée : {latency:.1f} ms.",
                    evidence=evidence,
                )
            )

        if not findings:
            findings.append(
                AgentFinding(
                    code="network_targets_reachable",
                    title="Cibles réseau accessibles",
                    severity=FindingSeverity.INFO,
                    summary=f"Les {len(checks)} cibles TCP configurées ont répondu sans latence élevée.",
                    evidence=[
                        Evidence(source="tcp_probe", field="reachable_targets", value=len(checks))
                    ],
                )
            )
        return AgentReport(
            agent_id=self.agent_id,
            status=AgentStatus.OK,
            summary=(
                f"{len(checks)} contrôles réseau et {len(network_alerts)} alertes réseau analysés."
            ),
            input_count=len(checks) + len(network_alerts),
            findings=findings,
            limitations=["Les sondes TCP vérifient l'accès au service, pas toutes les couches réseau."],
        )
