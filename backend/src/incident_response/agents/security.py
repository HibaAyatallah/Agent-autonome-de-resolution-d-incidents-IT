from collections.abc import Iterable, Mapping
from typing import Any

from incident_response.agents.models import (
    AgentFinding,
    AgentReport,
    AgentStatus,
    Evidence,
    FindingSeverity,
)


class SecurityAgent:
    """Flag security-related alerts for review; never claims an attack is confirmed."""

    agent_id = "security"

    def analyze(self, records: Iterable[Mapping[str, Any]]) -> AgentReport:
        ssh_alerts = [
            record
            for record in records
            if record.get("alert_name") == "SSH Authentication Failure"
        ]
        if not ssh_alerts:
            return AgentReport(
                agent_id=self.agent_id,
                status=AgentStatus.NO_DATA,
                summary="Aucune alerte de sécurité SSH n'est présente dans les données reçues.",
                input_count=0,
                limitations=[
                    "L'absence de telles alertes dans l'entrée ne prouve pas l'absence d'incident de sécurité."
                ],
            )

        summaries = sorted(
            {
                str(record["summary"])
                for record in ssh_alerts
                if record.get("summary") is not None
            }
        )
        evidence = [
            Evidence(source="dataset_alerts", field="ssh_alert_event_count", value=len(ssh_alerts)),
            Evidence(
                source="dataset_alerts",
                field="reported_rule_summary",
                value=summaries[0] if summaries else "not_available",
            ),
        ]
        return AgentReport(
            agent_id=self.agent_id,
            status=AgentStatus.OK,
            summary=f"{len(ssh_alerts)} alertes SSH transmises pour examen sécurité.",
            input_count=len(ssh_alerts),
            findings=[
                AgentFinding(
                    code="security_ssh_failure_alerts",
                    title="Signal d'échecs d'authentification SSH",
                    severity=FindingSeverity.WARNING,
                    summary=(
                        "La source de monitoring signale des échecs d'authentification SSH. "
                        "Vérifier les journaux d'authentification et les règles de l'hôte avant de conclure."
                    ),
                    evidence=evidence,
                    limitations=[
                        "Le nombre est un décompte d'événements d'alerte, pas le nombre de tentatives SSH.",
                        "Les lignes d'authentification brutes et les adresses source ne sont pas disponibles.",
                        "Une alerte de sécurité n'établit pas qu'une attaque a réussi.",
                    ],
                )
            ],
            limitations=[
                "Aucun blocage de compte, bannissement d'IP ou autre action de sécurité n'est exécuté."
            ],
        )
