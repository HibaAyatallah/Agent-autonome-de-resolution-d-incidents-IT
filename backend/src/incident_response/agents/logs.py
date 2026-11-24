from collections import Counter
from collections.abc import Iterable, Mapping
from typing import Any

from incident_response.agents.models import (
    AgentFinding,
    AgentReport,
    AgentStatus,
    Evidence,
    FindingSeverity,
)


class LogsAgent:
    """Summarize alert records and log-related signals without claiming raw-log access."""

    agent_id = "logs"

    def analyze(self, records: Iterable[Mapping[str, Any]]) -> AgentReport:
        log_records = [record for record in records if record.get("source_type") == "log"]
        if not log_records:
            return AgentReport(
                agent_id=self.agent_id,
                status=AgentStatus.NO_DATA,
                summary="Aucune alerte de type log à analyser.",
                input_count=0,
                limitations=["Aucune ligne de journal brute n'a été fournie."],
            )

        counts = Counter(str(record.get("alert_name") or "(nom absent)") for record in log_records)
        findings = []
        for alert_name, count in sorted(counts.items()):
            sample_ids = [
                str(record["source_record_id"])
                for record in log_records
                if (record.get("alert_name") or "(nom absent)") == alert_name
                and record.get("source_record_id") is not None
            ][:5]
            if alert_name == "SSH Authentication Failure":
                title = "Alertes d'échecs d'authentification SSH"
                code = "log_ssh_auth_failure_alerts"
                summary = (
                    f"La source a enregistré {count} alertes SSH de ce type. "
                    "Cela justifie une vérification des journaux d'authentification."
                )
            elif alert_name in {"DatasourceError", "DatasourceNoData"}:
                title = "Signal d'erreur ou d'absence de données"
                code = f"log_{alert_name.lower()}"
                summary = f"La source a enregistré {count} alertes {alert_name}."
            else:
                title = f"Alerte de journal : {alert_name}"
                code = "log_alert_observed"
                summary = f"La source a enregistré {count} alertes de journal {alert_name}."
            findings.append(
                AgentFinding(
                    code=code,
                    title=title,
                    severity=FindingSeverity.WARNING,
                    summary=summary,
                    evidence=[
                        Evidence(source="dataset_alerts", field="alert_name", value=alert_name),
                        Evidence(source="dataset_alerts", field="event_count", value=count),
                        Evidence(
                            source="dataset_alerts",
                            field="sample_record_ids",
                            value=", ".join(sample_ids) if sample_ids else "not_available",
                        ),
                    ],
                    limitations=[
                        "Le dataset contient des événements d'alerte, pas les lignes de logs brutes."
                    ],
                )
            )

        return AgentReport(
            agent_id=self.agent_id,
            status=AgentStatus.OK,
            summary=f"{len(log_records)} alertes de type log analysées.",
            input_count=len(log_records),
            findings=findings,
            limitations=["Le nombre d'alertes n'est pas nécessairement le nombre d'erreurs sous-jacentes."],
        )
