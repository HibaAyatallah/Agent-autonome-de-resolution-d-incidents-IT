from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from dataclasses import dataclass

from incident_response.agents.logs import LogsAgent
from incident_response.agents.models import AgentReport, AgentStatus
from incident_response.agents.network import NetworkAgent
from incident_response.agents.security import SecurityAgent
from incident_response.agents.system import SystemAgent
from incident_response.orchestration.models import (
    IncidentAssessment,
    IncidentInput,
    IncidentPriority,
    IncidentWorkflowState,
    WorkflowEvent,
    WorkflowStatus,
)
from incident_response.orchestration.settings import WorkflowSettings
from incident_response.reasoning.agent import ReasoningAgent


@dataclass(frozen=True)
class AgentExecution:
    report: AgentReport
    attempts: int


class CoordinatorAgent:
    """Own the incident workflow and aggregate specialized agent reports."""

    agent_id = "coordinator"

    def __init__(
        self,
        agent_timeout_seconds: float | None = None,
        max_agent_attempts: int | None = None,
    ) -> None:
        settings = WorkflowSettings()
        timeout = agent_timeout_seconds if agent_timeout_seconds is not None else settings.agent_timeout_seconds
        attempts = max_agent_attempts if max_agent_attempts is not None else settings.max_agent_attempts
        if not 0.1 <= timeout <= 60:
            raise ValueError("agent_timeout_seconds must be between 0.1 and 60 seconds.")
        if not 1 <= attempts <= 3:
            raise ValueError("max_agent_attempts must be between 1 and 3.")
        self.agent_timeout_seconds = timeout
        self.max_agent_attempts = attempts
        self.logs_agent = LogsAgent()
        self.system_agent = SystemAgent()
        self.network_agent = NetworkAgent()
        self.security_agent = SecurityAgent()
        self.reasoning_agent = ReasoningAgent()

    def run(self, incident: IncidentInput) -> IncidentAssessment:
        state = IncidentWorkflowState(
            incident=incident,
            events=[
                WorkflowEvent(
                    event_type="incident_received",
                    actor=self.agent_id,
                    message="Incident validé et ajouté à l'état partagé du workflow.",
                ),
                WorkflowEvent(
                    event_type="triage_started",
                    actor=self.agent_id,
                    message="Catégorisation initiale des signaux disponibles.",
                ),
            ],
        )
        state.status = WorkflowStatus.DIAGNOSING
        state.categories = self._classify_categories(incident)
        state.events.append(
            WorkflowEvent(
                event_type="triage_completed",
                actor=self.agent_id,
                message=f"Catégories initiales : {', '.join(state.categories)}.",
            )
        )
        state.events.append(
            WorkflowEvent(
                event_type="diagnosis_started",
                actor=self.agent_id,
                message="Les agents spécialisés reçoivent le même contexte en lecture seule.",
            )
        )

        work: dict[str, Callable[[], AgentReport]] = {
            "logs": lambda: self.logs_agent.analyze(incident.alert_records),
            "system": lambda: self.system_agent.analyze(
                incident.monitoring_snapshot,
                incident.alert_records,
            ),
            "network": lambda: self.network_agent.analyze(
                incident.monitoring_snapshot.network_checks
                if incident.monitoring_snapshot is not None
                else None,
                incident.alert_records,
            ),
            "security": lambda: self.security_agent.analyze(incident.alert_records),
        }
        reports: dict[str, AgentReport] = {}
        with ThreadPoolExecutor(max_workers=len(work), thread_name_prefix="incident-agent") as pool:
            for name in work:
                state.events.append(
                    WorkflowEvent(
                        event_type="agent_dispatched",
                        actor=self.agent_id,
                        message=f"Contexte transmis à l'agent {name}.",
                    )
                )
            futures = {
                name: pool.submit(self._run_with_retries, name, task)
                for name, task in work.items()
            }
            for name, future in futures.items():
                try:
                    execution = future.result(
                        timeout=self.agent_timeout_seconds * self.max_agent_attempts
                    )
                    reports[name] = execution.report
                    if execution.attempts > 1:
                        state.events.append(
                            WorkflowEvent(
                                event_type="agent_retried",
                                actor=name,
                                message=f"L'agent a nécessité {execution.attempts} tentatives.",
                            )
                        )
                    state.events.append(
                        WorkflowEvent(
                            event_type=(
                                "agent_completed"
                                if execution.report.status != AgentStatus.ERROR
                                else "agent_failed"
                            ),
                            actor=name,
                            message=(
                                "Rapport structuré reçu par le coordinateur."
                                if execution.report.status != AgentStatus.ERROR
                                else "L'agent a échoué après les tentatives autorisées."
                            ),
                        )
                    )
                except TimeoutError:
                    future.cancel()
                    reports[name] = self._error_report(name, "timeout")
                    state.events.append(
                        WorkflowEvent(
                            event_type="agent_timeout",
                            actor=name,
                            message="Délai de diagnostic dépassé.",
                        )
                    )
                except Exception as exc:  # noqa: BLE001 - isolate a failed agent from its peers.
                    reports[name] = self._error_report(name, type(exc).__name__)
                    state.events.append(
                        WorkflowEvent(
                            event_type="agent_failed",
                            actor=name,
                            message="L'agent n'a pas pu terminer son analyse.",
                        )
                    )

        state.agent_reports = reports
        reasoning = self.reasoning_agent.analyze(reports)
        state.events.append(
            WorkflowEvent(
                event_type="reasoning_completed",
                actor=self.reasoning_agent.agent_id,
                message=reasoning.summary,
            )
        )
        state.priority = self._select_priority(reports)
        failed_agents = [name for name, report in reports.items() if report.status == AgentStatus.ERROR]
        state.status = WorkflowStatus.DEGRADED if failed_agents else WorkflowStatus.DIAGNOSED
        finding_count = sum(len(report.findings) for report in reports.values())
        summary = (
            f"{len(reports) - len(failed_agents)} agents ont terminé, "
            f"{finding_count} constats transmis ; priorité initiale {state.priority.value}."
        )
        if failed_agents:
            summary += f" Diagnostic partiel : agents indisponibles ({', '.join(failed_agents)})."
        summary += " Aucune cause racine n'est confirmée et aucune résolution n'est exécutée à cette étape."
        state.events.append(
            WorkflowEvent(
                event_type="assessment_ready",
                actor=self.agent_id,
                message=summary,
            )
        )

        return IncidentAssessment(
            incident_id=incident.incident_id,
            origin=incident.origin,
            status=state.status,
            priority=state.priority,
            categories=state.categories,
            description=incident.description,
            summary=summary,
            agent_reports=state.agent_reports,
            reasoning=reasoning,
            events=state.events,
        )

    @staticmethod
    def _error_report(agent_id: str, reason: str) -> AgentReport:
        detail = "Délai dépassé." if reason == "timeout" else "Erreur interne de l'agent."
        return AgentReport(
            agent_id=agent_id,
            status=AgentStatus.ERROR,
            summary=detail,
            input_count=0,
            limitations=["Consulter les journaux applicatifs pour le détail technique."],
        )

    def _run_with_retries(self, agent_id: str, task: Callable[[], AgentReport]) -> AgentExecution:
        for attempt in range(1, self.max_agent_attempts + 1):
            try:
                return AgentExecution(report=task(), attempts=attempt)
            except Exception as exc:  # noqa: BLE001 - retry any agent implementation failure.
                if attempt == self.max_agent_attempts:
                    return AgentExecution(
                        report=self._error_report(agent_id, type(exc).__name__),
                        attempts=attempt,
                    )
        raise RuntimeError("Agent retry loop exited unexpectedly.")

    @staticmethod
    def _classify_categories(incident: IncidentInput) -> list[str]:
        categories: set[str] = set()
        text = incident.description.casefold()
        alert_names = {str(record.get("alert_name", "")) for record in incident.alert_records}
        source_types = {str(record.get("source_type", "")) for record in incident.alert_records}
        if "log" in source_types:
            categories.add("logs")
        if "SSH Authentication Failure" in alert_names or "security" in text or "sécurité" in text:
            categories.add("security")
        if "Network Usage" in alert_names:
            categories.add("network")
        if alert_names.intersection({"CPU Usage", "RAM Usage", "Disk Usage"}) or any(
            word in text for word in ("cpu", "processeur", "ram", "mémoire", "disque")
        ):
            categories.add("system")
        if incident.monitoring_snapshot:
            categories.add("system")
            if incident.monitoring_snapshot.network_checks:
                categories.add("network")
        if any(word in text for word in ("network", "réseau", "dns", "latence", "connectivité")):
            categories.add("network")
        if not categories:
            categories.add("general")
        return sorted(categories)

    @staticmethod
    def _select_priority(reports: dict[str, AgentReport]) -> IncidentPriority:
        severities = [
            finding.severity
            for report in reports.values()
            for finding in report.findings
        ]
        if any(severity.value == "critical" for severity in severities):
            return IncidentPriority.P1
        if any(severity.value == "warning" for severity in severities):
            return IncidentPriority.P2
        if any(report.status == AgentStatus.OK for report in reports.values()):
            return IncidentPriority.P3
        return IncidentPriority.UNASSESSED
