from __future__ import annotations

from collections import defaultdict

from incident_response.agents.models import AgentReport, AgentStatus, FindingSeverity
from incident_response.reasoning.models import (
    CauseHypothesis,
    ConfidenceLevel,
    ReasoningAssessment,
    ReasoningEvidence,
    ReasoningStatus,
    SimilarIncidentReference,
)

_HYPOTHESIS_DETAILS = {
    "system_resource_pressure": (
        "Pression sur les ressources système",
        "Un rapport système signale une ressource au-dessus du seuil ou une alerte historique de ressource.",
        [
            "Corréler la mesure avec l'heure de l'incident et consulter une série temporelle CPU, RAM et disque.",
            "Comparer les processus consommateurs et les journaux de l'hôte sur la même période.",
        ],
    ),
    "network_service_reachability": (
        "Inaccessibilité d'une cible réseau testée",
        "Une sonde configurée n'a pas pu joindre sa cible ; cela peut relever du réseau ou du service distant.",
        [
            "Répéter le contrôle depuis un autre point du réseau et vérifier l'état du service distant.",
            "Examiner les résultats DNS et TCP horodatés autour de l'incident.",
        ],
    ),
    "network_latency": (
        "Latence élevée vers une cible réseau testée",
        "Une sonde configurée a mesuré une latence supérieure au seuil du diagnostic.",
        [
            "Répéter les mesures vers plusieurs cibles et comparer les latences dans le temps.",
            "Corréler ces mesures avec les journaux du service et l'heure de l'incident.",
        ],
    ),
    "network_usage_alert": (
        "Alerte de consommation réseau",
        "Le dataset contient une alerte réseau, sans mesure brute ni série temporelle associée.",
        [
            "Consulter les métriques réseau brutes et leur série temporelle pour la période concernée.",
            "Vérifier si la source de l'alerte et la cible affectée correspondent à cet incident.",
        ],
    ),
    "ssh_authentication_signal": (
        "Signal d'échecs d'authentification SSH",
        "Les rapports signalent des alertes d'échecs SSH, ce qui justifie une vérification des journaux d'authentification.",
        [
            "Examiner les journaux d'authentification bruts autour de l'heure concernée.",
            "Vérifier les comptes et hôtes touchés ; l'alerte seule ne démontre pas une attaque réussie.",
        ],
    ),
    "monitoring_data_source_issue": (
        "Anomalie de la source de données de monitoring",
        "Une alerte indique une erreur ou une absence de données de la source de monitoring.",
        [
            "Vérifier l'état de la source, de l'exporteur et de la requête de collecte.",
            "Comparer avec un contrôle indépendant de l'hôte ou du service affecté.",
        ],
    ),
    "service_availability_signal": (
        "Signal de disponibilité du serveur",
        "Une alerte de disponibilité est présente, mais les rapports ne confirment pas l'état du serveur.",
        [
            "Confirmer l'état du service avec une sonde indépendante et consulter ses journaux.",
            "Vérifier les redémarrages et événements d'infrastructure autour de l'horodatage de l'alerte.",
        ],
    ),
}


class ReasoningAgent:
    """Build cautious, evidence-linked cause hypotheses from specialist reports."""

    agent_id = "reasoning"

    def analyze(
        self,
        reports: dict[str, AgentReport],
        similar_incidents: list[SimilarIncidentReference] | None = None,
    ) -> ReasoningAssessment:
        grouped: dict[str, list[ReasoningEvidence]] = defaultdict(list)
        counter: dict[str, list[ReasoningEvidence]] = defaultdict(list)
        limitations: dict[str, list[str]] = defaultdict(list)
        data_gaps = self._data_gaps(reports)
        similar = similar_incidents or []

        for report_name, report in sorted(reports.items()):
            if report.status != AgentStatus.OK:
                continue
            for finding in report.findings:
                evidence_items = [
                    ReasoningEvidence(
                        agent_id=report.agent_id or report_name,
                        finding_code=finding.code,
                        finding_title=finding.title,
                        severity=finding.severity,
                        source=evidence.source,
                        field=evidence.field,
                        value=evidence.value,
                        unit=evidence.unit,
                    )
                    for evidence in finding.evidence
                ]
                hypothesis_id = self._hypothesis_for(report.agent_id, finding.code, evidence_items)
                if hypothesis_id is None:
                    continue
                if finding.severity == FindingSeverity.INFO:
                    counter[hypothesis_id].extend(evidence_items)
                    continue
                grouped[hypothesis_id].extend(evidence_items)
                limitations[hypothesis_id].extend(finding.limitations)
                limitations[hypothesis_id].extend(report.limitations)

        hypotheses = [
            self._build_hypothesis(
                hypothesis_id, evidence, counter[hypothesis_id], limitations[hypothesis_id]
            )
            for hypothesis_id, evidence in sorted(grouped.items())
        ]
        hypotheses.sort(
            key=lambda item: (item.confidence != ConfidenceLevel.MODERATE, item.hypothesis_id)
        )

        if not hypotheses:
            summary = "Aucune hypothèse de cause n'est soutenue par les constats disponibles."
            if data_gaps:
                summary += " Les données manquantes limitent l'analyse."
            return ReasoningAssessment(
                status=ReasoningStatus.INSUFFICIENT_DATA,
                summary=self._append_memory_context(summary, len(similar)),
                data_gaps=data_gaps
                or ["Aucun constat pertinent n'a été produit par les rapports spécialisés."],
                similar_incidents=similar,
            )

        summary = (
            f"{len(hypotheses)} hypothèse(s) de cause probable générée(s) à partir des rapports spécialisés. "
            "Aucune cause racine n'est confirmée ; les hypothèses nécessitent une vérification temporelle et indépendante."
        )
        return ReasoningAssessment(
            status=ReasoningStatus.ANALYZED,
            summary=self._append_memory_context(summary, len(similar)),
            hypotheses=hypotheses,
            data_gaps=data_gaps,
            similar_incidents=similar,
        )

    @staticmethod
    def _append_memory_context(summary: str, similar_count: int) -> str:
        if similar_count:
            summary += (
                f" {similar_count} dossier(s) historique(s) similaire(s) sont fournis comme contexte ; "
                "ils ne confirment pas la cause de l'incident actuel."
            )
        return summary

    @staticmethod
    def _hypothesis_for(
        agent_id: str, finding_code: str, evidence: list[ReasoningEvidence]
    ) -> str | None:
        if agent_id == "system":
            if finding_code.startswith(
                ("resource_cpu_high", "resource_ram_high", "resource_disk_high")
            ):
                return "system_resource_pressure"
            if finding_code in {"dataset_cpu_usage", "dataset_ram_usage", "dataset_disk_usage"}:
                return "system_resource_pressure"
            if finding_code == "system_resources_below_alert_thresholds":
                return "system_resource_pressure"
        if agent_id == "network":
            if finding_code.startswith("network_target_unreachable_"):
                return "network_service_reachability"
            if finding_code.startswith("network_latency_high_"):
                return "network_latency"
            if finding_code == "dataset_network_usage_alert":
                return "network_usage_alert"
        if agent_id in {"logs", "security"}:
            if finding_code in {"log_ssh_auth_failure_alerts", "security_ssh_failure_alerts"}:
                return "ssh_authentication_signal"
            if finding_code in {"log_datasourceerror", "log_datasourcenodata"}:
                return "monitoring_data_source_issue"
            if any(
                item.field == "alert_name" and item.value == "Server Down Detection"
                for item in evidence
            ):
                return "service_availability_signal"
        return None

    @staticmethod
    def _build_hypothesis(
        hypothesis_id: str,
        evidence: list[ReasoningEvidence],
        counter_evidence: list[ReasoningEvidence],
        limitations: list[str],
    ) -> CauseHypothesis:
        title, explanation, checks = _HYPOTHESIS_DETAILS[hypothesis_id]
        has_live_observation = any(
            item.source in {"host_metrics", "tcp_probe"} and item.field != "reachable_targets"
            for item in evidence
        )
        confidence = ConfidenceLevel.MODERATE if has_live_observation else ConfidenceLevel.LOW
        if hypothesis_id == "ssh_authentication_signal":
            confidence = ConfidenceLevel.LOW

        if confidence == ConfidenceLevel.MODERATE:
            rationale = (
                "Modérée pour le signal technique observé directement pendant cette collecte ; "
                "sa causalité avec l'incident reste non établie faute de corrélation temporelle et de vérification indépendante."
            )
        else:
            rationale = (
                "Faible : les preuves disponibles sont des alertes ou un signal indirect, sans journaux/métriques bruts "
                "et sans corroboration indépendante liée à l'heure de l'incident."
            )
        if hypothesis_id == "ssh_authentication_signal":
            rationale += (
                " Les rapports Logs et Sécurité peuvent décrire les mêmes événements du dataset."
            )
        unique_limitations = list(dict.fromkeys(limitations))
        if not unique_limitations:
            unique_limitations = [
                "Cette hypothèse décrit un signal compatible, pas une cause racine confirmée."
            ]
        return CauseHypothesis(
            hypothesis_id=hypothesis_id,
            title=title,
            explanation=explanation,
            confidence=confidence,
            confidence_rationale=rationale,
            supporting_evidence=evidence,
            counter_evidence=counter_evidence,
            limitations=unique_limitations,
            next_diagnostic_checks=checks,
        )

    @staticmethod
    def _data_gaps(reports: dict[str, AgentReport]) -> list[str]:
        gaps: list[str] = []
        for report_name, report in sorted(reports.items()):
            if report.status == AgentStatus.NO_DATA:
                gaps.append(f"{report_name} : {report.summary}")
            elif report.status == AgentStatus.ERROR:
                gaps.append(f"{report_name} : rapport indisponible ({report.summary})")
            gaps.extend(f"{report_name} : {item}" for item in report.limitations)
        return list(dict.fromkeys(gaps))
