from __future__ import annotations

from collections import defaultdict
from uuid import UUID

from incident_response.reasoning.models import ReasoningAssessment, ReasoningEvidence
from incident_response.remediation.models import (
    ApprovalStatus,
    BlockedRecommendation,
    NetworkLatencyParameters,
    NetworkReachabilityParameters,
    ProposedActionType,
    ProposedRemediationAction,
    ProposedRemediationPlan,
    RemediationPlanStatus,
    ResourceMetric,
    ResourceReviewParameters,
    RiskLevel,
)

_RESOURCE_FIELDS = {
    "cpu_percent": ResourceMetric.CPU,
    "ram_percent": ResourceMetric.RAM,
    "disk_percent": ResourceMetric.DISK,
}

_BLOCK_REASONS = {
    "system_resource_pressure": (
        "Les preuves ne contiennent pas de mesure hôte et de seuil directement associés ; "
        "une alerte historique seule ne suffit pas à recommander une correction de ressource."
    ),
    "network_service_reachability": (
        "Aucun contrôle TCP direct avec cible et résultat d'accessibilité n'est fourni."
    ),
    "network_latency": "Aucune mesure de latence réseau directe n'est disponible.",
    "network_usage_alert": (
        "L'alerte du dataset ne contient ni métrique réseau brute, ni série temporelle, ni cible précise."
    ),
    "ssh_authentication_signal": (
        "Les alertes SSH ne contiennent pas les lignes d'authentification brutes ni une preuve d'attaque réussie ; "
        "aucun blocage d'adresse ou désactivation de compte n'est proposé."
    ),
    "monitoring_data_source_issue": (
        "L'alerte de source ne contient pas les journaux ou l'état technique nécessaires pour recommander une modification."
    ),
    "service_availability_signal": (
        "L'alerte ne précise pas de cible vérifiée et ne confirme pas l'état du service ; aucun redémarrage n'est proposé."
    ),
}


class RemediationPlanner:
    """Create human-reviewed, read-only recommendations from direct evidence only."""

    def build(self, incident_id: UUID, reasoning: ReasoningAssessment) -> ProposedRemediationPlan:
        actions: list[ProposedRemediationAction] = []
        blocked: list[BlockedRecommendation] = []
        seen_actions: set[tuple[object, ...]] = set()

        for hypothesis in reasoning.hypotheses:
            proposed = self._actions_for_hypothesis(
                hypothesis.hypothesis_id, hypothesis.supporting_evidence
            )
            if not proposed:
                blocked.append(
                    BlockedRecommendation(
                        hypothesis_id=hypothesis.hypothesis_id,
                        reason=_BLOCK_REASONS.get(
                            hypothesis.hypothesis_id,
                            "Les preuves ne correspondent à aucun type d'action autorisé dans cette phase.",
                        ),
                        evidence=hypothesis.supporting_evidence,
                    )
                )
                continue
            for action in proposed:
                key = (
                    action.action_type,
                    action.parameters.model_dump_json(),
                )
                if key not in seen_actions:
                    seen_actions.add(key)
                    actions.append(action)

        has_actions = bool(actions)
        if has_actions:
            status = RemediationPlanStatus.PENDING_APPROVAL
            approval_status = ApprovalStatus.PENDING_APPROVAL
            summary = (
                f"{len(actions)} recommandation(s) en lecture seule sont proposées et attendent une validation humaine. "
                "Aucune action n'a été exécutée."
            )
        else:
            status = RemediationPlanStatus.INSUFFICIENT_EVIDENCE
            approval_status = ApprovalStatus.NOT_REQUIRED
            summary = (
                "Aucune recommandation autorisée ne peut être proposée avec les preuves disponibles. "
                "Aucune action n'a été exécutée."
            )

        limitations = [
            "Les hypothèses de diagnostic ne sont pas des causes racines confirmées.",
            "Ce plan ne contient que des contrôles en lecture seule ; aucune commande, configuration ou donnée système n'est modifiée.",
            "L'approbation reste à effectuer hors de cette phase ; aucun mécanisme d'approbation ou d'exécution n'est exposé.",
        ]
        return ProposedRemediationPlan(
            incident_id=incident_id,
            status=status,
            summary=summary,
            approval_status=approval_status,
            approval_required=has_actions,
            actions=actions,
            blocked_recommendations=blocked,
            limitations=limitations,
        )

    def _actions_for_hypothesis(
        self,
        hypothesis_id: str,
        evidence: list[ReasoningEvidence],
    ) -> list[ProposedRemediationAction]:
        by_finding: dict[tuple[str, str], list[ReasoningEvidence]] = defaultdict(list)
        for item in evidence:
            by_finding[(item.agent_id, item.finding_code)].append(item)

        if hypothesis_id == "system_resource_pressure":
            return self._resource_actions(hypothesis_id, by_finding)
        if hypothesis_id == "network_service_reachability":
            return self._reachability_actions(hypothesis_id, by_finding)
        if hypothesis_id == "network_latency":
            return self._latency_actions(hypothesis_id, by_finding)
        return []

    @staticmethod
    def _resource_actions(
        hypothesis_id: str,
        by_finding: dict[tuple[str, str], list[ReasoningEvidence]],
    ) -> list[ProposedRemediationAction]:
        actions: list[ProposedRemediationAction] = []
        for (_, finding_code), items in by_finding.items():
            observed = next(
                (
                    item
                    for item in items
                    if item.source == "host_metrics"
                    and item.field in _RESOURCE_FIELDS
                    and isinstance(item.value, (int, float))
                    and not isinstance(item.value, bool)
                    and item.severity.value in {"warning", "critical"}
                ),
                None,
            )
            threshold = next(
                (
                    item
                    for item in items
                    if item.source == "monitoring_rule"
                    and item.field == "threshold_percent"
                    and isinstance(item.value, (int, float))
                    and not isinstance(item.value, bool)
                ),
                None,
            )
            if observed is None or threshold is None or observed.value <= threshold.value:
                continue
            metric = _RESOURCE_FIELDS[observed.field]
            actions.append(
                ProposedRemediationAction(
                    action_id=f"review-{metric.value}-{finding_code}",
                    hypothesis_id=hypothesis_id,
                    action_type=ProposedActionType.REVIEW_RESOURCE_METRICS,
                    title=f"Examiner la mesure {metric.value.upper()} relevée",
                    description=(
                        f"Faire vérifier la mesure {observed.value:g} % par rapport au seuil "
                        f"{threshold.value:g} %, puis la corréler à l'heure de l'incident."
                    ),
                    rationale=(
                        "Cette recommandation découle de l'observation directe des métriques hôte "
                        "et du seuil de la règle correspondante."
                    ),
                    parameters=ResourceReviewParameters(
                        parameter_type="resource_review",
                        metric=metric,
                        observed_percent=float(observed.value),
                        threshold_percent=float(threshold.value),
                    ),
                    evidence=items,
                    risk_level=RiskLevel.LOW,
                    risk_explanation="Vérification humaine en lecture seule ; aucune charge ni configuration ne change.",
                    limitations=[
                        "Un instantané ponctuel ne prouve pas que cette ressource est la cause de l'incident.",
                        "Le plan ne recommande pas de tuer un processus, redémarrer un service ou modifier la capacité.",
                    ],
                )
            )
        return actions

    @staticmethod
    def _reachability_actions(
        hypothesis_id: str,
        by_finding: dict[tuple[str, str], list[ReasoningEvidence]],
    ) -> list[ProposedRemediationAction]:
        actions: list[ProposedRemediationAction] = []
        for (_, finding_code), items in by_finding.items():
            target = next(
                (
                    item.value
                    for item in items
                    if item.source == "tcp_probe"
                    and item.field == "target_name"
                    and isinstance(item.value, str)
                ),
                None,
            )
            unreachable = any(
                item.source == "tcp_probe" and item.field == "reachable" and item.value is False
                for item in items
            )
            if not target or not unreachable:
                continue
            actions.append(
                ProposedRemediationAction(
                    action_id=f"verify-network-{finding_code}",
                    hypothesis_id=hypothesis_id,
                    action_type=ProposedActionType.VERIFY_NETWORK_REACHABILITY,
                    title=f"Vérifier l'accessibilité de {target}",
                    description=(
                        "Faire confirmer le résultat depuis un second point et vérifier le service distant "
                        "avant d'envisager une modification."
                    ),
                    rationale="Une sonde TCP configurée rapporte que cette cible n'est pas joignable.",
                    parameters=NetworkReachabilityParameters(
                        parameter_type="network_reachability",
                        target_name=target,
                        reachable=False,
                    ),
                    evidence=items,
                    risk_level=RiskLevel.LOW,
                    risk_explanation="Contrôle de connectivité en lecture seule ; aucune connexion n'est relancée par cette API.",
                    limitations=[
                        "Une sonde échouée ne distingue pas une panne réseau d'un service indisponible.",
                        "Cette recommandation ne redémarre pas la cible et ne change aucun pare-feu.",
                    ],
                )
            )
        return actions

    @staticmethod
    def _latency_actions(
        hypothesis_id: str,
        by_finding: dict[tuple[str, str], list[ReasoningEvidence]],
    ) -> list[ProposedRemediationAction]:
        actions: list[ProposedRemediationAction] = []
        for (_, finding_code), items in by_finding.items():
            target = next(
                (
                    item.value
                    for item in items
                    if item.source == "tcp_probe"
                    and item.field == "target_name"
                    and isinstance(item.value, str)
                ),
                None,
            )
            latency = next(
                (
                    item
                    for item in items
                    if item.source == "tcp_probe"
                    and item.field == "latency_ms"
                    and isinstance(item.value, (int, float))
                    and not isinstance(item.value, bool)
                ),
                None,
            )
            if not target or latency is None:
                continue
            actions.append(
                ProposedRemediationAction(
                    action_id=f"review-network-latency-{finding_code}",
                    hypothesis_id=hypothesis_id,
                    action_type=ProposedActionType.REVIEW_NETWORK_LATENCY,
                    title=f"Examiner la latence mesurée vers {target}",
                    description=(
                        f"Faire comparer la mesure de {latency.value:g} ms à une série temporelle "
                        "et à d'autres cibles avant toute modification réseau."
                    ),
                    rationale="La sonde TCP fournit directement une mesure de latence pour cette cible.",
                    parameters=NetworkLatencyParameters(
                        parameter_type="network_latency",
                        target_name=target,
                        latency_ms=float(latency.value),
                    ),
                    evidence=items,
                    risk_level=RiskLevel.LOW,
                    risk_explanation="Analyse humaine de la mesure ; aucune configuration réseau ne change.",
                    limitations=[
                        "La latence d'une sonde ponctuelle ne confirme pas la cause de l'incident.",
                        "Le seuil de la sonde n'est pas conservé dans la preuve et n'est pas répété comme une observation.",
                    ],
                )
            )
        return actions
