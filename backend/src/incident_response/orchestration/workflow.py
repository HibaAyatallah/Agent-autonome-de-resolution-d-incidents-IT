from incident_response.agents.coordinator import CoordinatorAgent
from incident_response.memory.repository import IncidentMemoryRepository
from incident_response.orchestration.models import IncidentAssessment, IncidentInput, WorkflowEvent
from incident_response.remediation.planner import RemediationPlanner


class IncidentWorkflow:
    """Explicit entry point for the diagnose-only incident workflow."""

    def __init__(
        self,
        coordinator: CoordinatorAgent | None = None,
        memory_repository: IncidentMemoryRepository | None = None,
    ) -> None:
        self.coordinator = coordinator or CoordinatorAgent()
        self.memory_repository = memory_repository
        self.remediation_planner = RemediationPlanner()

    def run(self, incident: IncidentInput) -> IncidentAssessment:
        similar_incidents = []
        if self.memory_repository is not None:
            categories = self.coordinator.classify_categories(incident)
            similar_incidents = self.memory_repository.find_similar(incident, categories)
        assessment = self.coordinator.run(incident, similar_incidents)
        plan = self.remediation_planner.build(incident.incident_id, assessment.reasoning)
        assessment = assessment.model_copy(
            update={
                "remediation_plan": plan,
                "events": [
                    *assessment.events,
                    WorkflowEvent(
                        event_type="remediation_plan_proposed",
                        actor="remediation_planner",
                        message=plan.summary,
                    ),
                ],
            }
        )
        if self.memory_repository is not None:
            self.memory_repository.save(incident, assessment)
        return assessment
