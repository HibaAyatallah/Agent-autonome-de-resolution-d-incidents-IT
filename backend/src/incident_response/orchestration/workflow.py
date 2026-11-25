from incident_response.agents.coordinator import CoordinatorAgent
from incident_response.memory.repository import IncidentMemoryRepository
from incident_response.orchestration.models import IncidentAssessment, IncidentInput


class IncidentWorkflow:
    """Explicit entry point for the diagnose-only incident workflow."""

    def __init__(
        self,
        coordinator: CoordinatorAgent | None = None,
        memory_repository: IncidentMemoryRepository | None = None,
    ) -> None:
        self.coordinator = coordinator or CoordinatorAgent()
        self.memory_repository = memory_repository

    def run(self, incident: IncidentInput) -> IncidentAssessment:
        similar_incidents = []
        if self.memory_repository is not None:
            categories = self.coordinator.classify_categories(incident)
            similar_incidents = self.memory_repository.find_similar(incident, categories)
        assessment = self.coordinator.run(incident, similar_incidents)
        if self.memory_repository is not None:
            self.memory_repository.save(incident, assessment)
        return assessment
