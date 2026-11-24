from incident_response.agents.coordinator import CoordinatorAgent
from incident_response.orchestration.models import IncidentAssessment, IncidentInput


class IncidentWorkflow:
    """Explicit entry point for the diagnose-only incident workflow."""

    def __init__(self, coordinator: CoordinatorAgent | None = None) -> None:
        self.coordinator = coordinator or CoordinatorAgent()

    def run(self, incident: IncidentInput) -> IncidentAssessment:
        return self.coordinator.run(incident)
