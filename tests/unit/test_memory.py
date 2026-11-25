import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from incident_response.agents.coordinator import CoordinatorAgent
from incident_response.memory.models import IncidentMemoryRecord
from incident_response.memory.repository import IncidentMemoryRepository
from incident_response.orchestration.models import IncidentInput, IncidentOrigin
from incident_response.orchestration.workflow import IncidentWorkflow
from sqlalchemy import select


class IncidentMemoryTests(unittest.TestCase):
    def make_repository(self, directory: str) -> IncidentMemoryRepository:
        database_path = Path(directory) / "incidents.sqlite"
        database_url = f"sqlite:///{database_path.as_posix()}"
        return IncidentMemoryRepository(database_url=database_url)

    def test_workflow_persists_case_and_retrieves_it_after_repository_restart(self) -> None:
        with TemporaryDirectory() as directory:
            with self.make_repository(directory) as first_repo:
                first_input = IncidentInput(
                    origin=IncidentOrigin.DATASET,
                    description="SSH authentication failures on server",
                    alert_records=[
                        {
                            "source_type": "log",
                            "alert_name": "SSH Authentication Failure",
                            "summary": "Several authentication failures were reported.",
                        }
                    ],
                )
                first_result = IncidentWorkflow(
                    coordinator=CoordinatorAgent(),
                    memory_repository=first_repo,
                ).run(first_input)

            with self.make_repository(directory) as restarted_repo:
                second_input = IncidentInput(
                    origin=IncidentOrigin.USER,
                    description="SSH authentication failures on server",
                    alert_records=[
                        {
                            "source_type": "log",
                            "alert_name": "SSH Authentication Failure",
                        }
                    ],
                )
                second_result = IncidentWorkflow(
                    coordinator=CoordinatorAgent(),
                    memory_repository=restarted_repo,
                ).run(second_input)

                self.assertEqual(first_result.reasoning.similar_incidents, [])
                self.assertEqual(len(second_result.reasoning.similar_incidents), 1)
                similar = second_result.reasoning.similar_incidents[0]
                self.assertEqual(similar.incident_id, str(first_input.incident_id))
                self.assertGreaterEqual(similar.similarity, 0.25)
                self.assertEqual(similar.final_status, None)
                self.assertEqual(
                    second_result.reasoning.hypotheses[0].confidence.value,
                    "low",
                    "Prior similar cases must not inflate current confidence.",
                )

    def test_memory_redacts_identifiers_and_secrets_and_leaves_outcome_unknown(self) -> None:
        with TemporaryDirectory() as directory, self.make_repository(directory) as repository:
            incident = IncidentInput(
                    description=(
                        "SSH failure from 192.0.2.44 user@example.com "
                        "token=private-value password=secret-value"
                    ),
                    alert_records=[
                        {"source_type": "log", "alert_name": "SSH Authentication Failure"}
                    ],
                )
            result = IncidentWorkflow(
                coordinator=CoordinatorAgent(),
                memory_repository=repository,
            ).run(incident)

            with repository._session_factory() as session:
                stored = session.get(IncidentMemoryRecord, str(incident.incident_id))
                self.assertIsNotNone(stored)
                self.assertIn("[IP masquée]", stored.description)
                self.assertIn("[email masqué]", stored.description)
                self.assertNotIn("private-value", stored.description)
                self.assertNotIn("secret-value", stored.description)
                self.assertIsNone(stored.root_cause)
                self.assertIsNone(stored.proposed_remediation)
                self.assertIsNone(stored.executed_actions)
                self.assertIsNone(stored.verification_result)
                self.assertIsNone(stored.final_status)
                self.assertEqual(
                    stored.hypotheses[0]["hypothesis_id"], "ssh_authentication_signal"
                )

                self.assertEqual(result.reasoning.similar_incidents, [])

    def test_reusing_incident_id_updates_existing_record_idempotently(self) -> None:
        with TemporaryDirectory() as directory, self.make_repository(directory) as repository:
            incident_id = uuid4()
            first = IncidentInput(incident_id=incident_id, description="CPU saturation")
            first_assessment = CoordinatorAgent().run(first)
            repository.save(first, first_assessment)

            second = IncidentInput(
                incident_id=incident_id, description="CPU saturation after more data"
            )
            second_assessment = CoordinatorAgent().run(second)
            repository.save(second, second_assessment)

            with repository._session_factory() as session:
                records = list(session.scalars(select(IncidentMemoryRecord)))
                self.assertEqual(len(records), 1)
                self.assertEqual(records[0].description, second.description)

    def test_unrelated_case_is_not_returned_as_similar(self) -> None:
        with TemporaryDirectory() as directory, self.make_repository(directory) as repository:
            saved = IncidentInput(description="Database connection pool exhausted")
            repository.save(saved, CoordinatorAgent().run(saved))
            query = IncidentInput(description="Printer paper jam in office")
            self.assertEqual(
                repository.find_similar(query, categories=["general"]),
                [],
            )


if __name__ == "__main__":
    unittest.main()
