from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self

from sqlalchemy import create_engine, func, select
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, sessionmaker

from incident_response.memory.models import IncidentMemoryRecord, MemoryBase
from incident_response.memory.schemas import IncidentHistoryItem, IncidentHistoryResponse
from incident_response.memory.settings import MemorySettings
from incident_response.orchestration.models import IncidentAssessment, IncidentInput
from incident_response.reasoning.models import SimilarIncidentReference
from incident_response.remediation.models import ApprovalStatus, ProposedRemediationPlan

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_EMAIL = re.compile(r"(?i)\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b")
_BEARER = re.compile(r"(?i)\bbearer\s+\S+")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(password|passwd|token|api[_-]?key|secret)\s*[:=]\s*[^\s,;]+"
)
_TOKEN = re.compile(r"[^\W_]{3,}", flags=re.UNICODE)
_STOP_WORDS = {
    "avec",
    "dans",
    "des",
    "les",
    "une",
    "pour",
    "sur",
    "the",
    "and",
    "for",
    "from",
    "with",
    "this",
    "that",
    "server",
    "serveur",
    "incident",
    "alerte",
    "alert",
    "general",
}
_SAFE_EVIDENCE_FIELDS = {
    "alert_name",
    "event_count",
    "cpu_percent",
    "ram_percent",
    "disk_percent",
    "threshold_percent",
    "reachable",
    "dns_resolved",
    "latency_ms",
}


def sanitize_memory_text(value: str) -> str:
    text = _BEARER.sub("Bearer [masqué]", value)
    text = _SECRET_ASSIGNMENT.sub(r"\1=[masqué]", text)
    text = _IPV4.sub("[IP masquée]", text)
    text = _EMAIL.sub("[email masqué]", text)
    return text[:2000]


def _tokens(value: str) -> set[str]:
    return {token for token in _TOKEN.findall(value.casefold()) if token not in _STOP_WORDS}


def _jaccard(left: set[str], right: set[str]) -> float:
    union = left | right
    return len(left & right) / len(union) if union else 0.0


def _sanitize_json_strings(value: Any) -> Any:
    if isinstance(value, str):
        return sanitize_memory_text(value)
    if isinstance(value, list):
        return [_sanitize_json_strings(item) for item in value]
    if isinstance(value, dict):
        return {key: _sanitize_json_strings(item) for key, item in value.items()}
    return value


class IncidentMemoryRepository:
    """SQLAlchemy-backed case memory with redacted text and lexical similarity."""

    def __init__(self, database_url: str | None = None) -> None:
        settings = MemorySettings()
        self.database_url = database_url or settings.database_url
        self.similar_case_limit = settings.similar_case_limit
        self.similar_case_minimum_score = settings.similar_case_minimum_score
        self.engine = self._create_engine(self.database_url)
        self._session_factory: sessionmaker[Session] = sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
        )
        MemoryBase.metadata.create_all(self.engine)

    @staticmethod
    def _create_engine(database_url: str):
        url = make_url(database_url)
        connect_args: dict[str, Any] = {}
        if url.drivername.startswith("sqlite"):
            connect_args["check_same_thread"] = False
            database = url.database
            if database and database != ":memory:" and not database.startswith("file:"):
                database_path = Path(database)
                if not database_path.is_absolute():
                    database_path = Path.cwd() / database_path
                database_path.parent.mkdir(parents=True, exist_ok=True)
        return create_engine(database_url, connect_args=connect_args, pool_pre_ping=True)

    def close(self) -> None:
        self.engine.dispose()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    @staticmethod
    def _search_text(incident: IncidentInput, assessment: IncidentAssessment) -> str:
        pieces = [sanitize_memory_text(incident.description)]
        pieces.extend(assessment.categories)
        pieces.extend(
            sanitize_memory_text(str(record.get("alert_name", "")))
            for record in incident.alert_records
            if record.get("alert_name")
        )
        pieces.extend(
            finding.code
            for report in assessment.agent_reports.values()
            for finding in report.findings
        )
        pieces.extend(hypothesis.hypothesis_id for hypothesis in assessment.reasoning.hypotheses)
        return " ".join(pieces)

    @staticmethod
    def _safe_findings(assessment: IncidentAssessment) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for agent_id, report in sorted(assessment.agent_reports.items()):
            for finding in report.findings:
                evidence = []
                for item in finding.evidence:
                    if item.field not in _SAFE_EVIDENCE_FIELDS:
                        continue
                    value = item.value
                    if isinstance(value, str):
                        value = sanitize_memory_text(value)
                    evidence.append(
                        {
                            "source": item.source,
                            "field": item.field,
                            "value": value,
                            "unit": item.unit,
                        }
                    )
                results.append(
                    {
                        "agent_id": agent_id,
                        "finding_code": finding.code,
                        "severity": finding.severity.value,
                        "evidence": evidence,
                    }
                )
        return results

    def save(self, incident: IncidentInput, assessment: IncidentAssessment) -> None:
        safe_description = sanitize_memory_text(incident.description)
        search_text = self._search_text(incident, assessment)
        hypotheses = [
            {
                "hypothesis_id": item.hypothesis_id,
                "confidence": item.confidence.value,
            }
            for item in assessment.reasoning.hypotheses
        ]
        created_at = (
            assessment.events[0].timestamp.isoformat()
            if assessment.events
            else datetime.now(UTC).isoformat()
        )

        values = {
            "incident_id": str(incident.incident_id),
            "created_at": created_at,
            "origin": incident.origin.value,
            "description": safe_description,
            "search_text": search_text,
            "categories": assessment.categories,
            "priority": assessment.priority.value,
            "workflow_status": assessment.status.value,
            "diagnosis_summary": sanitize_memory_text(assessment.reasoning.summary),
            "findings": self._safe_findings(assessment),
            "hypotheses": hypotheses,
            "proposed_remediation": (
                _sanitize_json_strings(assessment.remediation_plan.model_dump(mode="json"))
                if assessment.remediation_plan is not None
                else None
            ),
            # A plan is only a proposal; outcomes stay unset until verified by later phases.
            "root_cause": None,
            "executed_actions": None,
            "verification_result": None,
            "final_status": None,
        }
        with self._session_factory() as session:
            existing = session.get(IncidentMemoryRecord, str(incident.incident_id))
            if existing is None:
                session.add(IncidentMemoryRecord(**values))
            else:
                for key, value in values.items():
                    setattr(existing, key, value)
            session.commit()

    def list_history(
        self,
        *,
        limit: int = 20,
        offset: int = 0,
        query: str | None = None,
        priority: str | None = None,
        category: str | None = None,
    ) -> IncidentHistoryResponse:
        """Return a paginated, read-only view of stored redacted incident summaries."""
        if not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100.")
        if offset < 0:
            raise ValueError("offset must be non-negative.")

        statement = select(IncidentMemoryRecord)
        count_statement = select(func.count()).select_from(IncidentMemoryRecord)
        if query and query.strip():
            safe_query = sanitize_memory_text(query.strip()).casefold()
            statement = statement.where(
                func.lower(IncidentMemoryRecord.search_text).contains(safe_query)
                | func.lower(IncidentMemoryRecord.description).contains(safe_query)
                | func.lower(IncidentMemoryRecord.diagnosis_summary).contains(safe_query)
            )
            count_statement = count_statement.where(
                func.lower(IncidentMemoryRecord.search_text).contains(safe_query)
                | func.lower(IncidentMemoryRecord.description).contains(safe_query)
                | func.lower(IncidentMemoryRecord.diagnosis_summary).contains(safe_query)
            )
        if priority:
            statement = statement.where(IncidentMemoryRecord.priority == priority.upper())
            count_statement = count_statement.where(
                IncidentMemoryRecord.priority == priority.upper()
            )
        with self._session_factory() as session:
            if category:
                records = session.scalars(
                    statement.order_by(IncidentMemoryRecord.created_at.desc())
                ).all()
                filtered = [
                    record
                    for record in records
                    if category.casefold() in {item.casefold() for item in record.categories or []}
                ]
                total = len(filtered)
                records = filtered[offset : offset + limit]
            else:
                total = int(session.scalar(count_statement) or 0)
                records = session.scalars(
                    statement.order_by(IncidentMemoryRecord.created_at.desc())
                    .offset(offset)
                    .limit(limit)
                ).all()
        items = [
            IncidentHistoryItem(
                incident_id=record.incident_id,
                created_at=record.created_at,
                origin=record.origin,
                description=record.description,
                categories=record.categories or [],
                priority=record.priority,
                workflow_status=record.workflow_status,
                diagnosis_summary=record.diagnosis_summary,
                findings=record.findings or [],
                hypotheses=record.hypotheses or [],
                proposed_remediation=(
                    ProposedRemediationPlan.model_validate(record.proposed_remediation)
                    if record.proposed_remediation
                    else None
                ),
                final_status=record.final_status,
            )
            for record in records
        ]
        return IncidentHistoryResponse(items=items, total=total, limit=limit, offset=offset)

    def get_remediation_plan(self, incident_id: str) -> ProposedRemediationPlan | None:
        """Return a saved proposal without mutating approval or execution state."""
        with self._session_factory() as session:
            record = session.get(IncidentMemoryRecord, incident_id)
            if record is None or record.proposed_remediation is None:
                return None
            return ProposedRemediationPlan.model_validate(record.proposed_remediation)

    def record_remediation_decision(
        self,
        incident_id: str,
        *,
        decision: ApprovalStatus,
        reviewer_id: str,
        note: str | None,
        decided_at: datetime,
    ) -> ProposedRemediationPlan | None:
        """Persist an approval decision; this method never executes an action."""
        if decision not in {ApprovalStatus.APPROVED, ApprovalStatus.REJECTED}:
            raise ValueError("Only approve or reject decisions can be recorded.")
        with self._session_factory() as session:
            record = session.get(IncidentMemoryRecord, incident_id)
            if record is None or record.proposed_remediation is None:
                return None
            plan = ProposedRemediationPlan.model_validate(record.proposed_remediation)
            if not plan.actions:
                raise ValueError("A plan without proposed actions cannot be approved or rejected.")
            if plan.approval_status != ApprovalStatus.PENDING_APPROVAL:
                raise ValueError("This plan already has a decision.")
            values = plan.model_dump(mode="json")
            values.update(
                approval_status=decision.value,
                approval_decided_at=decided_at.isoformat(),
                approval_decided_by=reviewer_id,
                approval_note=sanitize_memory_text(note) if note else None,
            )
            updated = ProposedRemediationPlan.model_validate(values)
            record.proposed_remediation = updated.model_dump(mode="json")
            session.commit()
            return updated

    def find_similar(
        self,
        incident: IncidentInput,
        categories: list[str],
        limit: int | None = None,
        minimum_score: float | None = None,
    ) -> list[SimilarIncidentReference]:
        if limit is not None and not 1 <= limit <= 25:
            raise ValueError("limit must be between 1 and 25.")
        threshold = self.similar_case_minimum_score if minimum_score is None else minimum_score
        if not 0 <= threshold <= 1:
            raise ValueError("minimum_score must be between 0 and 1.")

        query_text = " ".join(
            [
                sanitize_memory_text(incident.description),
                *categories,
                *[
                    sanitize_memory_text(str(record["alert_name"]))
                    for record in incident.alert_records
                    if record.get("alert_name")
                ],
            ]
        )
        query_tokens = _tokens(query_text)
        query_categories = set(categories) - {"general"}
        candidates: list[tuple[float, IncidentMemoryRecord]] = []
        with self._session_factory() as session:
            statement = select(IncidentMemoryRecord).where(
                IncidentMemoryRecord.incident_id != str(incident.incident_id)
            )
            for record in session.scalars(statement):
                lexical_score = _jaccard(query_tokens, _tokens(record.search_text))
                record_categories = set(record.categories or []) - {"general"}
                category_score = _jaccard(query_categories, record_categories)
                if query_categories:
                    score = 0.8 * lexical_score + 0.2 * category_score
                else:
                    score = lexical_score
                if score >= threshold:
                    candidates.append((score, record))

        candidates.sort(key=lambda pair: (pair[0], pair[1].created_at), reverse=True)
        selected = candidates[: limit or self.similar_case_limit]
        return [
            SimilarIncidentReference(
                incident_id=record.incident_id,
                similarity=round(score, 4),
                categories=record.categories or [],
                priority=record.priority,
                workflow_status=record.workflow_status,
                hypothesis_ids=[item["hypothesis_id"] for item in record.hypotheses or []],
                final_status=record.final_status,
            )
            for score, record in selected
        ]
