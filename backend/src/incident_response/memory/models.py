from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class MemoryBase(DeclarativeBase):
    pass


class IncidentMemoryRecord(MemoryBase):
    __tablename__ = "incident_memory"

    incident_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40), index=True)
    origin: Mapped[str] = mapped_column(String(32))
    description: Mapped[str] = mapped_column(Text)
    search_text: Mapped[str] = mapped_column(Text, index=True)
    categories: Mapped[list[str]] = mapped_column(JSON)
    priority: Mapped[str] = mapped_column(String(20))
    workflow_status: Mapped[str] = mapped_column(String(32))
    diagnosis_summary: Mapped[str] = mapped_column(Text)
    findings: Mapped[list[dict]] = mapped_column(JSON)
    hypotheses: Mapped[list[dict]] = mapped_column(JSON)

    # These outcome fields stay NULL until later phases produce verified outcomes.
    root_cause: Mapped[str | None] = mapped_column(Text, nullable=True)
    proposed_remediation: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    executed_actions: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)
    verification_result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    final_status: Mapped[str | None] = mapped_column(String(32), nullable=True)

    updated_at: Mapped[str] = mapped_column(
        String(40),
        default=lambda: datetime.now(UTC).isoformat(),
        onupdate=lambda: datetime.now(UTC).isoformat(),
    )
