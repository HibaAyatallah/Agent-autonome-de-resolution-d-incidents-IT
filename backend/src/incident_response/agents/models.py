from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AgentStatus(StrEnum):
    OK = "ok"
    NO_DATA = "no_data"
    ERROR = "error"


class FindingSeverity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Evidence(BaseModel):
    model_config = ConfigDict(frozen=True)

    source: str
    field: str
    value: str | int | float | bool | None
    unit: str | None = None


class AgentFinding(BaseModel):
    code: str
    title: str
    severity: FindingSeverity
    summary: str
    evidence: list[Evidence] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class AgentReport(BaseModel):
    agent_id: str
    status: AgentStatus
    summary: str
    input_count: int = Field(ge=0)
    findings: list[AgentFinding] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


AlertRecord = dict[str, Any]
