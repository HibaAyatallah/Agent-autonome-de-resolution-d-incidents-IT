from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Severity(StrEnum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class ProcessMetric(BaseModel):
    pid: int
    name: str
    cpu_percent: float = Field(ge=0, le=100)
    memory_rss_bytes: int = Field(ge=0)


class SystemMetrics(BaseModel):
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    hostname: str
    cpu_percent: float = Field(ge=0, le=100)
    ram_percent: float = Field(ge=0, le=100)
    ram_available_bytes: int = Field(ge=0)
    disk_percent: float = Field(ge=0, le=100)
    disk_free_bytes: int = Field(ge=0)
    top_processes: list[ProcessMetric] = Field(default_factory=list)


class NetworkProbeResult(BaseModel):
    name: str
    host: str
    port: int = Field(ge=1, le=65535)
    dns_resolved: bool
    reachable: bool
    latency_ms: float | None = Field(default=None, ge=0)
    error: str | None = None
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class MonitoringAlert(BaseModel):
    model_config = ConfigDict(frozen=True)

    rule_id: str
    severity: Severity
    category: str
    metric: str
    observed_value: float | None = None
    threshold: float | None = None
    summary: str


class MonitoringSnapshot(BaseModel):
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    system: SystemMetrics
    network_checks: list[NetworkProbeResult] = Field(default_factory=list)
    alerts: list[MonitoringAlert] = Field(default_factory=list)
