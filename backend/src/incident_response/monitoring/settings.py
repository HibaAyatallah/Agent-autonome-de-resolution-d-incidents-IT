from __future__ import annotations

from dataclasses import dataclass

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class MonitoringEnvironment(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    cpu_warning: float = Field(default=80.0, validation_alias="MONITOR_CPU_WARNING")
    cpu_critical: float = Field(default=95.0, validation_alias="MONITOR_CPU_CRITICAL")
    ram_warning: float = Field(default=85.0, validation_alias="MONITOR_RAM_WARNING")
    ram_critical: float = Field(default=95.0, validation_alias="MONITOR_RAM_CRITICAL")
    disk_warning: float = Field(default=85.0, validation_alias="MONITOR_DISK_WARNING")
    disk_critical: float = Field(default=95.0, validation_alias="MONITOR_DISK_CRITICAL")
    network_targets: str = Field(default="", validation_alias="INCIDENT_NETWORK_TARGETS")

    @property
    def thresholds(self) -> DetectionThresholds:
        return DetectionThresholds(
            cpu_warning=self.cpu_warning,
            cpu_critical=self.cpu_critical,
            ram_warning=self.ram_warning,
            ram_critical=self.ram_critical,
            disk_warning=self.disk_warning,
            disk_critical=self.disk_critical,
        )

@dataclass(frozen=True)
class DetectionThresholds:
    cpu_warning: float = 80.0
    cpu_critical: float = 95.0
    ram_warning: float = 85.0
    ram_critical: float = 95.0
    disk_warning: float = 85.0
    disk_critical: float = 95.0

    def __post_init__(self) -> None:
        for name in (
            "cpu_warning",
            "cpu_critical",
            "ram_warning",
            "ram_critical",
            "disk_warning",
            "disk_critical",
        ):
            value = getattr(self, name)
            if not 0 <= value <= 100:
                raise ValueError(f"{name} must be between 0 and 100.")
        if self.cpu_warning >= self.cpu_critical:
            raise ValueError("CPU warning threshold must be below its critical threshold.")
        if self.ram_warning >= self.ram_critical:
            raise ValueError("RAM warning threshold must be below its critical threshold.")
        if self.disk_warning >= self.disk_critical:
            raise ValueError("Disk warning threshold must be below its critical threshold.")

    @classmethod
    def from_environment(cls) -> DetectionThresholds:
        return MonitoringEnvironment().thresholds


@dataclass(frozen=True)
class NetworkTarget:
    host: str
    port: int
    name: str
    timeout_seconds: float = 2.0

    def __post_init__(self) -> None:
        if not self.host or any(character.isspace() for character in self.host):
            raise ValueError("Network target host must be a non-empty hostname or IP address.")
        if not 1 <= self.port <= 65535:
            raise ValueError("Network target port must be between 1 and 65535.")
        if not 0.1 <= self.timeout_seconds <= 10:
            raise ValueError("Network target timeout must be between 0.1 and 10 seconds.")


def network_targets_from_environment() -> list[NetworkTarget]:
    """Parse explicitly configured TCP targets: `name=host:port,host:port`."""
    configured = MonitoringEnvironment().network_targets.strip()
    if not configured:
        return []

    targets = []
    for entry in configured.split(","):
        entry = entry.strip()
        if not entry:
            continue
        if "=" in entry:
            name, address = entry.split("=", 1)
            name = name.strip()
        else:
            address = entry
            name = address.strip()
        host, separator, port_text = address.rpartition(":")
        if not separator or not host.strip() or not name:
            raise ValueError(f"Invalid network target {entry!r}; expected name=host:port.")
        try:
            port = int(port_text)
        except ValueError as exc:
            raise ValueError(f"Invalid port in network target {entry!r}.") from exc
        targets.append(NetworkTarget(host=host.strip(), port=port, name=name))
    return targets
