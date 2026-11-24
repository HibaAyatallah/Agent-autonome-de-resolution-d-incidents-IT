from __future__ import annotations

import socket
import time
from pathlib import Path

from incident_response.monitoring.models import NetworkProbeResult, ProcessMetric, SystemMetrics
from incident_response.monitoring.settings import NetworkTarget


def collect_system_metrics(
    disk_path: str | Path | None = None,
    process_limit: int = 5,
    cpu_sample_seconds: float = 0.1,
) -> SystemMetrics:
    """Collect a read-only snapshot from the host running this process."""
    try:
        import psutil
    except ImportError as exc:
        raise RuntimeError("Install project dependencies with `python -m pip install -e .[dev]`.") from exc

    if process_limit < 0 or process_limit > 20:
        raise ValueError("process_limit must be between 0 and 20.")
    if not 0 <= cpu_sample_seconds <= 2:
        raise ValueError("cpu_sample_seconds must be between 0 and 2 seconds.")

    target_path = Path(disk_path) if disk_path is not None else Path.cwd().anchor
    if not target_path:
        target_path = Path.cwd()
    cpu_percent = psutil.cpu_percent(interval=cpu_sample_seconds)
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage(str(target_path))

    processes: list[tuple[int, str, int, object]] = []
    for process in psutil.process_iter(attrs=["pid", "name", "memory_info"]):
        try:
            info = process.info
            memory_info = info.get("memory_info")
            if memory_info is None:
                continue
            processes.append(
                (int(info["pid"]), str(info.get("name") or "unknown"), int(memory_info.rss), process)
            )
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, KeyError, TypeError):
            continue

    processes.sort(key=lambda item: item[2], reverse=True)
    top_processes = []
    logical_cpu_count = max(1, psutil.cpu_count() or 1)
    for pid, name, rss, process in processes[:process_limit]:
        try:
            process_cpu = float(process.cpu_percent(interval=0.05)) / logical_cpu_count
        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
            process_cpu = 0.0
        top_processes.append(
            ProcessMetric(
                pid=pid,
                name=name,
                cpu_percent=max(0.0, min(100.0, process_cpu)),
                memory_rss_bytes=rss,
            )
        )

    return SystemMetrics(
        hostname=socket.gethostname(),
        cpu_percent=max(0.0, min(100.0, float(cpu_percent))),
        ram_percent=float(memory.percent),
        ram_available_bytes=int(memory.available),
        disk_percent=float(disk.percent),
        disk_free_bytes=int(disk.free),
        top_processes=top_processes,
    )


def check_tcp_target(target: NetworkTarget) -> NetworkProbeResult:
    """Resolve a configured host and test its TCP service without shell commands."""
    try:
        addresses = socket.getaddrinfo(
            target.host,
            target.port,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror:
        return NetworkProbeResult(
            name=target.name,
            host=target.host,
            port=target.port,
            dns_resolved=False,
            reachable=False,
            error="dns_resolution_failed",
        )

    start = time.perf_counter()
    last_error = "connection_failed"
    for family, socktype, protocol, _, sockaddr in addresses:
        try:
            with socket.socket(family, socktype, protocol) as connection:
                connection.settimeout(target.timeout_seconds)
                connection.connect(sockaddr)
            elapsed_ms = (time.perf_counter() - start) * 1000
            return NetworkProbeResult(
                name=target.name,
                host=target.host,
                port=target.port,
                dns_resolved=True,
                reachable=True,
                latency_ms=elapsed_ms,
            )
        except TimeoutError:
            last_error = "connection_timeout"
        except OSError:
            last_error = "connection_failed"

    return NetworkProbeResult(
        name=target.name,
        host=target.host,
        port=target.port,
        dns_resolved=True,
        reachable=False,
        latency_ms=(time.perf_counter() - start) * 1000,
        error=last_error,
    )
