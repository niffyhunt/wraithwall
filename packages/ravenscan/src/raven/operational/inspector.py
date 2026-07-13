"""Phase 6 — Operational Intelligence.

Inspects runtime systems and surfaces anomalies before failures occur.
- Docker containers
- Systemd services
- System resources (CPU, memory, disk)
- Process health
- Database health
- Redis/queue health
- Background workers
- Long-running processes

v0.1: Foundation with Docker and system resource checks.
Gracefully degrades when dependencies (docker-py, psutil) are absent.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from raven.core.models import OperationalHealthModel


@dataclass
class ContainerInfo:
    """Status of a single Docker container."""

    name: str
    image: str
    status: str
    state: str  # running, exited, paused
    ports: list[str] = field(default_factory=list)
    health: str = "unknown"
    started_at: str = ""
    restart_count: int = 0


@dataclass
class SystemResource:
    """System resource snapshot."""

    cpu_percent: float = 0.0
    memory_total_mb: float = 0.0
    memory_used_mb: float = 0.0
    memory_percent: float = 0.0
    disk_total_gb: float = 0.0
    disk_used_gb: float = 0.0
    disk_percent: float = 0.0
    load_avg_1: float = 0.0
    load_avg_5: float = 0.0
    load_avg_15: float = 0.0


@dataclass
class ProcessInfo:
    """Information about a running process."""

    pid: int
    name: str
    status: str
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    uptime_seconds: float = 0.0
    restart_count: int = 0


@dataclass
class OperationalHealth:
    """Complete operational intelligence snapshot."""

    scanned_at: str
    containers: list[ContainerInfo] = field(default_factory=list)
    systemd_services: list[dict[str, str]] = field(default_factory=list)
    system_resources: Optional[SystemResource] = None
    processes: list[ProcessInfo] = field(default_factory=list)
    anomalies: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    has_docker: bool = False
    has_systemd: bool = False
    has_psutil: bool = False
    overall_status: str = "unknown"


def analyze(config_path: Optional[Path] = None) -> OperationalHealth:
    """Collect operational intelligence from the runtime environment.

    Args:
        config_path: Optional repository path for context. Not used for runtime
                     inspection but passed for interface consistency.

    Returns:
        OperationalHealth with all collected data. Gracefully degrades when
        dependencies are absent.
    """
    now = datetime.now(timezone.utc).isoformat()
    health = OperationalHealth(scanned_at=now)

    health.has_docker = shutil.which("docker") is not None
    health.has_systemd = _detect_systemd()
    health.has_psutil = _try_import_psutil()

    if health.has_docker:
        health.containers = _inspect_docker_containers()

    if health.has_systemd:
        health.systemd_services = _inspect_systemd_services()

    if health.has_psutil:
        health.system_resources = _collect_system_resources()
        health.processes = _collect_process_info()

    health.anomalies = _detect_anomalies(health)
    health.overall_status = _assess_status(health)

    return health


def _try_import_psutil() -> bool:
    try:
        import psutil  # type: ignore[import-untyped] # noqa: F401
        return True
    except ImportError:
        return False


def _detect_systemd() -> bool:
    """Check if systemd is available on this system."""
    return Path("/run/systemd/system").exists() or Path("/sys/fs/cgroup/systemd").exists()


def _inspect_docker_containers() -> list[ContainerInfo]:
    """Query Docker for running container information."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}|{{.Image}}|{{.Status}}|{{.State}}|{{.Ports}}"],
            capture_output=True, text=True, timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, PermissionError):
        return []

    containers: list[ContainerInfo] = []
    for line in result.stdout.strip().split("\n"):
        if not line:
            continue
        parts = line.split("|")
        if len(parts) < 4:
            continue
        name, image, status, state, *rest = parts
        ports = rest[0].split(", ") if rest and rest[0] else []

        health_status = "unknown"
        health_result = subprocess.run(
            ["docker", "inspect", "--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}", name],
            capture_output=True, text=True, timeout=5,
        )
        if health_result.returncode == 0:
            health_status = health_result.stdout.strip()

        started = ""
        started_result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.StartedAt}}", name],
            capture_output=True, text=True, timeout=5,
        )
        if started_result.returncode == 0:
            started = started_result.stdout.strip()

        restart_count = 0
        restart_result = subprocess.run(
            ["docker", "inspect", "--format", "{{.RestartCount}}", name],
            capture_output=True, text=True, timeout=5,
        )
        if restart_result.returncode == 0:
            try:
                restart_count = int(restart_result.stdout.strip())
            except ValueError:
                pass

        containers.append(ContainerInfo(
            name=name,
            image=image,
            status=status,
            state=state,
            ports=ports,
            health=health_status,
            started_at=started,
            restart_count=restart_count,
        ))

    return containers


def _inspect_systemd_services() -> list[dict[str, str]]:
    """Query systemd for active service status."""
    unit_patterns = [
        "gunicorn", "nginx", "apache2", "caddy", "postgresql", "mysql",
        "redis", "mongod", "celery", "supervisor", "docker", "containerd",
    ]
    services: list[dict[str, str]] = []

    for pattern in unit_patterns:
        try:
            result = subprocess.run(
                ["systemctl", "is-active", f"{pattern}.service", "--quiet"],
                capture_output=True, timeout=3,
            )
            if result.returncode == 0:
                status_result = subprocess.run(
                    ["systemctl", "show", f"{pattern}.service", "--property=ActiveState,SubState,LoadState"],
                    capture_output=True, text=True, timeout=3,
                )
                info: dict[str, str] = {"name": pattern, "active": "yes"}
                for line in status_result.stdout.strip().split("\n"):
                    if "=" in line:
                        k, v = line.split("=", 1)
                        info[k.lower()] = v
                services.append(info)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue

    return services


def _collect_system_resources() -> SystemResource:
    """Collect CPU, memory, and disk statistics using psutil."""
    try:
        import psutil  # type: ignore[import-untyped,unused-ignore]

        cpu = psutil.cpu_percent(interval=0.5)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        load = os.getloadavg() if hasattr(os, "getloadavg") else (0.0, 0.0, 0.0)

        return SystemResource(
            cpu_percent=cpu,
            memory_total_mb=round(mem.total / (1024 * 1024), 1),
            memory_used_mb=round(mem.used / (1024 * 1024), 1),
            memory_percent=mem.percent,
            disk_total_gb=round(disk.total / (1024 ** 3), 1),
            disk_used_gb=round(disk.used / (1024 ** 3), 1),
            disk_percent=disk.percent,
            load_avg_1=load[0],
            load_avg_5=load[1],
            load_avg_15=load[2],
        )
    except Exception:
        return SystemResource()


def _collect_process_info() -> list[ProcessInfo]:
    """Collect information about long-running and background processes."""
    try:
        import psutil  # type: ignore[import-untyped,unused-ignore]

        bg_keywords = ["python", "gunicorn", "celery", "redis", "postgres", "mysql", "node", "java"]

        processes: list[ProcessInfo] = []
        for proc in psutil.process_iter(["pid", "name", "status", "cpu_percent", "memory_info", "create_time"]):
            try:
                info = proc.info
                name = info.get("name", "")
                if not any(kw in name.lower() for kw in bg_keywords):
                    continue

                mem_mb = 0.0
                if info.get("memory_info"):
                    mem_mb = info["memory_info"].rss / (1024 * 1024)

                uptime = 0.0
                if info.get("create_time"):
                    uptime = datetime.now().timestamp() - info["create_time"]

                processes.append(ProcessInfo(
                    pid=info["pid"],
                    name=name,
                    status=info.get("status", "unknown"),
                    cpu_percent=info.get("cpu_percent", 0.0) or 0.0,
                    memory_mb=round(mem_mb, 1),
                    uptime_seconds=uptime,
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return processes
    except Exception:
        return []


def _detect_anomalies(health: OperationalHealth) -> list[str]:
    """Detect operational anomalies from collected data."""
    anomalies: list[str] = []

    for c in health.containers:
        if c.state == "exited":
            anomalies.append(f"Container '{c.name}' is exited (restart count: {c.restart_count})")
        elif c.state == "paused":
            anomalies.append(f"Container '{c.name}' is paused")
        elif c.health == "unhealthy" and c.state == "running":
            anomalies.append(f"Container '{c.name}' is running but health check failed")
        if c.restart_count > 5:
            anomalies.append(f"Container '{c.name}' has restarted {c.restart_count} times")

    if health.system_resources:
        sr = health.system_resources
        if sr.cpu_percent > 90:
            anomalies.append(f"CPU usage is critical: {sr.cpu_percent}%")
        elif sr.cpu_percent > 75:
            health.warnings.append(f"CPU usage is high: {sr.cpu_percent}%")
        if sr.memory_percent > 90:
            anomalies.append(f"Memory usage is critical: {sr.memory_percent}%")
        elif sr.memory_percent > 75:
            health.warnings.append(f"Memory usage is high: {sr.memory_percent}%")
        if sr.disk_percent > 90:
            anomalies.append(f"Disk usage is critical: {sr.disk_percent}%")
        elif sr.disk_percent > 80:
            health.warnings.append(f"Disk usage is high: {sr.disk_percent}%")

    return anomalies


def _assess_status(health: OperationalHealth) -> str:
    """Compute overall operational health status."""
    if health.anomalies:
        return "degraded"
    if health.warnings:
        return "warning"
    return "healthy"


def to_model(health: OperationalHealth) -> OperationalHealthModel:
    """Convert the internal OperationalHealth dataclass to a Pydantic model for serialization."""
    running = sum(1 for c in health.containers if c.state == "running")
    exited = sum(1 for c in health.containers if c.state == "exited")
    sr = health.system_resources or SystemResource()

    return OperationalHealthModel(
        scanned_at=health.scanned_at,
        overall_status=health.overall_status,
        container_count=len(health.containers),
        containers_running=running,
        containers_exited=exited,
        service_count=len(health.systemd_services),
        cpu_percent=sr.cpu_percent,
        memory_percent=sr.memory_percent,
        disk_percent=sr.disk_percent,
        anomalies=health.anomalies,
        warnings=health.warnings,
    )
