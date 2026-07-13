"""Phase 4 — Change Intelligence: semantic change tracking.

Tracks meaningful engineering changes across revisions:
- Authentication changes
- Authorization changes
- New/removed API endpoints
- Shell execution and subprocess additions
- Filesystem operation changes
- Docker/infrastructure modifications
- Dependency updates
- Permission changes
- Environment variable changes
- Redis schema evolution
- Database migration detection
- Infrastructure modifications

Produces structured change records with affected files, symbols, and confidence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from raven.core.context import RepositoryContext
from raven.core.models import SecurityReport, Severity


@dataclass
class TrackedChange:
    """A single semantic change detected between two repository states."""

    category: str
    title: str
    description: str
    severity: Severity
    evidence: str
    affected_files: list[str] = field(default_factory=list)
    affected_symbols: list[str] = field(default_factory=list)
    confidence: float = 1.0
    recommendation: str = ""


@dataclass
class ChangeReport:
    """Aggregated change intelligence for a revision."""

    scanned_at: str
    revision: str
    previous_revision: str | None = None
    changes: list[TrackedChange] = field(default_factory=list)
    total_changes: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0

    def __post_init__(self) -> None:
        self.total_changes = len(self.changes)
        self.critical_count = sum(1 for c in self.changes if c.severity == Severity.CRITICAL)
        self.high_count = sum(1 for c in self.changes if c.severity == Severity.HIGH)
        self.medium_count = sum(1 for c in self.changes if c.severity == Severity.MEDIUM)
        self.low_count = sum(1 for c in self.changes if c.severity == Severity.LOW)


def analyze(ctx: RepositoryContext, security: SecurityReport | None = None) -> ChangeReport:
    """Run semantic change analysis on the current repository state.

    When no previous revision is available, this acts as a baseline
    discovery — flagging all detected patterns as "initial observations."
    """
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    changes: list[TrackedChange] = []

    changes.extend(_track_authentication(ctx))
    changes.extend(_track_authorization(ctx))
    changes.extend(_track_api_endpoints(ctx))
    changes.extend(_track_shell_execution(ctx))
    changes.extend(_track_filesystem_operations(ctx))
    changes.extend(_track_docker_changes(ctx))
    changes.extend(_track_dependency_changes(ctx))
    changes.extend(_track_permission_changes(ctx))
    changes.extend(_track_environment_changes(ctx))
    changes.extend(_track_redis_schema(ctx))
    changes.extend(_track_database_changes(ctx))
    changes.extend(_track_infrastructure(ctx))

    return ChangeReport(
        scanned_at=now,
        revision="current",
        changes=changes,
    )


AUTH_MARKERS = [
    (r'@login_required|@jwt_required|@auth\.require|require_auth|login_required\(', "Authentication decorator"),
    (r'flask_login\.login_user|flask_login\.logout_user', "Session management"),
    (r'bcrypt\.(hashpw|checkpw|gensalt)|argon2|hashlib\.scrypt|pbkdf2', "Password hashing"),
    (r'pyotp\.totp|pyotp\.hotp|generate_2fa|verify_2fa', "2FA implementation"),
    (r'session\[.user_id.\]|session\[.authenticated.\]|session\[.logged_in.\]', "Session access"),
]


def _track_authentication(ctx: RepositoryContext) -> list[TrackedChange]:
    """Detect authentication patterns: login decorators, session management, password hashing, 2FA."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        if f.language != "python":
            continue
        for i, line in enumerate(f.lines):
            for pattern, label in AUTH_MARKERS:
                if re.search(pattern, line):
                    results.append(TrackedChange(
                        category="authentication",
                        title=f"Authentication mechanism: {label}",
                        description=f"Found {label} usage in {f.relative_path}.",
                        severity=Severity.INFO,
                        evidence=f"{f.relative_path}:{i + 1}",
                        affected_files=[f.relative_path],
                        affected_symbols=[label],
                        confidence=0.9,
                    ))
                    break
    return results


AUTHZ_MARKERS = [
    (r'@require_role|@admin_required|@permission_required|require_admin|@roles_required', "Role-based access"),
    (r'@owner_required|check_ownership|verify_owner', "Ownership verification"),
    (r'can_\(|has_permission\(|check_permission\(', "Permission check"),
    (r'403|Forbidden|forbidden\b', "Authorization failure response"),
    (r'flask_principal|rbac|RoleNeed', "RBAC framework"),
]


def _track_authorization(ctx: RepositoryContext) -> list[TrackedChange]:
    """Detect authorization patterns: role checks, permissions, ownership verification, RBAC."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        if f.language != "python":
            continue
        for i, line in enumerate(f.lines):
            for pattern, label in AUTHZ_MARKERS:
                if re.search(pattern, line):
                    results.append(TrackedChange(
                        category="authorization",
                        title=f"Authorization mechanism: {label}",
                        description=f"Found {label} usage in {f.relative_path}.",
                        severity=Severity.INFO,
                        evidence=f"{f.relative_path}:{i + 1}",
                        affected_files=[f.relative_path],
                        affected_symbols=[label],
                        confidence=0.9,
                    ))
                    break
    return results


API_MARKERS = [
    (r'@app\.route\(|@bp\.route\(|@blueprint\.route\(', "Flask route"),
    (r'@router\.(get|post|put|delete|patch)\(', "FastAPI route"),
    (r'@app\.(get|post|put|delete|patch)\(', "FastAPI app route"),
    (r'@app\.websocket\(|@router\.websocket\(', "WebSocket endpoint"),
    (r'Blueprint\(.*\)|APIRouter\(', "Route blueprint declaration"),
]


def _track_api_endpoints(ctx: RepositoryContext) -> list[TrackedChange]:
    """Discover API endpoint definitions and route registrations."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        if f.language != "python":
            continue
        for i, line in enumerate(f.lines):
            for pattern, label in API_MARKERS:
                if re.search(pattern, line):
                    results.append(TrackedChange(
                        category="api_endpoint",
                        title=f"API endpoint: {label}",
                        description=f"Route definition in {f.relative_path}:{i + 1}.",
                        severity=Severity.INFO,
                        evidence=f"{f.relative_path}:{i + 1}: {line.strip()}",
                        affected_files=[f.relative_path],
                        confidence=0.95,
                    ))
                    break
    return results


SHELL_EXEC_MARKERS = [
    (r'os\.system\(', "os.system() call", Severity.HIGH),
    (r'os\.popen\(', "os.popen() call", Severity.HIGH),
    (r'subprocess\.(run|Popen|call|check_output)\(', "subprocess execution", Severity.MEDIUM),
    (r'shell\s*=\s*True', "shell=True", Severity.HIGH),
    (r'eval\(', "eval() call", Severity.CRITICAL),
    (r'exec\(', "exec() call", Severity.CRITICAL),
    (r'compile\(', "compile() call", Severity.MEDIUM),
    (r'__import__\(', "dynamic __import__", Severity.MEDIUM),
]


def _track_shell_execution(ctx: RepositoryContext) -> list[TrackedChange]:
    """Track command execution, subprocess invocation, and dynamic code evaluation."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        if f.language != "python":
            continue
        for i, line in enumerate(f.lines):
            if line.strip().startswith("#"):
                continue
            for pattern, label, sev in SHELL_EXEC_MARKERS:
                if re.search(pattern, line):
                    results.append(TrackedChange(
                        category="shell_execution",
                        title=f"Code execution risk: {label}",
                        description=f"{label} usage at {f.relative_path}:{i + 1}. Verify input is sanitized.",
                        severity=sev,
                        evidence=f"{f.relative_path}:{i + 1}: {line.strip()[:100]}",
                        affected_files=[f.relative_path],
                        affected_symbols=[label],
                        confidence=0.85,
                        recommendation="Ensure no user-controlled input reaches this call without validation.",
                    ))
                    break
    return results


FILESYSTEM_MARKERS = [
    (r'open\(.*,\s*[\"\'][wab]', "File write/open", Severity.MEDIUM),
    (r'os\.(remove|unlink|rmdir)\(', "File deletion", Severity.MEDIUM),
    (r'shutil\.(rmtree|copy|move)\(', "Bulk file operation", Severity.MEDIUM),
    (r'os\.(chmod|chown)\(', "Permission change", Severity.HIGH),
    (r'tarfile\.extractall|zipfile\.extractall', "Archive extraction", Severity.HIGH),
    (r'tempfile\.(mkstemp|mkdtemp|NamedTemporaryFile)', "Temporary file creation", Severity.LOW),
]


def _track_filesystem_operations(ctx: RepositoryContext) -> list[TrackedChange]:
    """Track filesystem access: file writes, deletions, permission changes, archive extraction."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        if f.language != "python":
            continue
        for i, line in enumerate(f.lines):
            if line.strip().startswith("#"):
                continue
            for pattern, label, sev in FILESYSTEM_MARKERS:
                if re.search(pattern, line):
                    results.append(TrackedChange(
                        category="filesystem",
                        title=f"Filesystem operation: {label}",
                        description=f"{label} at {f.relative_path}:{i + 1}. Verify path inputs are sanitized.",
                        severity=sev,
                        evidence=f"{f.relative_path}:{i + 1}",
                        affected_files=[f.relative_path],
                        confidence=0.85,
                        recommendation="Validate all file paths against path traversal and symlink attacks.",
                    ))
                    break
    return results


DOCKER_MARKERS = [
    (r'FROM\s+\S+', "Docker base image", Severity.INFO),
    (r'EXPOSE\s+\d+', "Docker port exposure", Severity.INFO),
    (r'VOLUME\s+', "Docker volume mount", Severity.LOW),
    (r'COPY\s+--from=', "Docker multi-stage copy", Severity.INFO),
    (r'USER\s+(?!root)', "Docker non-root user", Severity.INFO),
    (r'HEALTHCHECK\s+', "Docker healthcheck", Severity.INFO),
]


def _track_docker_changes(ctx: RepositoryContext) -> list[TrackedChange]:
    """Track Dockerfile instructions and docker-compose configurations."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        if f.relative_path.lower().startswith("dockerfile") or f.relative_path.endswith((".dockerfile", ".dockerfile")):
            for i, line in enumerate(f.lines):
                for pattern, label, sev in DOCKER_MARKERS:
                    if re.match(pattern, line.strip()):
                        results.append(TrackedChange(
                            category="docker",
                            title=f"Docker instruction: {label}",
                            description=f"Docker instruction in {f.relative_path}:{i + 1}.",
                            severity=sev,
                            evidence=f"{f.relative_path}:{i + 1}: {line.strip()}",
                            affected_files=[f.relative_path],
                            confidence=0.95,
                        ))
        if f.relative_path in ("docker-compose.yml", "docker-compose.yaml"):
            for i, line in enumerate(f.lines):
                stripped = line.strip()
                if "image:" in stripped:
                    results.append(TrackedChange(
                        category="docker",
                        title="Docker Compose service image",
                        description=f"Service image reference in {f.relative_path}:{i + 1}.",
                        severity=Severity.INFO,
                        evidence=f"{f.relative_path}:{i + 1}: {stripped}",
                        affected_files=[f.relative_path],
                        confidence=0.95,
                    ))
    return results


ENV_VAR_MARKERS = [
    (r'os\.environ\[|os\.getenv\(|os\.environ\.get\(', "Environment variable read"),
    (r'\.env\b', ".env file reference"),
    (r'config\(|getenv\(|environ\[', "Configuration access"),
]


def _track_environment_changes(ctx: RepositoryContext) -> list[TrackedChange]:
    """Track environment variable access and configuration management patterns."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        if f.language != "python":
            continue
        for i, line in enumerate(f.lines):
            for pattern, label in ENV_VAR_MARKERS:
                if re.search(pattern, line):
                    if "os.environ" in line or "os.getenv" in line:
                        var_match = re.search(r'os\.(environ\[|environ\.get\(|getenv\()["\']([^"\']+)["\']', line)
                        symbol = var_match.group(2) if var_match else label
                        results.append(TrackedChange(
                            category="environment",
                            title=f"Environment variable: {symbol}",
                            description=f"Environment variable access at {f.relative_path}:{i + 1}.",
                            severity=Severity.INFO,
                            evidence=f"{f.relative_path}:{i + 1}",
                            affected_files=[f.relative_path],
                            affected_symbols=[symbol],
                            confidence=0.9,
                        ))
                    break
    return results


DEPENDENCY_MARKERS = [
    (r'import\s+|from\s+\S+\s+import', "Python import"),
    (r'pip\s+install|pip3\s+install', "Pip install command"),
]


def _track_dependency_changes(ctx: RepositoryContext) -> list[TrackedChange]:
    """Track dependency additions, removals, and version changes."""
    results: list[TrackedChange] = []
    dep_files = ["requirements.txt", "requirements.in", "pyproject.toml", "Pipfile", "package.json"]
    for f in ctx.files:
        if f.relative_path in dep_files or f.relative_path.endswith((".lock", ".toml")):
            for d in ctx.dependencies:
                if d.source == f.relative_path or d.source == f.relative_path.split("/")[-1]:
                    results.append(TrackedChange(
                        category="dependency",
                        title=f"Dependency: {d.name}@{d.version}",
                        description=f"Dependency {d.name} version {d.version} in {f.relative_path}.",
                        severity=Severity.INFO,
                        evidence=f"Source: {d.source}, dev: {d.is_dev}",
                        affected_files=[f.relative_path],
                        affected_symbols=[d.name],
                        confidence=0.9,
                    ))
    return results


REDIS_MARKERS = [
    (r'redis\.(set|get|hset|hget|zadd|lpush|rpush|sadd|expire|delete|publish)\(', "Redis operation"),
    (r'redis\.(incr|decr|incrby|hincrby)', "Redis counter"),
    (r'r\.set\(|r\.get\(|redis_client\.', "Redis client usage"),
]


def _track_redis_schema(ctx: RepositoryContext) -> list[TrackedChange]:
    """Detect Redis key patterns, data structures, and operation types."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        if f.language != "python":
            continue
        for i, line in enumerate(f.lines):
            for pattern, label in REDIS_MARKERS:
                if re.search(pattern, line):
                    results.append(TrackedChange(
                        category="redis",
                        title=f"Redis operation: {label}",
                        description=f"Redis operation at {f.relative_path}:{i + 1}.",
                        severity=Severity.INFO,
                        evidence=f"{f.relative_path}:{i + 1}",
                        affected_files=[f.relative_path],
                        confidence=0.85,
                    ))
                    break
    return results


DB_MIGRATION_MARKERS = [
    (r'alembic|flask_migrate|django\.db\.migrations', "Migration framework"),
    (r'create_table\(|alter_table\(|add_column\(', "Schema change operation"),
    (r'db\.create_all\(|db\.drop_all\(', "Auto DDL statement"),
    (r'CREATE\s+TABLE|ALTER\s+TABLE|DROP\s+TABLE', "Raw SQL DDL"),
    (r'\b(upgrade|downgrade)\s*\(', "Migration upgrade/downgrade"),
]


def _track_database_changes(ctx: RepositoryContext) -> list[TrackedChange]:
    """Track database schema changes: migrations, DDL statements, ORM schema operations."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        if f.language != "python" and not f.relative_path.endswith(".sql"):
            continue
        for i, line in enumerate(f.lines):
            for pattern, label in DB_MIGRATION_MARKERS:
                if re.search(pattern, line):
                    results.append(TrackedChange(
                        category="database",
                        title=f"Database operation: {label}",
                        description=f"Database change at {f.relative_path}:{i + 1}.",
                        severity=Severity.HIGH,
                        evidence=f"{f.relative_path}:{i + 1}",
                        affected_files=[f.relative_path],
                        confidence=0.85,
                        recommendation="Verify database migration safety and rollback plan.",
                    ))
                    break
    return results


PERMISSION_MARKERS = [
    (r'chmod\s+[0-7]{3,4}', "chmod permission change"),
    (r'os\.chmod\(.*0o?[0-7]{3,4}', "Python chmod call"),
    (r'chown\s+|os\.chown\(', "Ownership change"),
    (r'chgrp\s+', "Group change"),
    (r'umask\s+', "umask setting"),
]


def _track_permission_changes(ctx: RepositoryContext) -> list[TrackedChange]:
    """Track permission and ownership changes in scripts and configuration."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        for i, line in enumerate(f.lines):
            for pattern, label in PERMISSION_MARKERS:
                if re.search(pattern, line):
                    results.append(TrackedChange(
                        category="permissions",
                        title=f"Permission change: {label}",
                        description=f"Permission/ownership operation at {f.relative_path}:{i + 1}.",
                        severity=Severity.MEDIUM,
                        evidence=f"{f.relative_path}:{i + 1}",
                        affected_files=[f.relative_path],
                        confidence=0.9,
                        recommendation="Verify that permission changes do not weaken security.",
                    ))
    return results


INFRA_MARKERS = [
    (r'systemd|systemctl|\.service\b|\.timer\b', "Systemd service"),
    (r'nginx|apache2|caddy', "Web server configuration"),
    (r'cron\b|supervisor', "Job scheduler"),
    (r'kube|kubernetes|k8s', "Kubernetes resource"),
    (r'terraform|terragrunt', "Infrastructure-as-code"),
    (r'ansible|puppet|chef|salt', "Configuration management"),
    (r'prometheus|grafana|datadog', "Monitoring"),
]


def _track_infrastructure(ctx: RepositoryContext) -> list[TrackedChange]:
    """Track infrastructure changes: systemd, web servers, schedulers, monitoring, IaC."""
    results: list[TrackedChange] = []
    for f in ctx.files:
        for i, line in enumerate(f.lines):
            for pattern, label in INFRA_MARKERS:
                if re.search(pattern, line, re.IGNORECASE):
                    results.append(TrackedChange(
                        category="infrastructure",
                        title=f"Infrastructure: {label}",
                        description=f"Infrastructure pattern at {f.relative_path}:{i + 1}.",
                        severity=Severity.INFO,
                        evidence=f"{f.relative_path}:{i + 1}",
                        affected_files=[f.relative_path],
                        confidence=0.85,
                    ))
                    break
    return results
