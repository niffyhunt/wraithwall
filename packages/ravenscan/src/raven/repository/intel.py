"""Phase 1 — Repository Intelligence.

Collects: project structure, languages, frameworks, dependency graph,
package managers, Docker/CI/CD topology, background workers, API routes,
databases.

Produces: RepositoryProfile
"""

from __future__ import annotations

import ast
import os
from pathlib import Path
from typing import Optional

from raven.core.config import RavenConfig
from raven.core.context import RepositoryContext, ParsedFile, DependencyInfo
from raven.core.models import (
    RepositoryProfile,
    RepoStructure,
    FrameworkInfo,
    DependencyEntry,
)
from raven.utils.logging import get_logger

logger = get_logger(__name__)

LANGUAGE_MAP: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".h": "c",
    ".cpp": "c++",
    ".hpp": "c++",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".json": "json",
    ".toml": "toml",
    ".md": "markdown",
    ".dockerfile": "dockerfile",
    ".sh": "shell",
    ".bash": "shell",
    ".sql": "sql",
}

PYTHON_FRAMEWORKS: dict[str, str] = {
    "flask": "Flask",
    "django": "Django",
    "fastapi": "FastAPI",
    "starlette": "Starlette",
    "aiohttp": "aiohttp",
    "tornado": "Tornado",
    "pyramid": "Pyramid",
    "sanic": "Sanic",
    "litestar": "Litestar",
    "sqlalchemy": "SQLAlchemy",
    "pony": "PonyORM",
    "peewee": "Peewee",
    "tortoise-orm": "TortoiseORM",
    "celery": "Celery",
    "dramatiq": "Dramatiq",
    "rq": "RQ",
    "apscheduler": "APScheduler",
    "pydantic": "Pydantic",
    "marshmallow": "Marshmallow",
    "jinja2": "Jinja2",
    "click": "Click",
    "typer": "Typer",
    "gunicorn": "Gunicorn",
    "uvicorn": "Uvicorn",
    "pytest": "pytest",
    "vue": "Vue.js",
    "react": "React",
    "next": "Next.js",
    "nuxt": "Nuxt.js",
    "express": "Express",
    "koa": "Koa",
    "nest": "NestJS",
    "gin": "Gin",
    "echo": "Echo",
    "fiber": "Fiber",
    "actix": "Actix",
    "rocket": "Rocket",
    "axum": "Axum",
    "spring": "Spring",
    "laravel": "Laravel",
    "symfony": "Symfony",
    "rails": "Rails",
}

BG_WORKER_MARKERS: dict[str, str] = {
    "celery": "Celery",
    "dramatiq": "Dramatiq",
    "rq": "RQ",
    "apscheduler": "APScheduler",
    "threading.Thread": "Threading",
    "multiprocessing.Process": "Multiprocessing",
}

DB_INDICATORS: dict[str, list[str]] = {
    "SQLAlchemy": ["sqlalchemy"],
    "Django ORM": ["django.db"],
    "Tortoise ORM": ["tortoise"],
    "Peewee": ["peewee"],
    "MongoDB": ["pymongo", "motor", "mongoengine"],
    "Redis": ["redis", "aioredis"],
    "PostgreSQL": ["psycopg2", "asyncpg"],
    "MySQL": ["pymysql", "mysqlclient", "aiomysql"],
    "SQLite": ["sqlite3"],
}

CI_INDICATORS: dict[str, str] = {
    ".github/workflows": "GitHub Actions",
    "Jenkinsfile": "Jenkins",
    ".gitlab-ci.yml": "GitLab CI",
    ".circleci": "CircleCI",
    ".travis.yml": "Travis CI",
    "azure-pipelines.yml": "Azure Pipelines",
}

DOCKERFILE_NAMES = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", ".dockerignore"]

ROUTE_CAP = 200


def build_context(config: RavenConfig) -> RepositoryContext:
    """Walk the repository and build a complete RepositoryContext."""
    root = config.path.resolve()
    ctx = RepositoryContext(root=root)

    _collect_files(ctx, root, config)
    _detect_languages(ctx)
    _detect_frameworks(ctx)
    _resolve_dependencies(ctx)
    _detect_infrastructure(ctx)
    _detect_api_routes(ctx)
    _detect_database(ctx)
    _detect_bg_workers(ctx)

    return ctx


def analyze(config: RavenConfig, ctx: Optional[RepositoryContext] = None) -> RepositoryProfile:
    """Run Phase 1 analysis and return a RepositoryProfile."""
    if ctx is None:
        ctx = build_context(config)

    return RepositoryProfile(
        structure=RepoStructure(
            root=str(ctx.root),
            total_files=ctx.total_files,
            total_lines=ctx.total_lines,
            total_python_files=ctx.total_python_files,
            directory_count=_count_dirs(ctx.root, config),
        ),
        language_primary=ctx.language_primary,
        languages=ctx.languages,
        frameworks=[FrameworkInfo(name=f) for f in ctx.frameworks],
        package_manager=ctx.package_manager,
        dependencies=[
            DependencyEntry(name=d.name, version=d.version, source=d.source, is_dev=d.is_dev)
            for d in ctx.dependencies
        ],
        has_docker=ctx.has_docker,
        has_ci=ctx.has_ci,
        ci_provider=ctx.ci_provider,
        bg_workers=ctx.bg_workers,
        api_routes=ctx.api_routes,
        database=ctx.database,
    )


def _excluded(path: Path, config: RavenConfig) -> bool:
    """Check if a path matches any exclude pattern."""
    parts = str(path).split(os.sep)
    for pat in config.exclude_patterns:
        if pat in parts:
            return True
        if pat.startswith("*") and any(p.endswith(pat[1:]) for p in parts):
            return True
    return False


def _collect_files(ctx: RepositoryContext, root: Path, config: RavenConfig) -> None:
    """Walk the directory tree and collect all non-excluded files with AST parsing."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames if not _excluded(Path(dirpath) / d, config)
        ]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if _excluded(fpath, config):
                continue
            try:
                size = fpath.stat().st_size
                if size > config.max_file_size_bytes:
                    continue
            except OSError:
                continue
            rel = str(fpath.relative_to(root))
            lang = _guess_language(fname)
            try:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            except (UnicodeDecodeError, PermissionError, OSError):
                logger.debug("Could not read file: %s", fpath)
                continue
            lines = content.splitlines()
            pf = ParsedFile(
                path=fpath,
                relative_path=rel,
                language=lang,
                content=content,
                size_bytes=size,
                lines=lines,
            )
            if lang == "python":
                try:
                    pf.ast_tree = ast.parse(content)
                except SyntaxError:
                    pass
            ctx.files.append(pf)
            ctx.total_files += 1
            ctx.total_lines += len(lines)
            if lang == "python":
                ctx.total_python_files += 1


def _guess_language(filename: str) -> str:
    """Map a filename to a language based on extension."""
    if filename.lower() == "dockerfile":
        return "dockerfile"
    ext = Path(filename).suffix.lower()
    return LANGUAGE_MAP.get(ext, "unknown")


def _count_dirs(root: Path, config: RavenConfig) -> int:
    """Count non-excluded subdirectories."""
    count = 0
    for dirpath, dirnames, _ in os.walk(root):
        dirnames[:] = [d for d in dirnames if not _excluded(Path(dirpath) / d, config)]
        count += len(dirnames)
    return count


def _detect_languages(ctx: RepositoryContext) -> None:
    """Identify all languages in the project and the primary language."""
    counts: dict[str, int] = {}
    for f in ctx.files:
        if f.language != "unknown":
            counts[f.language] = counts.get(f.language, 0) + 1
    ctx.languages = sorted(counts.keys(), key=lambda k: counts[k], reverse=True)
    ctx.language_primary = ctx.languages[0] if ctx.languages else "unknown"


def _detect_frameworks(ctx: RepositoryContext) -> None:
    """Detect frameworks from dependency names and import patterns."""
    frameworks: set[str] = set()
    dep_names = {d.name.lower() for d in ctx.dependencies}

    for dep_name_lower, display_name in PYTHON_FRAMEWORKS.items():
        if dep_name_lower in dep_names:
            frameworks.add(display_name)

    for f in ctx.files:
        if f.language != "python":
            continue
        content_lower = f.content.lower()
        if "from flask import" in content_lower or "import flask" in content_lower:
            frameworks.add("Flask")
        if "from django" in content_lower or "import django" in content_lower:
            frameworks.add("Django")
        if "from fastapi" in content_lower or "import fastapi" in content_lower:
            frameworks.add("FastAPI")
        if "from sqlalchemy" in content_lower or "import sqlalchemy" in content_lower:
            frameworks.add("SQLAlchemy")
        if "celery" in content_lower:
            frameworks.add("Celery")
        if "apscheduler" in content_lower:
            frameworks.add("APScheduler")

    ctx.frameworks = sorted(frameworks)


def _resolve_dependencies(ctx: RepositoryContext) -> None:
    """Identify package manager and resolve dependencies from manifest files."""
    root = ctx.root

    for req_file in ["requirements.txt", "requirements.in"]:
        if (root / req_file).exists():
            ctx.package_manager = "pip"
            _parse_requirements(ctx, root / req_file)

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        ctx.package_manager = ctx.package_manager or "pip"
        _parse_pyproject_deps(ctx, pyproject)

    pipfile = root / "Pipfile"
    if pipfile.exists():
        ctx.package_manager = ctx.package_manager or "pipenv"
        _parse_pipfile(ctx, pipfile)

    if (root / "poetry.lock").exists():
        ctx.package_manager = "poetry"

    pkg_json = root / "package.json"
    if pkg_json.exists():
        _parse_package_json(ctx, pkg_json)

    if (root / "go.mod").exists():
        ctx.package_manager = ctx.package_manager or "go modules"

    if (root / "Cargo.toml").exists():
        ctx.package_manager = ctx.package_manager or "cargo"


def _parse_requirements(ctx: RepositoryContext, path: Path) -> None:
    """Parse pip requirements.txt into DependencyInfo entries."""
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            pkg = line.split("[")[0].split("==")[0].split(">=")[0].split("<=")[0].split("~=")[0].split("!=")[0].strip()
            ver = line.split("==")[1].strip() if "==" in line else "unknown"
            if pkg:
                ctx.dependencies.append(
                    DependencyInfo(name=pkg, version=ver, source=path.name)
                )
    except Exception:
        logger.debug("Could not parse requirements file: %s", path)


def _parse_pyproject_deps(ctx: RepositoryContext, path: Path) -> None:
    """Parse PEP 621 pyproject.toml dependencies (requires tomllib or tomli)."""
    try:
        import tomllib as _toml
    except ImportError:
        try:
            import tomli as _toml  # type: ignore[import-not-found,no-redef,unused-ignore]
        except ImportError:
            return
    try:
        data = _toml.loads(path.read_text())
        deps = data.get("project", {}).get("dependencies", [])
        for dep in deps:
            name = dep.split("[")[0].split(">=")[0].split("<=")[0].split("==")[0].split("~=")[0].strip()
            if name:
                ctx.dependencies.append(
                    DependencyInfo(name=name, version="unknown", source="pyproject.toml")
                )
        opt_deps = data.get("project", {}).get("optional-dependencies", {})
        for group, deps_list in opt_deps.items():
            for dep in deps_list:
                name = dep.split("[")[0].split(">=")[0].split("<=")[0].split("==")[0].split("~=")[0].strip()
                if name:
                    ctx.dependencies.append(
                        DependencyInfo(name=name, version="unknown", source="pyproject.toml", is_dev=True)
                    )
    except Exception:
        logger.debug("Could not parse pyproject.toml dependencies: %s", path)


def _parse_pipfile(ctx: RepositoryContext, path: Path) -> None:
    """Parse Pipfile into DependencyInfo entries."""
    try:
        content = path.read_text()
        in_packages = False
        in_dev = False
        for line in content.splitlines():
            line = line.strip()
            if "[packages]" in line:
                in_packages = True
                in_dev = False
                continue
            if "[dev-packages]" in line:
                in_dev = True
                continue
            if line.startswith("[") and "[packages]" not in line and "[dev-packages]" not in line:
                in_packages = False
                in_dev = False
                continue
            if in_packages and "=" in line:
                name = line.split("=")[0].strip().strip('"').strip("'")
                ctx.dependencies.append(
                    DependencyInfo(name=name, version="unknown", source="Pipfile", is_dev=in_dev)
                )
    except Exception:
        logger.debug("Could not parse Pipfile: %s", path)


def _parse_package_json(ctx: RepositoryContext, path: Path) -> None:
    """Parse package.json for JavaScript/Node dependencies."""
    import json
    try:
        data = json.loads(path.read_text())
        for dep_name, version in data.get("dependencies", {}).items():
            ctx.dependencies.append(
                DependencyInfo(name=dep_name, version=str(version), source="package.json")
            )
        for dep_name, version in data.get("devDependencies", {}).items():
            ctx.dependencies.append(
                DependencyInfo(name=dep_name, version=str(version), source="package.json", is_dev=True)
            )
    except Exception:
        logger.debug("Could not parse package.json: %s", path)


def _detect_infrastructure(ctx: RepositoryContext) -> None:
    """Detect Docker, CI/CD, and systemd configuration."""
    root = ctx.root
    ctx.has_docker = any((root / name).exists() for name in DOCKERFILE_NAMES)

    for indicator, provider in CI_INDICATORS.items():
        if (root / indicator).exists():
            ctx.has_ci = True
            ctx.ci_provider = provider
            break

    ctx.has_systemd = any(
        f.relative_path.endswith(".service") or f.relative_path.endswith(".timer")
        for f in ctx.files
    )


def _detect_api_routes(ctx: RepositoryContext) -> None:
    """Discover Flask, FastAPI, and other framework route decorators."""
    routes: list[str] = []
    for f in ctx.files:
        if f.language != "python":
            continue
        for line in f.lines:
            stripped = line.strip()
            if "@app.route(" in stripped or "@bp.route(" in stripped or "@blueprint.route(" in stripped:
                routes.append(f"{f.relative_path}: {stripped}")
            elif "@router.get(" in stripped or "@router.post(" in stripped or "@router.put(" in stripped or "@router.delete(" in stripped or "@router.patch(" in stripped:
                routes.append(f"{f.relative_path}: {stripped}")
            elif "@app.get(" in stripped or "@app.post(" in stripped or "@app.put(" in stripped or "@app.delete(" in stripped:
                routes.append(f"{f.relative_path}: {stripped}")
    ctx.api_routes = routes[:ROUTE_CAP]


def _detect_database(ctx: RepositoryContext) -> None:
    """Identify database systems from imports and dependencies."""
    detected: list[str] = []
    for f in ctx.files:
        if f.language != "python":
            continue
        for db_name, markers in DB_INDICATORS.items():
            if any(m in f.content for m in markers) and db_name not in detected:
                detected.append(db_name)
    if detected:
        ctx.database = ", ".join(detected)
    elif any(d.name.lower() in ("sqlalchemy", "django", "psycopg2") for d in ctx.dependencies):
        ctx.database = "SQL (via dependencies)"


def _detect_bg_workers(ctx: RepositoryContext) -> None:
    """Detect background worker systems from dependencies and code patterns."""
    found: set[str] = set()
    for d in ctx.dependencies:
        name_lower = d.name.lower()
        if name_lower in BG_WORKER_MARKERS:
            found.add(BG_WORKER_MARKERS[name_lower])
    for f in ctx.files:
        if f.language != "python":
            continue
        for marker, label in BG_WORKER_MARKERS.items():
            if marker in f.content and marker not in ("celery", "dramatiq", "rq", "apscheduler"):
                found.add(label)
    ctx.bg_workers = sorted(found)
