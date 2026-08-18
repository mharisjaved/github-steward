"""Focused architecture and dependency-boundary assertions."""

from __future__ import annotations

import ast
import pathlib
import re
import subprocess
import tomllib
from collections.abc import Iterator

from github_steward.adapters.postgres.metadata import (
    APPEND_ONLY_TABLE_NAMES,
    TABLE_NAMES,
    metadata,
)

ROOT = pathlib.Path(__file__).parents[2]
SRC = ROOT / "src" / "github_steward"
GS_I5_BASELINE = "d0956b56c60928e15f427aee22c21c48903b6d83"
GS_I5_EXACT_ALLOWED_PATHS = frozenset(
    {
        "migrations/versions/0004_gs_i5_github_app_identity.py",
        "pyproject.toml",
        "uv.lock",
    }
)
GS_I5_ALLOWED_PATH_PREFIXES = (
    ".afef/specifications/",
    ".afef/work-records/",
    "src/github_steward/domain/",
    "src/github_steward/application/",
    "src/github_steward/ports/",
    "src/github_steward/adapters/github/",
    "src/github_steward/adapters/postgres/",
    "tests/unit/",
    "tests/contract/",
    "tests/integration/postgres/",
    "tests/integration/github/",
    "tests/architecture/",
)
GS_I5_SECURITY_INFRASTRUCTURE_MARKERS = frozenset(
    {
        "broker",
        "cache",
        "credential",
        "github_app",
        "jwt",
        "security",
        "token",
        "unix",
    }
)
GS_I4_TABLE_NAMES = frozenset(
    {
        "delivery_inbox",
        "work_record",
        "work_attempt",
        "canonical_observation",
        "current_observation_pointer",
        "analysis_view",
        "analysis_view_observation",
        "audit_event",
        "preparedness_profile",
        "preparedness_assessment",
        "preparedness_assessment_evidence",
    }
)


def _imports(path: pathlib.Path) -> Iterator[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            yield from (alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            yield node.module


def _module_imports(relative: str) -> set[str]:
    return {
        imported
        for path in (SRC / relative).rglob("*.py")
        for imported in _imports(path)
    }


def _is_allowed_gs_i5_path(path: str) -> bool:
    if path in GS_I5_EXACT_ALLOWED_PATHS:
        return True
    if path.startswith("src/github_steward/infrastructure/"):
        relative = pathlib.PurePosixPath(path).relative_to(
            "src/github_steward/infrastructure"
        )
        if relative.name == "__init__.py":
            return True
        return any(
            marker in relative.as_posix()
            for marker in GS_I5_SECURITY_INFRASTRUCTURE_MARKERS
        )
    return path.startswith(GS_I5_ALLOWED_PATH_PREFIXES)


def test_domain_imports_only_standard_library_and_itself() -> None:
    imports = _module_imports("domain")
    prohibited_roots = {
        "sqlalchemy",
        "psycopg",
        "alembic",
        "httpx",
        "rfc8785",
        "pytest",
        "hypothesis",
    }
    assert not {name.split(".")[0] for name in imports} & prohibited_roots
    assert not {
        name
        for name in imports
        if name.startswith("github_steward.")
        and not name.startswith("github_steward.domain")
    }


def test_runtime_source_never_imports_migrations_or_alembic() -> None:
    imports = _module_imports("")
    assert "migrations" not in {name.split(".")[0] for name in imports}
    assert "alembic" not in {name.split(".")[0] for name in imports}


def test_only_clock_infrastructure_reads_wall_clock() -> None:
    implicit_readers = {
        path.relative_to(SRC).as_posix()
        for path in SRC.rglob("*.py")
        if "datetime.now(" in path.read_text()
    }
    assert implicit_readers == {"infrastructure/clock.py"}


def test_exactly_thirteen_core_tables_and_no_orm() -> None:
    assert tuple(metadata.tables) == TABLE_NAMES
    assert len(metadata.tables) == 13
    assert set(TABLE_NAMES) == GS_I4_TABLE_NAMES | {
        "installation_observation",
        "repository_authorization",
    }
    source_text = "\n".join(path.read_text() for path in SRC.rglob("*.py"))
    for prohibited in (
        "DeclarativeBase",
        "declarative_base",
        "mapped_column",
        "Session",
        "AsyncEngine",
        "AsyncSession",
    ):
        assert prohibited not in source_text


def test_exactly_nine_append_only_targets() -> None:
    assert APPEND_ONLY_TABLE_NAMES == (
        "delivery_inbox",
        "canonical_observation",
        "analysis_view",
        "analysis_view_observation",
        "audit_event",
        "preparedness_profile",
        "preparedness_assessment",
        "preparedness_assessment_evidence",
        "installation_observation",
    )
    assert set(APPEND_ONLY_TABLE_NAMES) <= set(TABLE_NAMES)


def test_application_imports_only_domain_and_ports_with_no_remote_technology() -> None:
    imports = _module_imports("application")
    prohibited = {
        "sqlalchemy",
        "psycopg",
        "alembic",
        "rfc8785",
        "requests",
        "httpx",
        "fastapi",
        "flask",
        "django",
        "redis",
        "celery",
        "github",
        "openai",
        "langchain",
    }
    assert not {name.split(".")[0] for name in imports} & prohibited
    assert not {
        name
        for name in imports
        if name.startswith("github_steward.")
        and not name.startswith(("github_steward.domain", "github_steward.ports"))
    }


def test_exactly_four_linear_alembic_revisions() -> None:
    revision_files = sorted((ROOT / "migrations" / "versions").glob("*.py"))
    assert [path.name for path in revision_files] == [
        "0001_gs_i1_foundation.py",
        "0002_gs_i2_durable_processing.py",
        "0003_gs_i4_preparedness.py",
        "0004_gs_i5_github_app_identity.py",
    ]
    identities = []
    for path in revision_files:
        source = path.read_text()
        revision_match = re.search(r'^revision: str = "([^"]+)"$', source, re.MULTILINE)
        down_revision_match = re.search(
            r"^down_revision: str \| None = (.+)$", source, re.MULTILINE
        )
        assert revision_match is not None
        assert down_revision_match is not None
        identities.append(
            (
                revision_match.group(1),
                down_revision_match.group(1),
            )
        )
    assert identities == [
        ("gs_i1_0001", "None"),
        ("gs_i2_0002", '"gs_i1_0001"'),
        ("gs_i4_0003", '"gs_i2_0002"'),
        ("gs_i5_0004", '"gs_i4_0003"'),
    ]


def test_gs_i1_through_gs_i4_migrations_are_byte_identical() -> None:
    protected = (
        "migrations/versions/0001_gs_i1_foundation.py",
        "migrations/versions/0002_gs_i2_durable_processing.py",
        "migrations/versions/0003_gs_i4_preparedness.py",
    )
    result = subprocess.run(
        ["git", "diff", "--name-only", GS_I5_BASELINE, "--", *protected],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert result.stdout == ""


def test_dependency_categories_are_bounded() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    runtime = project["project"]["dependencies"]
    dev = project["dependency-groups"]["dev"]
    expected_runtime = {
        "SQLAlchemy>=2.0,<2.1",
        "alembic>=1.18,<1.19",
        "httpx>=0.28,<0.29",
        "psycopg[binary]>=3.3,<3.4",
        "rfc8785>=0.1.4,<0.2",
        "PyJWT[crypto]>=2.13,<3",
    }
    expected_dev = {
        "pytest>=9,<10",
        "hypothesis>=6.100,<7",
        "pytest-cov>=7,<8",
        "ruff>=0.15,<0.17",
        "mypy>=2,<3",
        "import-linter>=2.10,<3",
    }
    assert set(runtime) == expected_runtime
    assert set(dev) == expected_dev
    assert project["tool"]["uv"]["index"] == [
        {
            "name": "pypi",
            "url": "https://pypi.org/simple",
            "default": True,
        }
    ]


def test_gs_i5_baseline_diff_stays_within_authorized_paths_and_ceiling() -> None:
    changed = subprocess.run(
        ["git", "diff", "--name-only", GS_I5_BASELINE, "--"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    gs_i5_paths = set(changed) | set(untracked)

    assert len(gs_i5_paths) <= 50
    assert not {path for path in gs_i5_paths if not _is_allowed_gs_i5_path(path)}
