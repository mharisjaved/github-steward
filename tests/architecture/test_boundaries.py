"""Focused architecture and dependency-boundary assertions."""

from __future__ import annotations

import ast
import pathlib
import tomllib
from collections.abc import Iterator

from github_steward.adapters.postgres.metadata import (
    APPEND_ONLY_TABLE_NAMES,
    TABLE_NAMES,
    metadata,
)

ROOT = pathlib.Path(__file__).parents[2]
SRC = ROOT / "src" / "github_steward"


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


def test_domain_imports_only_standard_library_and_itself() -> None:
    imports = _module_imports("domain")
    prohibited_roots = {
        "sqlalchemy",
        "psycopg",
        "alembic",
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


def test_exactly_eight_core_tables_and_no_orm() -> None:
    assert tuple(metadata.tables) == TABLE_NAMES
    assert len(metadata.tables) == 8
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


def test_immutable_analysis_view_association_is_append_only() -> None:
    assert APPEND_ONLY_TABLE_NAMES == (
        "canonical_observation",
        "analysis_view",
        "analysis_view_observation",
        "audit_event",
    )
    assert set(APPEND_ONLY_TABLE_NAMES) <= set(TABLE_NAMES)


def test_dependency_categories_are_bounded() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    runtime = project["project"]["dependencies"]
    dev = project["dependency-groups"]["dev"]
    expected_runtime = {
        "SQLAlchemy>=2.0,<2.1",
        "alembic>=1.18,<1.19",
        "psycopg[binary]>=3.3,<3.4",
        "rfc8785>=0.1.4,<0.2",
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
