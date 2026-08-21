"""Static GS-I6 inbound-only web and dependency boundaries."""

from __future__ import annotations

import ast
import pathlib
import tomllib
from collections.abc import Iterator

ROOT = pathlib.Path(__file__).parents[2]
SRC = ROOT / "src" / "github_steward"
WEBHOOK_ADAPTER = SRC / "adapters" / "web" / "github_webhook.py"


def _python_files(path: pathlib.Path) -> Iterator[pathlib.Path]:
    yield from path.rglob("*.py")


def _tree(path: pathlib.Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _import_roots(path: pathlib.Path) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(_tree(path)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.split(".")[0])
    return roots


def _dependency_name(requirement: str) -> str:
    return requirement.split("[")[0].split("<")[0].split(">=")[0].strip().casefold()


def test_only_authorized_direct_web_dependency_families_are_present() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = project["project"]["dependencies"]
    names = {_dependency_name(requirement) for requirement in runtime}
    assert names == {
        "alembic",
        "httpx",
        "psycopg",
        "pyjwt",
        "rfc8785",
        "sqlalchemy",
        "starlette",
        "uvicorn",
    }
    assert not names & {
        "celery",
        "fastapi",
        "flask",
        "pygithub",
        "redis",
        "requests",
    }


def test_starlette_and_uvicorn_remain_outside_inward_packages() -> None:
    offenders: dict[str, set[str]] = {}
    for package in ("domain", "application", "ports"):
        for path in _python_files(SRC / package):
            prohibited = _import_roots(path) & {"starlette", "uvicorn"}
            if prohibited:
                offenders[path.relative_to(SRC).as_posix()] = prohibited
    assert not offenders


def test_webhook_adapter_has_no_github_transport_or_persistence_technology() -> None:
    imports = _import_roots(WEBHOOK_ADAPTER)
    assert not imports & {
        "alembic",
        "httpx",
        "psycopg",
        "requests",
        "sqlalchemy",
        "urllib",
        "uvicorn",
    }
    source = WEBHOOK_ADAPTER.read_text(encoding="utf-8")
    assert "github_steward.adapters.github" not in source


def test_webhook_authentication_uses_required_stdlib_primitives_and_streaming() -> None:
    tree = _tree(WEBHOOK_ADAPTER)
    imports = _import_roots(WEBHOOK_ADAPTER)
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert {"hashlib", "hmac"} <= imports
    assert "compare_digest" in attributes
    assert "stream" in attributes
    assert "body" not in attributes


def test_webhook_boundary_has_no_logging_or_secret_bearing_model_fields() -> None:
    tree = _tree(WEBHOOK_ADAPTER)
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not calls & {"print", "repr"}
    assert "logging" not in _import_roots(WEBHOOK_ADAPTER)
    source = WEBHOOK_ADAPTER.read_text(encoding="utf-8")
    for prohibited in (
        "expected_signature",
        "raw_body_persistence",
        "webhook_secret_column",
    ):
        assert prohibited not in source
