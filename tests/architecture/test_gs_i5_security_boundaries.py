"""Static GS-I5 credential, transport, and persistence boundaries."""

from __future__ import annotations

import ast
import pathlib
import subprocess
import tomllib
from collections.abc import Iterator

from github_steward.adapters.postgres.metadata import metadata

ROOT = pathlib.Path(__file__).parents[2]
SRC = ROOT / "src" / "github_steward"
GS_I5_ACCEPTED_CANDIDATE = "578cdd7c65c35b1dff517785392297ea15e7c3ae"
BROKER_OWNED_MARKERS = frozenset(
    {
        "broker",
        "credential",
        "github_app",
        "jwt",
        "security",
        "token",
    }
)
PERSISTED_SECRET_NAMES = frozenset(
    {
        "app_jwt",
        "authorization_header",
        "bearer_token",
        "installation_token",
        "jwt",
        "private_key",
        "private_key_pem",
    }
)
SECRET_FREE_OBJECT_PATHS = (
    SRC / "domain",
    SRC / "application" / "local_processing.py",
    SRC / "application" / "preparedness.py",
    SRC / "ports" / "persistence.py",
    SRC / "adapters" / "postgres",
)


def _python_files(path: pathlib.Path) -> Iterator[pathlib.Path]:
    if path.is_file():
        yield path
    elif path.is_dir():
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


def _broker_owned(path: pathlib.Path) -> bool:
    relative = path.relative_to(SRC).as_posix()
    return relative.startswith("infrastructure/") and any(
        marker in relative for marker in BROKER_OWNED_MARKERS
    )


def _class_field_names(path: pathlib.Path) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(_tree(path)):
        if not isinstance(node, ast.ClassDef):
            continue
        for statement in node.body:
            if isinstance(statement, ast.AnnAssign) and isinstance(
                statement.target, ast.Name
            ):
                names.add(statement.target.id.casefold())
    return names


def _uppercase_http_literals(path: pathlib.Path) -> set[str]:
    verbs = {"DELETE", "PATCH", "POST", "PUT"}
    return {
        node.value
        for node in ast.walk(_tree(path))
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value in verbs
    }


def test_pyjwt_is_imported_only_by_broker_owned_infrastructure() -> None:
    importers = {
        path.relative_to(SRC).as_posix()
        for path in SRC.rglob("*.py")
        if "jwt" in _import_roots(path)
    }
    assert importers
    assert not {relative for relative in importers if not _broker_owned(SRC / relative)}


def test_private_key_identifiers_are_broker_owned() -> None:
    offenders: set[str] = set()
    for path in SRC.rglob("*.py"):
        identifiers = {
            node.id.casefold()
            for node in ast.walk(_tree(path))
            if isinstance(node, ast.Name)
        }
        identifiers.update(
            node.arg.casefold()
            for node in ast.walk(_tree(path))
            if isinstance(node, ast.arg)
        )
        if {"private_key", "private_key_pem"} & identifiers and not _broker_owned(path):
            offenders.add(path.relative_to(SRC).as_posix())
    assert not offenders


def test_domain_processing_evidence_and_postgres_objects_are_secret_free() -> None:
    offenders: dict[str, set[str]] = {}
    for root in SECRET_FREE_OBJECT_PATHS:
        for path in _python_files(root):
            sensitive = _class_field_names(path) & PERSISTED_SECRET_NAMES
            if sensitive:
                offenders[path.relative_to(ROOT).as_posix()] = sensitive
    assert not offenders


def test_postgres_schema_has_no_credential_columns() -> None:
    credential_columns = {
        f"{table.name}.{column.name}"
        for table in metadata.tables.values()
        for column in table.columns
        if column.name.casefold() in PERSISTED_SECRET_NAMES
    }
    assert not credential_columns


def test_unix_broker_source_does_not_reference_tcp_socket_families() -> None:
    prohibited: dict[str, set[str]] = {}
    for path in SRC.rglob("*.py"):
        names = {
            node.id
            for node in ast.walk(_tree(path))
            if isinstance(node, ast.Name) and node.id in {"AF_INET", "AF_INET6"}
        }
        names.update(
            node.attr
            for node in ast.walk(_tree(path))
            if isinstance(node, ast.Attribute) and node.attr in {"AF_INET", "AF_INET6"}
        )
        for node in ast.walk(_tree(path)):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                aliases = node.names
                names.update(
                    alias.name
                    for alias in aliases
                    if alias.name in {"AF_INET", "AF_INET6"}
                )
        if names:
            prohibited[path.relative_to(SRC).as_posix()] = names
    assert not prohibited


def test_github_mutation_verbs_are_absent_except_control_plane_token_post() -> None:
    github_roots = (SRC / "adapters" / "github", SRC / "infrastructure" / "broker")
    mutation_literals: dict[str, set[str]] = {}
    for root in github_roots:
        for path in root.rglob("*.py"):
            verbs = _uppercase_http_literals(path)
            if verbs:
                mutation_literals[path.relative_to(SRC).as_posix()] = verbs

    assert mutation_literals == {"infrastructure/broker/app_control_plane.py": {"POST"}}


def test_gs_i5_adds_no_server_or_oauth_runtime_dependency() -> None:
    baseline_pyproject = subprocess.run(
        ["git", "show", f"{GS_I5_ACCEPTED_CANDIDATE}:pyproject.toml"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    project = tomllib.loads(baseline_pyproject)
    assert project["project"]["scripts"] == {
        "github-steward": "github_steward.cli:main"
    }
    dependency_names = {
        dependency.split("[")[0].split("<")[0].split(">=")[0].casefold()
        for dependency in project["project"]["dependencies"]
    }
    assert not dependency_names & {
        "authlib",
        "django",
        "fastapi",
        "flask",
        "gunicorn",
        "oauthlib",
        "pygithub",
        "requests-oauthlib",
        "uvicorn",
    }
