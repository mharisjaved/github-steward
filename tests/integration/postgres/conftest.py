"""Disposable PostgreSQL lifecycle for GS-I1 integration validation."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import secrets
import socket
from collections.abc import Iterator
from typing import Any

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from sqlalchemy.engine import URL, Engine, make_url

DATABASE_PREFIX = "github_steward_gs_i1_"
_DATABASE_NAME = re.compile(r"^github_steward_gs_i1_[0-9a-f]{24}$")


def _admin_url() -> URL:
    raw = os.environ.get("GS_TEST_DATABASE_ADMIN_URL")
    if raw is None:
        raise RuntimeError("GS_TEST_DATABASE_ADMIN_URL is required")
    url = make_url(raw)
    if url.drivername != "postgresql+psycopg":
        raise RuntimeError("admin URL must use postgresql+psycopg")
    host = url.host or str(url.query.get("host", ""))
    if host.startswith("/"):
        return url
    try:
        if not ipaddress.ip_address(host).is_loopback:
            raise RuntimeError("admin URL must target a loopback address")
    except ValueError as exc:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(
                host,
                url.port or 5432,
                type=socket.SOCK_STREAM,
            )
        }
        if not addresses or not all(
            ipaddress.ip_address(address).is_loopback for address in addresses
        ):
            raise RuntimeError(
                "admin URL hostname must resolve only to loopback"
            ) from exc
    return url


def _admin_engine() -> Engine:
    return sa.create_engine(
        _admin_url(),
        isolation_level="AUTOCOMMIT",
        poolclass=sa.pool.NullPool,
    )


def _database_identifier(name: str) -> str:
    if _DATABASE_NAME.fullmatch(name) is None:
        raise RuntimeError("unsafe disposable database name")
    return f'"{name}"'


def _create_database() -> tuple[str, str]:
    name = DATABASE_PREFIX + secrets.token_hex(12)
    identifier = _database_identifier(name)
    engine = _admin_engine()
    try:
        with engine.connect() as connection:
            exists = connection.scalar(
                sa.text(
                    "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = :name)"
                ),
                {"name": name},
            )
            if exists:
                raise RuntimeError("generated disposable database already exists")
            connection.exec_driver_sql(
                f"CREATE DATABASE {identifier} WITH TEMPLATE template0 ENCODING 'UTF8'"
            )
    finally:
        engine.dispose()
    runtime = _admin_url().set(database=name).render_as_string(hide_password=False)
    return name, runtime


def _drop_database(name: str) -> None:
    identifier = _database_identifier(name)
    engine = _admin_engine()
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql(
                f"ALTER DATABASE {identifier} WITH ALLOW_CONNECTIONS false"
            )
            for _ in range(100):
                sessions = connection.execute(
                    sa.text(
                        "SELECT pid, usename = current_user AS owned "
                        "FROM pg_stat_activity "
                        "WHERE datname = :name AND pid <> pg_backend_pid()"
                    ),
                    {"name": name},
                ).tuples()
                rows = list(sessions)
                for process_id, owned in rows:
                    if owned:
                        connection.execute(
                            sa.text("SELECT pg_terminate_backend(:process_id)"),
                            {"process_id": process_id},
                        )
                if not rows:
                    break
            else:
                raise RuntimeError(
                    "disposable database still has non-terminable sessions"
                )
            connection.exec_driver_sql(f"DROP DATABASE IF EXISTS {identifier}")
            remains = connection.scalar(
                sa.text(
                    "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = :name)"
                ),
                {"name": name},
            )
            if remains:
                raise RuntimeError("disposable database remains after cleanup")
    finally:
        engine.dispose()


def _alembic_config() -> Config:
    return Config("alembic.ini")


def _verify_admin() -> dict[str, Any]:
    engine = _admin_engine()
    try:
        with engine.connect() as connection:
            row = (
                connection.execute(
                    sa.text(
                        "SELECT current_setting('server_version_num')::integer "
                        "AS version_num, "
                        "rolcanlogin, rolcreatedb, rolsuper, rolcreaterole, "
                        "rolreplication, rolbypassrls, "
                        "inet_server_addr() AS server_address "
                        "FROM pg_roles WHERE rolname = current_user"
                    )
                )
                .mappings()
                .one()
            )
    finally:
        engine.dispose()
    address = row["server_address"]
    local = address is None or ipaddress.ip_address(str(address)).is_loopback
    return {
        "server_major": int(row["version_num"]) // 10000,
        "local": local,
        "login": bool(row["rolcanlogin"]),
        "createdb": bool(row["rolcreatedb"]),
        "superuser": bool(row["rolsuper"]),
        "createrole": bool(row["rolcreaterole"]),
        "replication": bool(row["rolreplication"]),
        "bypassrls": bool(row["rolbypassrls"]),
    }


def _assert_admin_capabilities(summary: dict[str, Any]) -> None:
    expected = {
        "server_major": 16,
        "local": True,
        "login": True,
        "createdb": True,
        "superuser": False,
        "createrole": False,
        "replication": False,
        "bypassrls": False,
    }
    if summary != expected:
        raise RuntimeError("PostgreSQL server or role does not meet GS-I1 boundaries")


@pytest.fixture(scope="session")
def postgres_database_url() -> Iterator[str]:
    """Create, migrate, and always remove one isolated integration database."""

    _assert_admin_capabilities(_verify_admin())
    name, runtime_url = _create_database()
    previous = os.environ.get("GS_TEST_DATABASE_URL")
    os.environ["GS_TEST_DATABASE_URL"] = runtime_url
    try:
        command.upgrade(_alembic_config(), "head")
        yield runtime_url
    finally:
        if previous is None:
            os.environ.pop("GS_TEST_DATABASE_URL", None)
        else:
            os.environ["GS_TEST_DATABASE_URL"] = previous
        _drop_database(name)


@pytest.fixture(scope="session")
def postgres_engine(postgres_database_url: str) -> Iterator[Engine]:
    """Provide a synchronous Core engine for the disposable database."""

    engine = sa.create_engine(postgres_database_url, poolclass=sa.pool.NullPool)
    try:
        yield engine
    finally:
        engine.dispose()


def _run_preflight() -> None:
    summary = _verify_admin()
    _assert_admin_capabilities(summary)
    name, runtime_url = _create_database()
    try:
        engine = sa.create_engine(runtime_url, poolclass=sa.pool.NullPool)
        try:
            with engine.connect() as connection:
                assert connection.scalar(sa.text("SHOW server_encoding")) == "UTF8"
        finally:
            engine.dispose()
    finally:
        _drop_database(name)
    print("postgresql_preflight=passed")
    print("server_major=16")
    print("endpoint_class=local")
    print("role_overprivileged=false")
    print(f"disposable_database={DATABASE_PREFIX}<unique>")
    print("disposable_database_removed=true")
    print("credentials_exposed=false")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preflight", action="store_true")
    args = parser.parse_args()
    if not args.preflight:
        parser.error("--preflight is required")
    _run_preflight()


if __name__ == "__main__":
    main()
