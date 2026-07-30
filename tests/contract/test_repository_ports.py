"""Repository interface shape and immutability contracts."""

from __future__ import annotations

import dataclasses
import inspect

from github_steward.ports.persistence import (
    AnalysisViewRecord,
    AnalysisViewRepository,
    AuditEventRecord,
    AuditEventRepository,
    CanonicalObservationRecord,
    CanonicalObservationRepository,
    CurrentObservationPointerRepository,
    InboxWorkRepository,
    UnitOfWork,
    WorkLeaseRepository,
)


def _public_methods(protocol: type[object]) -> set[str]:
    return {
        name
        for name, value in inspect.getmembers(protocol, inspect.isfunction)
        if not name.startswith("_")
    }


def test_append_only_ports_expose_no_update_or_delete() -> None:
    assert _public_methods(CanonicalObservationRepository) == {"append"}
    assert _public_methods(AnalysisViewRepository) == {"insert"}
    assert _public_methods(AuditEventRepository) == {"append"}


def test_mutable_ports_are_explicitly_cas_and_lease_oriented() -> None:
    assert _public_methods(CurrentObservationPointerRepository) == {"compare_and_swap"}
    assert _public_methods(WorkLeaseRepository) == {"acquire", "release"}
    assert _public_methods(InboxWorkRepository) == {"create_delivery_and_work"}
    assert _public_methods(UnitOfWork) == {"commit", "rollback"}


def test_immutable_port_records_are_frozen_values() -> None:
    for record in (
        CanonicalObservationRecord,
        AnalysisViewRecord,
        AuditEventRecord,
    ):
        assert dataclasses.is_dataclass(record)
        assert vars(record)["__dataclass_params__"].frozen
