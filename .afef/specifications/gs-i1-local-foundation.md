---
schema_version: "0.2.0"
specification_id: "SPEC-0002"
title: "GS-I1 Local Domain, Canonicalization, and Persistence Foundation"
owner: "github-steward-product-owner"
specification_status: active
delivery_status: implemented
dependencies:
  - "SPEC-0001"
supersedes: []
affected_paths:
  - ".afef/project-manifest.yaml"
  - ".afef/specifications/gs-i1-local-foundation.md"
  - ".afef/work-records/gs-i1.yaml"
  - ".python-version"
  - ".gitignore"
  - "README.md"
  - "alembic.ini"
  - "pyproject.toml"
  - "uv.lock"
  - "src/github_steward/__init__.py"
  - "src/github_steward/domain/__init__.py"
  - "src/github_steward/domain/canonical.py"
  - "src/github_steward/domain/errors.py"
  - "src/github_steward/domain/lifecycles.py"
  - "src/github_steward/application/__init__.py"
  - "src/github_steward/ports/__init__.py"
  - "src/github_steward/ports/persistence.py"
  - "src/github_steward/adapters/__init__.py"
  - "src/github_steward/adapters/canonicalization/__init__.py"
  - "src/github_steward/adapters/canonicalization/rfc8785.py"
  - "src/github_steward/adapters/postgres/__init__.py"
  - "src/github_steward/adapters/postgres/metadata.py"
  - "src/github_steward/infrastructure/__init__.py"
  - "migrations/env.py"
  - "migrations/script.py.mako"
  - "migrations/versions/0001_gs_i1_foundation.py"
  - "tests/conftest.py"
  - "tests/unit/domain/test_canonical_contracts.py"
  - "tests/unit/domain/test_lifecycles.py"
  - "tests/contract/test_jcs_adversarial.py"
  - "tests/contract/test_jcs_vectors.py"
  - "tests/contract/test_repository_ports.py"
  - "tests/integration/postgres/conftest.py"
  - "tests/integration/postgres/test_concurrency.py"
  - "tests/integration/postgres/test_migrations.py"
  - "tests/integration/postgres/test_schema_invariants.py"
  - "tests/architecture/test_boundaries.py"
acceptance_criteria:
  - id: "AC-0001"
    description: "Exactly four immutable fail-closed lifecycle families implement every authorized transition, reject every other transition without mutation, and preserve BlockReason as a separate reason inventory."
  - id: "AC-0002"
    description: "A strict project-owned adapter accepts only constructed supported Python values, enforces the exact safe integer and timestamp policies, emits RFC 8785 UTF-8 bytes, and computes lowercase payload-only jcs-sha256/v1 digests."
  - id: "AC-0003"
    description: "Domain-oriented protocols expose append-only observation, view, and audit storage plus explicit pointer CAS, transactional inbox/work, lease, and unit-of-work boundaries without concrete production repositories."
  - id: "AC-0004"
    description: "Synchronous SQLAlchemy Core metadata and one transactional Alembic root revision define exactly the eight authorized PostgreSQL tables with deterministic names and append-only UPDATE/DELETE rejection triggers."
  - id: "AC-0005"
    description: "Local PostgreSQL 16 integration evidence proves transaction rollback, delivery conflict classification, pointer CAS, lease contention, immutable references, triggers, catalog invariants, and upgrade-downgrade-reupgrade behavior."
  - id: "AC-0006"
    description: "Locked Ruff, mypy, Import Linter, pytest, branch coverage, Alembic, catalog, and AFEF validation pass without changing the frozen project files."
  - id: "AC-0007"
    description: "The candidate remains one local commit on the authorized branch with no GitHub access, remote Git action, deployment, publication, production role, or readiness overclaim."
related_decisions:
  - "GS-I1-PACKAGE-BOUNDARY"
  - "GS-I1-JCS-RFC8785"
  - "GS-I1-SQLALCHEMY-CORE"
  - "GS-I1-ALEMBIC"
related_evidence: []
---

# GS-I1 Local Foundation

## Scope and authority

This specification implements the separately authorized local Sprint 1
foundation under the High Assurance profile. It is subordinate to SPEC-0001
and does not supersede or weaken that architecture baseline.

The bounded implementation contains domain lifecycle contracts,
canonicalization and digest contracts, repository ports, PostgreSQL metadata,
one migration, and local tests. It does not contain use cases, process entry
points, runtime composition, concrete repositories, network clients, webhook
ingress, GitHub behavior, production roles, containers, deployment, or CI.

## Lifecycle contract

The four state-machine families and their complete accepted transition sets are
those defined by SPEC-0001 and the Product Owner GS-I1 authorization:
ApprovalCandidate, Approval, ExecutableOperation, and ExecutionAttempt.
Unlisted transitions fail closed and immutable state values prevent mutation
after rejection. BlockReason is a distinct enumeration and is not a set of
additional states.

## Canonicalization contract

Only already constructed supported Python values cross the adapter boundary.
Booleans are checked before integers. Integers are limited to
`[-9007199254740991, 9007199254740991]`. Floats and all other unsupported
categories are rejected. Tuples normalize to ordered JSON arrays, mappings
require string keys, and lone Unicode surrogates fail.

Digest-bearing timestamps must already use
`YYYY-MM-DDTHH:MM:SS.ffffffZ`. The canonical payload bytes are RFC 8785 JCS
encoded as UTF-8. SHA-256 covers the payload only and is represented as
lowercase hexadecimal with format `jcs-sha256/v1`.

The API does not parse raw JSON. Duplicate member names are unobservable after
ordinary parsing into a Python mapping; duplicate-key ingress detection is
deferred and not claimed.

## Persistence contract

Repository protocols expose append/insert but no update or delete operation for
canonical observations, analysis views, and audit events. Current observation
pointers use versioned compare-and-swap. Delivery inbox and work creation share
one transaction boundary. Work leases use opaque tokens and guarded versions;
lease expiry does not authorize an external retry.

The PostgreSQL foundation contains exactly:

1. `delivery_inbox`
2. `work_record`
3. `work_attempt`
4. `canonical_observation`
5. `current_observation_pointer`
6. `analysis_view`
7. `analysis_view_observation`
8. `audit_event`

Immutable analysis-view links target observation version identifiers, never a
mutable current pointer. Migration-owned triggers reject UPDATE and DELETE on
canonical observations, analysis views, and audit events. Insert remains
permitted.

Append-only assurance is bounded as follows:

```yaml
append_only_enforcement:
  repository_interface: "ESTABLISHED"
  postgresql_trigger: "ESTABLISHED"
  postgresql_role_grants: "NOT_ESTABLISHED_DEFERRED"
```

No cryptographic immutability, cryptographic audit chain, or complete
persistence-model claim is made.

## Migration and evidence boundary

The deterministic revision is `gs_i1_0001`, with `down_revision = null`.
PostgreSQL DDL is transactional. Alembic metadata comparison is bounded and is
not complete schema-equivalence evidence; direct catalog and fresh migration
evidence remain separate.

Required deferred claims:

```yaml
schema_evidence:
  complete_schema_equivalence_claimed: false
duplicate_key_ingress_detection: "NOT_IMPLEMENTED_DEFERRED"
production_database_readiness: "NOT_CLAIMED"
github_integration_readiness: "NOT_CLAIMED"
write_readiness: "NOT_CLAIMED"
operational_readiness: "NOT_CLAIMED"
production_readiness: "NOT_CLAIMED"
```
