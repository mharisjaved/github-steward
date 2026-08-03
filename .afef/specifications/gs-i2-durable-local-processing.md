---
schema_version: "0.2.0"
specification_id: "SPEC-0003"
title: "GS-I2 Durable Local Processing and Recovery"
owner: "github-steward-product-owner"
specification_status: active
delivery_status: implemented
dependencies:
  - "SPEC-0001"
  - "SPEC-0002"
supersedes: []
affected_paths:
  - ".afef/project-manifest.yaml"
  - ".afef/specifications/gs-i2-durable-local-processing.md"
  - ".afef/work-records/gs-i2.yaml"
  - "src/github_steward/domain/errors.py"
  - "src/github_steward/domain/processing.py"
  - "src/github_steward/ports/__init__.py"
  - "src/github_steward/ports/clock.py"
  - "src/github_steward/ports/persistence.py"
  - "src/github_steward/application/local_processing.py"
  - "src/github_steward/infrastructure/clock.py"
  - "src/github_steward/adapters/postgres/metadata.py"
  - "src/github_steward/adapters/postgres/repositories.py"
  - "src/github_steward/adapters/postgres/unit_of_work.py"
  - "migrations/versions/0002_gs_i2_durable_processing.py"
  - "tests/unit/domain/test_processing.py"
  - "tests/contract/test_repository_ports.py"
  - "tests/architecture/test_boundaries.py"
  - "tests/integration/postgres/conftest.py"
  - "tests/integration/postgres/test_concurrency.py"
  - "tests/integration/postgres/test_migrations.py"
  - "tests/integration/postgres/test_schema_invariants.py"
  - "tests/integration/postgres/test_repositories.py"
  - "tests/integration/postgres/test_local_processing.py"
  - "tests/integration/postgres/test_recovery.py"
acceptance_criteria:
  - id: "AC-0001"
    description: "The public synthetic boundary accepts exactly the authorized already-decoded mapping, validates and copies it, canonicalizes it through the project-owned boundary, deeply freezes it, and never treats raw JSON as authoritative."
  - id: "AC-0002"
    description: "Receipt atomically creates one durable inbox/work pair, derives all durable application identities with the fixed UUIDv5 namespace, and classifies same-digest replay and different-digest integrity conflict without overwrite under concurrency."
  - id: "AC-0003"
    description: "READ COMMITTED application-owned transactions implement SKIP LOCKED claim, guarded lease renewal and release, three-attempt retry decisions, atomic completion and classified failure, and bounded deterministic expired-work reconciliation without holding a transaction during CPU-only processing."
  - id: "AC-0004"
    description: "Revision gs_i2_0002 forms one linear Alembic chain, retains exactly eight tables, adds durable inbox payloads and exact state checks, makes the inbox the fifth append-only target, and enforces entity-coupled pointer references with a reversible downgrade."
  - id: "AC-0005"
    description: "Deterministic processing appends one observation, analysis view, immutable association, explicit current-pointer create/CAS outcome, and audit evidence; pointer conflict succeeds without retry and every authorized fault boundary has exact rollback or commit-before-ack evidence."
  - id: "AC-0006"
    description: "Locked offline formatting, lint, strict typing, import boundaries, real PostgreSQL tests, Alembic checks, global branch coverage of at least 95 percent, and the pinned AFEF validator pass with protected files and dependencies unchanged."
  - id: "AC-0007"
    description: "The candidate is exactly one local direct-descendant commit of c956a912ad8f541c7edb9ad20523a63f960d8e82 with no GitHub access, remote Git action, dependency change, deployment, external effect, or production-readiness claim."
related_decisions:
  - "GS-I2-DECODED-MAPPING-BOUNDARY"
  - "GS-I2-POSTGRESQL-WORKFLOW-AUTHORITY"
  - "GS-I2-DETERMINISTIC-LOCAL-PROCESSING"
related_evidence: []
---

# GS-I2 Durable Local Processing and Recovery

## Authority and scope

This High Assurance implementation is one direct descendant of accepted GS-I1
commit `c956a912ad8f541c7edb9ad20523a63f960d8e82`. It implements only durable
synthetic receipt, deterministic local processing, guarded leases, explicit
pointer create/CAS, classified local failure, and bounded expired-work
recovery. PostgreSQL remains the local-workflow authority.

Raw JSON bytes or text are not an authoritative input. The receipt service
accepts an already-decoded `Mapping[str, object]` with exactly `entity_kind`,
`entity_id`, `observed_at`, `sequence`, `expected_pointer_version`, and
`observation`. Validation, copying, project-owned RFC 8785 canonicalization,
digesting, and deep freezing occur before durable receipt. Duplicate object-key
detection remains deferred and is not claimed.

GitHub credentials, APIs, reads and writes, HTTP ingress, OAuth, sessions,
external queues, Redis, asynchronous persistence, execution workers, LLMs,
plugins, Artifact 07 runtime reuse, deployment, publication, and production
readiness are outside scope and prohibited.

## Deterministic processing contract

The fixed UUIDv5 namespace is `15200e7d-6747-5b89-bf26-870ce9894353` and the
provider/work type are `synthetic` and `PROCESS_SYNTHETIC_OBSERVATION`. Durable
delivery, work, attempt, observation, analysis-view, and audit identities use
the exact Product Owner-authorized derivation strings. Lease tokens alone are
opaque per-claim uniqueness values and are never durable application identity.

Receipt T1 uses PostgreSQL uniqueness for `(provider, provider_delivery_id)`.
It returns `CREATED`, `DUPLICATE_SAME_DIGEST`, or
`INTEGRITY_FAILURE_DIFFERENT_DIGEST` with the durable original identifiers and
never overwrites the accepted payload.

The complete work inventory is `AVAILABLE`, `PROCESSING`, `RETRY_WAIT`,
`SUCCEEDED`, and `FAILED`. The complete attempt inventory is `STARTED`,
`SUCCEEDED`, `RETRYABLE_FAILURE`, `TERMINAL_FAILURE`, and `ABANDONED`. Claiming
uses `FOR UPDATE SKIP LOCKED`, ordered by availability and work identifier, and
atomically creates the next positive `STARTED` attempt.

## Clock, lease, retry, and recovery boundary

Application and repository operations receive explicit timezone-aware UTC
timestamps. Only the standard infrastructure `Clock` implementation reads
`datetime.now(UTC)`; tests inject fixed clocks and preserve microseconds.

```yaml
lease_duration_seconds: 300
retry_delay_seconds: 60
maximum_attempts: 3
reconciliation_batch_limit: 100
renewal_requires: "now < lease_expires_at"
expired_when: "lease_expires_at <= now"
eligible_when: "available_at <= now"
```

Renewal, release, completion, and classified failure require the matching
work identifier, processing state, opaque lease token, and guarded version.
Retryable failures schedule attempts one and two after exactly 60 seconds;
attempt three fails terminally. Reconciliation orders expired processing rows
by expiry and identifier, handles at most 100, abandons the unfinished attempt,
clears ownership, increments the work version, and schedules immediate retry or
terminal failure. Repeated reconciliation is idempotent.

## Transactions, pointer result, and migration

The application owns transaction commencement and commit at PostgreSQL READ
COMMITTED. Repositories never commit, roll back, open a top-level transaction,
or expose SQLAlchemy values. T1 receipt, T2 claim, T3 renewal, T4 completion,
T5 classified failure, and T6 reconciliation are separate atomic boundaries.
Deterministic CPU-only processing occurs after T2 commit and before T4/T5.

Expected pointer version null creates version zero only when absent. Expected
integer `N` updates only persisted version `N` to `N + 1`. A missing or stale
pointer produces explicit `POINTER_CONFLICT`, preserves the new immutable
observation, completes successfully, records audit evidence, and never retries.

Alembic revision `gs_i2_0002` follows `gs_i1_0001`. It fails closed if historical
inbox rows exist, adds the four durable payload columns, exact workflow checks,
the inbox trigger, and entity-coupled pointer foreign key while retaining eight
tables and one migration head. Downgrade restores the accepted GS-I1 objects.

## Assurance and claims boundary

Tests cover mapping validation, deep immutability, deterministic identities and
digests, concurrency, lease boundaries, retry ceiling, pointer outcomes,
upgrade/downgrade/re-upgrade, schema and trigger inventories, every required
fault injection, commit-before-ack replay, reconciliation rollback and batch
limit, and complete exact-pattern database cleanup. No dependency changes are
authorized. Passing evidence is bounded local implementation evidence and is
not an independent review, final acceptance, external-effect, operational, or
production-readiness claim.
