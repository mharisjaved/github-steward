---
schema_version: "0.2.0"
specification_id: "SPEC-0006"
title: "GS-I4 Deterministic Preparedness and Coherent Evidence"
owner: "Harry5174"
specification_status: active
delivery_status: implemented
dependencies:
  - "SPEC-0002"
  - "SPEC-0003"
  - "SPEC-0004"
  - "SPEC-0005"
supersedes: []
affected_paths:
  - "README.md"
  - ".afef/project-manifest.yaml"
  - ".afef/specifications/gs-architecture-baseline.md"
  - ".afef/specifications/gs-d2-production-architecture.md"
  - ".afef/specifications/gs-i4-deterministic-preparedness.md"
  - ".afef/work-records/gs-a0-adoption.yaml"
  - ".afef/work-records/gs-i4.yaml"
  - "src/github_steward/domain/__init__.py"
  - "src/github_steward/domain/acquisition.py"
  - "src/github_steward/domain/errors.py"
  - "src/github_steward/domain/preparedness.py"
  - "src/github_steward/application/__init__.py"
  - "src/github_steward/application/public_acquisition.py"
  - "src/github_steward/application/local_processing.py"
  - "src/github_steward/application/preparedness.py"
  - "src/github_steward/ports/__init__.py"
  - "src/github_steward/ports/github.py"
  - "src/github_steward/ports/persistence.py"
  - "src/github_steward/adapters/github/__init__.py"
  - "src/github_steward/adapters/github/public_rest.py"
  - "src/github_steward/adapters/postgres/__init__.py"
  - "src/github_steward/adapters/postgres/metadata.py"
  - "src/github_steward/adapters/postgres/repositories.py"
  - "src/github_steward/adapters/postgres/unit_of_work.py"
  - "migrations/versions/0003_gs_i4_preparedness.py"
  - "tests/architecture/test_boundaries.py"
  - "tests/contract/test_repository_ports.py"
  - "tests/contract/test_preparedness_properties.py"
  - "tests/unit/domain/test_acquisition.py"
  - "tests/unit/domain/test_preparedness.py"
  - "tests/unit/application/test_public_acquisition.py"
  - "tests/unit/application/test_preparedness.py"
  - "tests/unit/adapters/test_public_github.py"
  - "tests/integration/postgres/test_public_acquisition_postgres.py"
  - "tests/integration/postgres/test_preparedness_postgres.py"
  - "tests/integration/postgres/test_repositories.py"
  - "tests/integration/postgres/test_concurrency.py"
  - "tests/integration/postgres/test_schema_invariants.py"
  - "tests/integration/postgres/test_migrations.py"
acceptance_criteria:
  - id: "AC-0001"
    description: "A recorded/fake A-pass1-B-pass2-C acquisition seals a view only when anchor and corresponding facet semantic digests match, with at most two whole attempts."
  - id: "AC-0002"
    description: "PreparednessProfile v1 and PreparednessAssessment v1 are exact, deterministic, explicit-version, JCS/SHA-256 values with uncertainty precedence and a 600-second inclusive freshness boundary."
  - id: "AC-0003"
    description: "Status, check, review, requested-reviewer, and facet-aware ordering semantics fail closed where remote ordering or evidence coherence is not provable."
  - id: "AC-0004"
    description: "One linear migration adds exactly the three preparedness tables, preserves migrations 0001 and 0002, and enforces immutable records plus no-fork profile succession."
  - id: "AC-0005"
    description: "The existing current pointer performs replay no-op, progression CAS, regression/incomparable rejection, and one bounded reload/recompute CAS retry."
  - id: "AC-0006"
    description: "Frozen offline static, architecture, unit, contract, property, PostgreSQL, migration, coverage, AFEF, integrity, and secret checks pass without dependency or lock change."
---

# GS-I4 deterministic preparedness

GS-I4 adds a local, credential-free pipeline:

```text
recorded/fake GitHub evidence
  -> bounded coherent acquisition
  -> PreparednessProfile v1
  -> PreparednessAssessment v1
  -> immutable PostgreSQL evidence
  -> facet-aware current-pointer decision
```

The profile schema is `github-steward/preparedness-profile/v1`. A profile has a
stable UUID, positive version, numeric repository ID, exact predecessor
reference `(profile_id, version, digest)`,
effective interval, explicit required checks keyed by `(producer_app_id,
check_name)`, required statuses keyed only by Python `context.casefold()`, the
profile-configured subset of recognized success-like check conclusions, the
review-blocking policy, and an acquisition-configuration identity containing
version, digest, and the fixed 600-second assessment-freshness window.
Whitespace and Unicode normalization are never applied to status contexts.
Successor rows form one transactional, no-fork chain. Assessment always
receives the exact profile reference `(profile_id, version, digest)`; it never
asks for an implicit current profile.

The assessment schema is `github-steward/preparedness-assessment/v1`. Its
deterministic content binds repository, pull request, head, base, exact profile
ID/version/digest, exact analysis-view ID/digest, seal time, evaluation time,
freshness, verdict, ordered reason codes, and evidence summary. Verdicts are exactly
`READY_FOR_HUMAN_REVIEW`, `NOT_READY`, and `INDETERMINATE`. Evidence uncertainty
precedes product blockers. Freshness uses `evaluated_at - evidence_sealed_at`:
ages from zero through 600 seconds are fresh, older evidence is stale, and a
reversed clock is `EVIDENCE_CLOCK_ANOMALY`.

Each coherent attempt reads anchor A, all seven facets, anchor B, all seven
facets again, then anchor C. Facets are files, commits, reviews, requested
reviewers, exact-head check-suite count, latest exact-head check runs, and commit
statuses. A/B/C semantic digests and corresponding pass digests must match. A
failed attempt contributes no reusable partial facet; after two failed attempts
the result is `EVIDENCE_UNSTABLE`. `evidence_sealed_at` is read once, after all
equalities, immediately before the digest-bearing view is sealed.

Status identity is `context.casefold()` and latest selection is maximum
`(updated_at, status_id)`. Original casing is raw/display provenance and is
excluded from profile, status-facet, coherent-view, assessment-summary, and
source-order semantic identity. Only exact `success` satisfies a required status.
Check identity is `(producer_app_id, check_name)`; lifecycle and distinct
generation order use validated remote timing and numeric-ID tie-breaks, never
local acquisition order. Only current-head review history affects readiness;
neutral activity does not clear an opinion and a valid dismissal removes its
target. Requested users and teams use numeric identity, with login and slug as
display/routing evidence.

Candidate-to-current ordering is `REPLAY`, `PROGRESSION`, `REGRESSION`, or
`INCOMPARABLE`. Anchor, files, commits, statuses, checks, reviews, requested
reviewers, and check-suite count are compared independently and aggregated.
Replay performs no CAS. Only progression may advance the existing GS-I2 pointer.
Regression, incomparability, mixed advance/regression, and unresolved second CAS
failure cannot promote.

Persistence retains the eight accepted tables and adds only
`preparedness_profile`, `preparedness_assessment`, and
`preparedness_assessment_evidence` through revision `gs_i4_0003`, down revision
`gs_i2_0002`. Profile rows retain exact predecessor digests; assessment rows
retain exact profile and analysis-view digests, with foreign keys binding those
digests to their immutable source rows. Provider `github` and work type
`REFRESH_GITHUB_PULL_REQUEST` use numeric repository ID and pull number as the
semantic work subject. No GitHub credential, network access, mutation, LLM,
deployment, dependency change, or lock change is part of GS-I4.
