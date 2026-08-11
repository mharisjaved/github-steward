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
  - ".afef/specifications/gs-i4-deterministic-preparedness.md"
  - ".afef/work-records/gs-i4.yaml"
  - "src/github_steward"
  - "migrations/versions/0003_gs_i4_preparedness.py"
  - "tests"
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
stable UUID, positive version, numeric repository ID, exact predecessor,
effective interval, explicit required checks keyed by `(producer_app_id,
check_name)`, required statuses keyed only by Python `context.casefold()`, the
review-blocking policy, the acquisition-configuration digest, and the fixed
600-second freshness window. Whitespace and Unicode normalization are never
applied to status contexts. Successor rows form one transactional, no-fork
chain. Assessment always receives an exact profile identity; it never asks for
an implicit current profile.

The assessment schema is `github-steward/preparedness-assessment/v1`. Its
deterministic content binds repository, pull request, head, base, profile,
analysis view, seal time, evaluation time, freshness, verdict, ordered reason
codes, and evidence summary. Verdicts are exactly
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
`(updated_at, status_id)`. Only exact `success` satisfies a required status.
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
`gs_i2_0002`. Provider `github` and work type
`REFRESH_GITHUB_PULL_REQUEST` use numeric repository ID and pull number as the
semantic work subject. No GitHub credential, network access, mutation, LLM,
deployment, dependency change, or lock change is part of GS-I4.
