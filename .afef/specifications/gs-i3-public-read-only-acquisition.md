---
schema_version: "0.2.0"
specification_id: "SPEC-0004"
title: "GS-I3 Public Read-Only GitHub Acquisition"
owner: "github-steward-product-owner"
specification_status: active
delivery_status: implemented
dependencies:
  - "SPEC-0001"
  - "SPEC-0002"
  - "SPEC-0003"
supersedes: []
affected_paths:
  - ".afef/project-manifest.yaml"
  - ".afef/specifications/gs-i3-public-read-only-acquisition.md"
  - ".afef/work-records/gs-i3.yaml"
  - "pyproject.toml"
  - "uv.lock"
  - "src/github_steward/domain/acquisition.py"
  - "src/github_steward/ports/github.py"
  - "src/github_steward/application/public_acquisition.py"
  - "src/github_steward/adapters/github/__init__.py"
  - "src/github_steward/adapters/github/public_rest.py"
  - "src/github_steward/cli.py"
  - "tests/architecture/test_boundaries.py"
  - "tests/unit/domain/test_acquisition.py"
  - "tests/unit/adapters/test_public_github.py"
  - "tests/unit/application/test_public_acquisition.py"
  - "tests/unit/test_cli.py"
  - "tests/integration/postgres/test_public_acquisition_postgres.py"
acceptance_criteria:
  - id: "AC-0001"
    description: "A project-owned synchronous port and adapter construct each request independently of injected client defaults, permit only anonymous HTTPS GET requests to api.github.com, send only allowlisted application headers with explicit timeouts, disable authentication and redirects, follow only validated Link next relations, and expose no GitHub mutation operation."
  - id: "AC-0002"
    description: "Authoritative raw bytes are size-bounded, SHA-256 hashed, strictly decoded as UTF-8 JSON with nested duplicate-key and unsupported-number rejection, and every required collection-item shape, stable field type, and source relationship fails closed."
  - id: "AC-0003"
    description: "Pull details, files, commits, reviews, exact-head check-suite count, and latest exact-head checks are acquired with complete pagination, explicit 1,000-suite and other upstream caps, count checks, and a bounded two-pass consistency retry."
  - id: "AC-0004"
    description: "A stable versioned snapshot records source identity, head and base SHAs, API version, completeness, raw-response digests, and a project canonical digest without retrieval timestamps or transport headers affecting identity."
  - id: "AC-0005"
    description: "A deterministic source-and-snapshot delivery identity enters through the accepted GS-I2 decoded-mapping intake and atomically creates durable inbox and work, classifies replay, and leaves no rows after validation, transport, consistency, limit, or transaction failure."
  - id: "AC-0006"
    description: "The local command emits concise JSON, automated tests remain offline, all new GS-I3 modules have 100 percent branch coverage, global branch coverage does not regress, and the public live smoke is bounded to PR 1."
  - id: "AC-0007"
    description: "The implementation commit descends from accepted main and GS-I3-CR1 is exactly one child of 3c4442940f82dc8334b68e37dc22e39effc452bb, with no push, pull request, merge, tag, release, deployment, authenticated GitHub access, or private probe."
related_decisions:
  - "GS-I3-ANONYMOUS-GET-ONLY"
  - "GS-I3-TWO-PASS-CONSISTENCY"
  - "GS-I3-REUSE-GS-I2-INTAKE"
related_evidence: []
---

# GS-I3 Public Read-Only GitHub Acquisition

GS-I3 adds the first real remote boundary without expanding GitHub authority.
The transport accepts only HTTPS `GET` targets at `api.github.com`, sends no
`Authorization` header, never fetches issue comments, and follows only
same-origin `rel="next"` links. Timeouts, retries, response bytes, pages, and
documented collection limits are all bounded.

Raw response bytes are authoritative. Each body is hashed before strict UTF-8
and JSON decoding. Duplicate keys at any depth, floats and non-finite numbers,
unexpected top-level shapes, required-field type errors, identity mismatch,
relationship mismatch, incomplete counts, and upstream truncation fail closed.

Acquisition reads the pull request, every required collection, and the pull
request again. A changed anchor discards the attempt and retries the complete
sequence once; a second change returns `CONCURRENT_CHANGE`. Only a stable
attempt becomes `github.pull_request_snapshot.v1`.

Snapshot identity excludes retrieval time and transport headers. It includes
repository and pull identity, head and base SHAs, validated semantic source
data, API version, completeness counts, and ordered raw-response digests. The
existing project RFC 8785 wrapper supplies the canonical snapshot digest.

The stable repository id, pull number, and snapshot digest derive the poll
delivery identity. Successful results use the existing GS-I2 decoded-mapping
receipt and its application-owned PostgreSQL transaction, so no migration or
parallel persistence path is introduced. This is bounded implementation
evidence, not production readiness or authorization for GitHub writes.

## GS-I3-CR1 boundary hardening

GS-I3-CR1 closes `GS-I3-ANON-001` by constructing each `httpx.Request`
directly and invoking the injected client with authentication and redirects
explicitly disabled. Client-level authorization, authentication, cookies,
query parameters, and redirect policy therefore cannot enter the request.

It closes `GS-I3-CHECK-001` by reading the exact-head check-suite summary
before check runs, validating its object shape and total, failing above 1,000,
and recording its raw digest and suite count in the snapshot. It closes
`GS-I3-SHAPE-001` by validating every collection entry as an object and
enforcing the stable required file, commit, review, and check-run fields and
relationships for API version `2026-03-10`.
