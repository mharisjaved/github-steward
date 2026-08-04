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
    description: "Project-owned infrastructure constructs the synchronous HTTPX client and real transport with environment trust, authentication, cookies, default parameters, hooks, proxies, and redirects disabled; a policy-enforcing wrapper validates every final real or fake transport request as an allowlisted anonymous HTTPS GET to api.github.com."
  - id: "AC-0002"
    description: "Authoritative raw bytes are size-bounded, SHA-256 hashed, strictly decoded as UTF-8 JSON with nested duplicate-key and unsupported-number rejection, and every required collection-item shape, stable field type, and absolute semantic relationship URL is validated for exact canonical GitHub origin and identity before durable intake."
  - id: "AC-0003"
    description: "Pull details, files, commits, reviews, exact-head check-suite count, and latest exact-head checks are acquired with complete pagination, explicit 1,000-suite and other upstream caps, count checks, and a bounded two-pass consistency retry."
  - id: "AC-0004"
    description: "A stable versioned snapshot records source identity, head and base SHAs, API version, completeness, raw-response digests, and a project canonical digest without retrieval timestamps or transport headers affecting identity."
  - id: "AC-0005"
    description: "A deterministic source-and-snapshot delivery identity enters through the accepted GS-I2 decoded-mapping intake and atomically creates durable inbox and work, classifies replay, and leaves no rows after validation, transport, consistency, limit, or transaction failure."
  - id: "AC-0006"
    description: "The local command emits concise JSON, automated tests remain offline, all new GS-I3 modules have 100 percent branch coverage, global branch coverage does not regress, and the public live smoke is bounded to PR 1."
  - id: "AC-0007"
    description: "The original GS-I3 and its direct-child CR1 were integrated by PR 2 at merge commit 6422bdaa46cd9d5aa1e108b01879102b358531b0; CR2 is exactly one local direct descendant of that merge with no history rewrite, push, pull request, merge, tag, release, deployment, authenticated GitHub access, or private probe."
  - id: "AC-0008"
    description: "CR2 preserves credential-redacted raw command output, machine-readable branch coverage, PostgreSQL and migration validation, exact Git identities, one public-smoke request audit, cleanup proof, a verified candidate bundle, and a safe verified evidence archive outside the repository."
  - id: "AC-0009"
    description: "CR3 uses one immutable six-kind canonical endpoint model for original targets, absolute Link targets, and the final HTTPX 0.28.1 raw request target; every serialized path and query is byte-canonical, and the final policy compares the delegated endpoint with its project-owned intended identity."
  - id: "AC-0010"
    description: "Every paginated endpoint binds owner, repository, pull number or exact head SHA, endpoint kind, path, per-page value, filter and complete invariant query identity to the response-producing page, permits only the exact next page, and rejects before a cross-identity or nonconsecutive request can be delegated or durably accepted."
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

At the CR1 candidate stage, GS-I3-CR1 reported `GS-I3-ANON-001` closed by
constructing each `httpx.Request`
directly and invoking the injected client with authentication and redirects
explicitly disabled. CR1 asserted that client-level authorization,
authentication, cookies, query parameters, and redirect policy therefore could
not enter the request; the later post-merge review found that request hooks and
other inherited client behavior still operated after that validation.

CR1 reported `GS-I3-CHECK-001` closed by reading the exact-head check-suite summary
before check runs, validating its object shape and total, failing above 1,000,
and recording its raw digest and suite count in the snapshot. CR1 also reported
`GS-I3-SHAPE-001` closed at that candidate stage by validating every collection
entry as an object and
enforcing the stable required file, commit, review, and check-run fields and
relationships for API version `2026-03-10`.

## GS-I3-CR2 post-merge acquisition boundary remediation

GS-I3 and CR1 were integrated through PR 2 at merge commit
`6422bdaa46cd9d5aa1e108b01879102b358531b0`. A later post-merge independent
review superseded the earlier final-assurance disposition and reopened it as
AMBER. `GS-I3-ANON-001` and `GS-I3-SHAPE-001` are reopened;
`GS-I3-CHECK-001` remains closed with exact-head, 999/1,000/1,001, latest-filter,
snapshot-provenance, and no-persistence regression protection; and
`GS-I3-EVID-001` remains open pending review of the exact-candidate raw evidence.

CR2 removes the arbitrary `httpx.Client` seam. Project-owned infrastructure
constructs both the client and default transport with `trust_env=False`,
`follow_redirects=False`, `auth=None`, no cookies, no default query parameters,
no external hooks, no proxy configuration, explicit connect/read/write/pool
timeouts, bounded connection limits, and the existing bounded application retry
policy. Tests may supply only a synchronous transport. A project-owned wrapper
remains outside both real and fake transports and validates the final request
immediately before delegation: method, scheme, host, user information, port,
fragment, endpoint path, exact endpoint query, empty body, credential-bearing
headers, and application-controlled headers all fail closed. A redirect is
classified without a second request.

Every review `pull_request_url` is now required to equal the complete canonical
relationship
`https://api.github.com/repos/{owner}/{repo}/pulls/{pull_number}`. Scheme,
authority, host, user information, port, exact path, dot or percent-encoded
bypass, query, fragment, and expected owner/repository/pull identity are checked
before the accepted GS-I2 durable intake.

At CR2 implementation freeze, the IDE Agent status for the attempted
`GS-I3-ANON-001` and `GS-I3-SHAPE-001` corrections was
`IMPLEMENTED_PENDING_INDEPENDENT_VERIFICATION`, not formal closure. Exact-candidate
adversarial validation later superseded that provisional status and stopped CR2
RED. Commit `eb06320257e233b76109c2244d0dff712dfd2ac4`, tree
`dc24a00f56d0c2540f10405e0fdd07e70a6835c2`, directly descends from the merge,
but it is rejected, unaccepted, unpushed, and unmerged history. Its final policy
transport delegated `/repos/o/r/pulls/%31` after validating decoded `URL.path`,
and its pagination parser accepted an `Other/Repository` pull-request link while
acquiring `Harry5174/github-steward` pull request 1.

## GS-I3-CR3 canonical transport and pagination identity binding

CR3 is the single authorized local child correction of rejected CR2. One
immutable adapter-owned endpoint model enumerates pull detail, pull files, pull
commits, pull reviews, exact-head check suites, and latest exact-head check runs.
The same parser validates the original input before HTTPX normalization, every
absolute Link target, and the serialized `httpx.URL.raw_path` immediately before
the real or fake transport is delegated. It rejects all percent-encoded path or
query forms, non-ASCII targets, backslashes, ambiguous separators, dot or empty
components, noncanonical case and ordering, duplicate or unknown query keys,
missing invariants, bodies, credentials, and final endpoint substitution.

For files, commits, reviews, and check runs, an omitted first page means page 1.
Only an explicit successor page within the existing 100-page bound may continue.
Owner, repository, pull number or exact head SHA, endpoint kind, canonical path,
`per_page=100`, `filter=latest` where applicable, and the complete invariant key
set are immutable across each link in the chain. Pull detail and check suites do
not paginate. The accepted GS-I2 intake, RFC 8785 wrapper, synchronous HTTPX
0.28.1 construction, redirect prohibition, strict review relationship, and
check-suite completeness behavior remain unchanged.

CR3 supersedes CR2 only as a local correction attempt. Its two subcorrections
are `IMPLEMENTED_PENDING_SUPERVISOR_AND_INDEPENDENT_VERIFICATION` within the IDE
Agent record. `GS-I3-ANON-001` and `GS-I3-SHAPE-001` remain formally reopened;
`GS-I3-CHECK-001` remains closed with regression protection; and
`GS-I3-EVID-001` remains open until exact-candidate evidence is independently
verified. Implementation Supervisor review is pending, High Assurance
Independent Review is not yet authorized, and push and merge remain
unauthorized.
