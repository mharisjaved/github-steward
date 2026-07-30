---
schema_version: "0.2.0"
specification_id: "SPEC-0001"
title: "GitHub Steward Repository-Owned Architecture Baseline"
owner: "Harry5174"
specification_status: active
delivery_status: in_progress
dependencies: []
supersedes: []
affected_paths:
  - ".afef/project-manifest.yaml"
  - ".afef/specifications/gs-architecture-baseline.md"
  - ".afef/work-records/gs-a0-adoption.yaml"
  - "README.md"
acceptance_criteria:
  - id: "AC-0001"
    description: "The repository contains exactly one AFEF v0.2.0 manifest, this canonical architecture specification, and one GS-A0 work record."
  - id: "AC-0002"
    description: "The specification records the accepted R0 baseline, IR-01, IR-02, lifecycle, security, persistence, authority, and gate contracts without beginning implementation."
  - id: "AC-0003"
    description: "The pinned AFEF v0.2.0 offline validator exits 0 with empty standard output and standard error and does not mutate the three adopter records."
  - id: "AC-0004"
    description: "No production code, implementation dependency, credential, remote action, or path outside the four-file allowlist is introduced, and exactly one authorized local root commit records the GS-A0 candidate."
related_decisions:
  - "IR-01"
  - "IR-02"
related_evidence: []
---

# GitHub Steward Repository-Owned Architecture Baseline

## 1. Binding disposition and claims boundary

The binding R0 disposition is:

> Approve — AFEF Architecture Readiness Gate passed for local Sprint 1.

The accepted baseline is **Redesign v2 + Redesign v2.1 Resolution Package +
Redesign v2.1.1 Clarifications and Corrections + Final Architecture Readiness
Review**.

This disposition establishes architecture readiness for a future, separately
authorized local Sprint 1. It does not authorize GS-I1, GitHub integration,
production implementation, external reads or writes, deployment, release, or a
production-readiness claim. This repository currently records intended
architecture only; conformance evidence establishes documentation-contract
conformance, not operational correctness.

`READY_FOR_HUMAN_REVIEW` means only that a pull request is open, non-draft, its
bounded evidence is coherent and current, and no pending or blocking automation
result was observed. It does not mean merge-ready, correct, secure,
policy-compliant, fully approved, or safe to deploy.

## 2. Authoritative lineage and supersession

The six architecture sources are loaded in this exact order:

1. `/agent factory/Pasted text.txt` — Redesign v2 foundational architecture;
   authoritative where not corrected later.
2. `/agent factory/Pasted markdown(2).md` — independent v2 review; historical
   required-change findings, not the current disposition.
3. `/agent factory/Pasted markdown(3).md` — Redesign v2.1 resolution package;
   accepted subject to v2.1.1 corrections.
4. `/agent factory/Pasted markdown(4).md` — targeted v2.1 review; ten errata
   findings and lineage.
5. `/agent factory/Pasted markdown(7).md` — Redesign v2.1.1; authoritative
   corrections to v2 and v2.1.
6. `/agent factory/Pasted markdown(8).md` — final binding approval and
   future-gate obligations.

Later items correct earlier items only where they expressly resolve a conflict.
Earlier dispositions—Major Redesign Required, Approve with Required Changes,
and open-gate statements—are historical finding lineage. Whole-repository
mutable snapshots, `CLEAR`, mutable or executable proposals, generic external
exactly-once claims, generic `updated_at` monotonicity, caller-selected broker
scope, a combined analysis/write worker, post-preview marker creation, and
self-referential digest structures are superseded. The GS-R0 Recovery Report is
the recovery and disposition record; this specification is the canonical
repository-owned architecture document.

## 3. Product scope and non-scope

GitHub Steward is a dedicated, explicitly single-tenant, GitHub App-backed
control-plane agent implemented as a modular monolith with separated process
roles. Its first slice deterministically assesses pull-request review
preparedness from a profile. Read-only value precedes any write. The first
possible future write is one approval-gated pull-request conversation comment
in a sandbox. Python and `uv` are settled project-level choices, but no package,
framework, or dependency is selected here. No LLM participates in the first
slice.

Explicit non-scope:

- no merge, push, commit, branch modification, label change, review approval,
  requested-changes review, check run, status creation, autonomous comment, or
  other GitHub mutation;
- no code generation, source-code analysis, multi-tenancy, general multi-agent
  scheduler, LLM tool execution, or LLM access to credentials;
- no Authorization Server integration in the MVP (`AUTH-01` Option C);
- no microservices requirement and no use of Artifact 07 as production source;
- no real GitHub read, App registration, OAuth implementation, public webhook,
  or write capability before its later gate.

The product prohibition on commit creation and repository mutation is
unchanged. The one authorized local root commit records this repository's
governance baseline only; it grants no commit or mutation authority to the
GitHub Steward product.

## 4. Modular-monolith topology and authority

The modular monolith has separately runnable and separately authorized process
roles:

| Component/process | Responsibility | Forbidden authority |
| --- | --- | --- |
| Web | Validate webhook ingress, durably record deliveries, manage local operator sessions and approval capture, and display evidence | GitHub App private key, token minting, analysis, or GitHub writes |
| Read worker | Acquire current state, canonicalize bounded evidence, run deterministic assessment, and create proposals | Write tokens, approval, GitHub POST, or any credential-bearing LLM |
| Execution worker | Validate and execute one sealed allowlisted operation | Analysis, proposal creation, approval, or arbitrary endpoints |
| Reconciler | Converge state, expire approvals, repair leases, and reconcile unknown outcomes | Blind retry or compensating write |
| Credential broker | Mint narrowly scoped installation tokens from trusted record identifiers | Analysis, approval, caller-selected scope, or arbitrary GitHub actions |
| PostgreSQL | Own local workflow truth, immutable/versioned evidence, approvals, operations, attempts, and audit history | Authority over GitHub remote truth |
| GitHub | Own remote repository state, permissions, actors, and effects | Authority over local workflow or approval truth |

The execution worker is present architecturally but disabled before Write
Readiness. The accepted Stage 1 boundary also disables every GitHub write.

## 5. Domain inventory and lifecycle contracts

The canonical aggregates and contracts are:

- identity: `OperatorIdentity`, local session, role assignment, repository
  grant, and authorization version;
- integration authority: `InstallationObservation`, installation permission
  version, repository authorization, and repository capability;
- delivery: webhook delivery inbox, durable work record/outbox, work attempt,
  and lease;
- canonical state: Repository, Pull Request, Check Run, Commit Status event,
  Review Set observation, Requested Reviewer Set observation, and Conversation
  Comment;
- evidence: `PreparednessProfile`, `AnalysisView`, and
  `PreparednessAssessment`;
- decision control plane: Proposal, `PolicyDecision`, `ApprovalCandidate`, and
  `Approval`;
- execution: `ExecutableOperation`, `ExecutionAttempt`, `RemoteResult`, and
  `ReconciliationRecord`;
- assurance: `AuditEvent` and `SecurityEvent`.

Canonical state machines:

```text
ApprovalCandidate:
  PREVIEWED -> APPROVED | EXPIRED | SUPERSEDED | CANCELED

Approval:
  APPROVED -> EXPIRED | REVOKED
           | INVALIDATED_BY_STATE_CHANGE | SUPERSEDED

ExecutableOperation:
  SEALED -> QUEUED -> VALIDATING -> EXECUTION_IN_PROGRESS -> SUCCEEDED
  SEALED/QUEUED/VALIDATING -> INVALIDATED | BLOCKED | CANCELED
  EXECUTION_IN_PROGRESS -> MANUAL_REVIEW_REQUIRED

ExecutionAttempt:
  CREATED -> STARTED -> REQUEST_SENT_OR_POSSIBLE
  REQUEST_SENT_OR_POSSIBLE -> RESPONSE_RECEIVED | UNKNOWN_OUTCOME
  RESPONSE_RECEIVED -> CONFIRMED_APPLIED | CONFIRMED_NOT_APPLIED | UNKNOWN_OUTCOME
  UNKNOWN_OUTCOME -> RECONCILING
  RECONCILING -> CONFIRMED_APPLIED | CONFIRMED_NOT_APPLIED
               | MANUAL_REVIEW_REQUIRED
```

`BLOCKED` is an operation lifecycle state. These are reasons, not additional
lifecycle states:

- `INTEGRITY_FAILURE`
- `INCOMPATIBLE_SCHEMA`
- `REPOSITORY_ROUTE_MISMATCH`
- `PERMISSION_CHANGED`
- `POLICY_CHANGED`
- `AUTHORIZATION_REVOKED`

## 6. Bounded coherent evidence acquisition

An assessment uses a two-pass, bounded acquisition:

1. read pull-request anchor `A`;
2. acquire checks, commit statuses, reviews, and requested-reviewer facets with
   complete bounded pagination;
3. read pull-request anchor `B`;
4. reacquire the same volatile facets under the same bounds;
5. read pull-request anchor `C`;
6. seal an `AnalysisView` only if `A`, `B`, and `C` match, both passes cover the
   same required facets, corresponding canonical facet digests match, all
   pagination is complete, and every freshness and acquisition bound is met.

The anchor is tied to the authoritative numeric repository ID, pull-request
number, head and base identities, state, and draft status. Webhooks accelerate
refresh but never establish complete history. Partial, truncated, failed,
unstable, stale, or ceiling-limited acquisition fails closed. Concrete
pagination ceilings and freshness settings remain open until real-read
integration and may not be silently inferred during GS-A0 or local Sprint 1.

## 7. Canonical envelopes and digests

Every digest-bearing profile, view, assessment, policy input or decision,
approval candidate, semantic precondition, executable operation, and audit
evidence record uses this payload-only envelope:

```json
{
  "payload": {
    "...": "digest-covered fields"
  },
  "digest": {
    "format": "jcs-sha256/v1",
    "value": "<sha256>"
  }
}
```

Canonicalization is RFC 8785 JSON Canonicalization Scheme (JCS), encoded as
UTF-8, then hashed with SHA-256. The digest covers `payload` only. Records carry
an explicit schema and schema version. UTC RFC 3339 timestamps follow one fixed
precision policy; identifiers inside envelopes have one consistent string
representation; null and omitted are distinct; semantic sets are explicitly
sorted arrays; ordered sequences preserve semantic order; floating-point
fields, duplicate keys, and non-finite numbers are forbidden.

## 8. Persistence and transaction invariants

- GitHub owns remote truth; PostgreSQL owns local-workflow truth.
- Webhook delivery and durable work creation occur in one PostgreSQL
  transaction. The same delivery ID and digest is a duplicate; the same ID with
  a different digest is an integrity incident.
- Canonical observations are append-only. Current pointers use
  compare-and-swap plus entity-specific ordering. Analysis views reference
  immutable version IDs, never mutable pointers.
- Approval atomically creates the operator decision, approval, sealed
  operation, and audit event from the locked candidate.
- No PostgreSQL transaction is claimed to contain a GitHub side effect.
- `REQUEST_SENT_OR_POSSIBLE` is durably committed before the network `POST`.
  Lease expiry never authorizes another `POST`. Any possible send must
  reconcile before retry.
- Runtime roles may insert audit events but may not update or delete them.
- Required uniqueness covers client approval submission ID, candidate to
  approval, one approved approval per proposal version, one operation per
  approval, one active operation per repository/pull request/conflict key, one
  non-terminal attempt per operation, provider plus remote artifact ID,
  operation marker, and the applicable remote-result identity.

## 9. GitHub authority, routing, permissions, and reconciliation

The numeric GitHub repository ID is authoritative. Owner and repository names
are mutable routing data. If a route resolves to another numeric ID, the call is
blocked with `REPOSITORY_ROUTE_MISMATCH` and reconciliation begins.
Installation state, suspension, repository selection, and permissions are
versioned observations.

The later real-read ceiling is Metadata: read, Pull requests: read, Checks:
read, and Commit statuses: read. The later sandbox-comment ceiling adds Pull
requests: write. A permission ceiling never bypasses the endpoint allowlist,
repository capability, policy, approval, sealed-operation validation, process
separation, or disabled execution worker.

Scheduled state convergence is mandatory. External effects are not claimed
exactly once. Timeout, crash, proxy error, malformed response, connection loss,
or `5xx` creates an unknown outcome and requires reconciliation. A valid `201`
may confirm applied; a documented rejection may confirm not applied but does
not authorize blind retry. Comment reconciliation binds repository and pull
request, App bot numeric user ID, operation marker, time window, and returned
body digest. Incomplete or ambiguous bounded search requires manual review.

## 10. Operator, session, authorization, and credential boundaries

Operators authenticate through GitHub App user authorization with PKCE S256,
one-time state, and exact callback binding. Device flow is disabled. A GitHub
user token is used only transiently to resolve the stable numeric user ID and is
then discarded.

Local roles, repository grants, sessions, and an authorization version govern
approval. `github_app_authorization.revoked` revokes sessions, increments the
authorization version, expires candidates, and invalidates or blocks unexecuted
approvals and operations. Bootstrap is a one-time administrative command, not a
permanent runtime environment path. Operator authentication does not change
`AUTH-01` Option C: the MVP has no Authorization Server integration.

No agent, LLM, or analysis component receives credentials or executes a
credential-bearing tool. The credential broker exposes only:

```text
MintReadToken(work_record_id)
MintWriteToken(operation_id)
```

Scope is derived from trusted PostgreSQL records, never from caller-selected
installation, repository, permission, or endpoint values. The write trusted
computing base is the Credential Broker, Execution Worker, Endpoint Allowlist,
Sealed Operation Validator, and GitHub Write Adapter.

## 11. Exact-body approval and possible-send protocol

The operator previews and approves the entire final comment, including footer
and the preallocated operation marker:

```text
<!-- github-steward-operation:v1:<lowercase-uuid> -->
```

The operation ID is allocated in `ApprovalCandidate`; the executor cannot append
or alter content after approval. Immediately before any possible send, execute
this exact sequence:

```text
remote preconditions validated
-> policy revalidated
-> approval expiry checked
-> token minted
-> pre-write reconciliation
-> approval expiry checked again
-> persist REQUEST_SENT_OR_POSSIBLE
-> POST
```

The final approval-expiry check is immediately before durable possible-send
state and the `POST`. Reconciliation precedes every retry.

## 12. Mandatory Integration Readiness resolutions

### IR-01 — initial event and permission boundary

`issue_comment` is excluded from the initial Stage 3 webhook/event set. The
initial GitHub App therefore does not require Issues: read for that event.
Adding `issue_comment` later requires a separately justified and approved
permission/event change. Integration Readiness must verify that the real App
configuration matches this repository-owned decision.

### IR-02 — check-run acquisition

```yaml
endpoint: "GET /repos/{owner}/{repo}/commits/{head_sha}/check-runs"
filter: latest
per_page: 100
pagination: "complete and bounded over the endpoint result"
identity: "producer App numeric ID plus check-run name"
```

Concrete pagination ceilings and freshness settings remain open until real-read
integration. Partial, truncated, failed, unstable, or ceiling-limited
acquisition fails closed.

## 13. Accepted Stage 1 deployment boundary

The accepted future Stage 1 environment is a dedicated x86_64 Ubuntu 24.04 LTS
VPS using Docker Engine, Docker Compose, and Caddy TLS ingress. Enabled roles
are Web, read worker, reconciler, credential broker, and PostgreSQL, with
separate runtime and database identities and separate read/write Unix sockets
for broker capability classes. The execution worker, Redis, external object
storage, LLM, and every GitHub write remain disabled.

VPS provider, sizing, monitoring backend, secret-facility implementation,
backup provider, container composition, and deployment files are later
implementation or operational decisions. This accepted boundary does not
authorize creation of deployment files in GS-A0.

## 14. Decision register

Accepted decisions include the dedicated repository, single tenancy, modular
monolith, separate process identities, deterministic profile-driven PR
preparedness, GitHub App, GitHub remote authority, PostgreSQL workflow
authority, transactional inbox/outbox, at-least-once processing, entity
versions, two-pass evidence acquisition, compare-and-swap pointers,
non-executable proposals, exact preview, `ApprovalCandidate`, sealed
operations, semantic preconditions, JCS/SHA-256 envelopes, unknown outcomes,
reconciliation-before-retry, stable GitHub identity with transient user token,
Pull requests: write only for the later sandbox comment, Python with `uv`, no
LLM in the first slice, no LLM tool execution, and `AUTH-01` Option C.

Deferred decisions include real GitHub reads and App registration, all GitHub
writes, effective ruleset evaluation, multi-tenancy, general multi-agent
arbitration, LLM integration, Redis, external object storage, microservices,
managed or sign-only key infrastructure, cryptographically tamper-evident
audit, and broader production deployment.

Superseded decisions and terms are the earlier non-approval dispositions,
Artifact 07 as production code, whole-repository mutable snapshots, `CLEAR`
(replaced by `NO_OBSERVED_BLOCKERS`), mutable or executable proposals, generic
external exactly-once claims, generic `updated_at` monotonicity,
caller-selected credential scope, a shared analysis/write worker, marker
creation after preview, and self-referential digest structures.

Open implementation decisions are exact package layout, ORM versus direct
database access, migration tool, web framework, RFC 8785 implementation
dependency, testing and architecture-enforcement libraries, VPS provider and
sizing, deployment files, telemetry, backup and secret-management products,
and the concrete pagination ceilings and freshness configuration. They must be
explicitly decided at their applicable future gate and are not selected here.

## 15. Finding-closure matrix

| Finding generation | Canonical closure |
| --- | --- |
| Pre-v2: authority ambiguity, dual-write ingress, mutable snapshots, stale approvals, generic idempotency, undefined identity, external-write ambiguity | Resolved in Redesign v2 |
| v2 review: product semantics, coherent acquisition, permissions/endpoints, OAuth lifecycle, digest format, lease recovery, content safety, process isolation, migration and deployment decisions | Resolved in Redesign v2.1 |
| v2.1 review: volatile-facet stability, overstated `CLEAR`, preview/operation-ID contradiction, recursive digests, uniqueness, PKCE/revocation, installation refresh, broker scope, POST retry ambiguity, generic monotonicity | Resolved in Redesign v2.1.1 |
| Final review: `issue_comment` permission mismatch | Resolved canonically by IR-01 for the initial set; later addition remains separately gated |
| Final review: check-run endpoint semantics | Resolved canonically by IR-02; concrete bounds remain open until real-read integration |
| Final review: broker trust claim, blocked reason codes, and last-moment approval expiry | Accepted clarifications carried into this baseline |

## 16. Local Sprint 1 boundary

The architecture gate permits only a future, separately authorized local Sprint
1 containing domain contracts, aggregate state machines, canonical envelope and
digest contracts, persistence schema, database migrations, repository
ports/interfaces, and local architecture tests.

Even in that future sprint, GitHub credentials or App registration, operator
OAuth implementation, a public webhook endpoint, real GitHub reads, execution
worker write capability, and real GitHub writes remain prohibited. GS-A0 does
not authorize or begin that sprint. GS-I1 requires separate Product Owner
authorization and must make the still-open implementation decisions explicitly.

## 17. Gates and readiness claims

- **Integration Readiness:** requires real GitHub App registration,
  endpoint/permission verification including IR-01 and IR-02, real-read
  evidence, webhook behavior, TLS, and observability.
- **Write Readiness:** requires independent executor/security review,
  exact-body approval proof, kill switches, content validation, duplicate
  prevention, unknown-outcome recovery, and the enabled execution worker.
- **Operational Readiness:** requires backup/restore proof, alerts, runbooks,
  credential rotation, incident exercises, and measured RPO/RTO.
- **Production Release:** requires explicit repositories/actions/permissions,
  SAST, secret and container scanning, an SBOM, deployment provenance,
  retention approval, SLO approval, and explicit release authority.

No Integration, Write, Operational, or Production Release gate is passed by
this specification. No production implementation has begun, and no
production-readiness claim is made.

## 18. Assumptions and risks

The architecture relies on later verification of real GitHub behavior,
permissions, endpoint semantics, bounded acquisition settings, and operator
flows. Documentation can preserve intent and invariants but cannot prove those
external facts. GS-A0 therefore fails closed at documentation and offline
conformance: it does not use GitHub credentials, contact APIs, choose
implementation dependencies, or infer authority beyond the exact work record.
