---
schema_version: "0.2.0"
specification_id: "SPEC-0007"
title: "GS-I6 Verified Webhook Ingress and Durable Refresh Scheduling"
owner: "Harry5174"
specification_status: active
delivery_status: in_progress
dependencies:
  - "SPEC-0001"
  - "SPEC-0002"
  - "SPEC-0003"
  - "SPEC-0004"
  - "SPEC-0005"
  - "SPEC-0006"
supersedes: []
affected_paths:
  - ".afef/specifications/gs-i6-verified-webhook-ingress.md"
  - ".afef/work-records/gs-i6.yaml"
  - "migrations/versions/0005_gs_i6_webhook_ingress.py"
  - "pyproject.toml"
  - "src/github_steward/adapters/postgres/github_authorization.py"
  - "src/github_steward/adapters/postgres/metadata.py"
  - "src/github_steward/adapters/postgres/repositories.py"
  - "src/github_steward/adapters/postgres/unit_of_work.py"
  - "src/github_steward/adapters/postgres/webhook.py"
  - "src/github_steward/adapters/web/__init__.py"
  - "src/github_steward/adapters/web/github_webhook.py"
  - "src/github_steward/application/webhook_ingress.py"
  - "src/github_steward/domain/webhook.py"
  - "src/github_steward/ports/webhook.py"
  - "tests/architecture/test_boundaries.py"
  - "tests/architecture/test_gs_i5_security_boundaries.py"
  - "tests/architecture/test_gs_i6_webhook_boundaries.py"
  - "tests/contract/test_webhook_ports.py"
  - "tests/integration/postgres/test_migrations.py"
  - "tests/integration/postgres/test_schema_invariants.py"
  - "tests/integration/postgres/test_webhook_ingress_postgres.py"
  - "tests/integration/web/test_github_webhook.py"
  - "tests/unit/adapters/test_webhook_security.py"
  - "tests/unit/application/test_webhook_ingress.py"
  - "tests/unit/domain/test_webhook.py"
  - "tests/unit/infrastructure/test_credential_broker.py"
  - "uv.lock"
acceptance_criteria:
  - id: "AC-0001"
    description: "POST /webhooks/github performs a bounded streaming body read, validates the three required headers, verifies only exact-byte HMAC-SHA256 with constant-time comparison, and performs no GitHub request inline."
  - id: "AC-0002"
    description: "The default body limit is 8 MiB, the configurable hard ceiling is 25 MiB, and oversized input returns 413 before unbounded buffering or any durable delivery, work, body, or attacker-controlled security event."
  - id: "AC-0003"
    description: "Authenticated input is decoded as strict UTF-8 and parsed as strict JSON with duplicate keys, non-finite numbers, invalid Unicode scalars, non-object roots, and unsafe parser detail rejected without raw-body persistence."
  - id: "AC-0004"
    description: "The exact recognized event and action matrix produces zero or one pull-request, repository, or authorization refresh; permission-ceiling actions produce no work and a bounded SecurityEventV1; issue_comment and unknown events gain no refresh authority."
  - id: "AC-0005"
    description: "Repository and pull-request work is scheduled only from numeric payload identities after current trusted GS-I5 RepositoryAuthorization proves AUTHORIZED_READ, write_enabled false, and exact installation identity agreement."
  - id: "AC-0006"
    description: "One GitHub provider delivery identity creates at most one work record; same-ID same-raw-digest replay is idempotent, while same-ID different-raw-digest replay preserves the original and appends WEBHOOK_DELIVERY_INTEGRITY_CONFLICT."
  - id: "AC-0007"
    description: "SecurityEventV1 is append-only, bounded, canonical, and secret-safe; invalid or missing HMAC creates no delivery, work, or persistent attacker-controlled event."
  - id: "AC-0008"
    description: "Delivery, optional work, and required audit/security evidence commit atomically before acknowledgement; rollback leaves no partial state and a lost acknowledgement followed by redelivery creates no duplicate work."
  - id: "AC-0009"
    description: "Revision gs_i6_0005 is the sole child of gs_i5_0004, accepted migrations 0001 through 0004 remain byte-identical, downgrade and re-upgrade work, and no GS-I7 persistence or scheduling mechanism is introduced."
  - id: "AC-0010"
    description: "The GS-I5 credential broker remains exact-type fail-closed for new repository and authorization refresh work, while the endpoint adds no GitHub write permission, write method, acquisition, token, private key, or signature persistence."
  - id: "AC-0011"
    description: "Offline static, architecture, unit, contract, web, adversarial, concurrency, PostgreSQL 16, migration, branch-coverage, AFEF, integrity, secret-scan, bundle, and evidence-package validation meet the authorized GS-I6 gates."
  - id: "AC-0012"
    description: "GS-I6-LIM-001 is explicitly ACCEPTED_NON_BLOCKING: distinct valid CI deliveries may each create one repository refresh, at most one per delivery and without PR fan-out; final_resolution is GS-I7."
---

# GS-I6 verified webhook ingress

## Authority and lifecycle

GS-I6 is a later, separately authorized implementation package based on exact
commit `71af3d1967175d5f44127de8259535854ba19c13` and tree
`8c034cab99d93150f0b4ae64366635760139629a`. The authoritative external kickoff
and the Implementation Supervisor's `GS-I6_PREIMPLEMENTATION_GREEN` resolution
record Product Owner authorization for this bounded local pass. The GS-I5 work
record and project manifest correctly preserve the historical fact that GS-I6
was not authorized by the earlier GS-I5 closeout; this later authorization does
not rewrite that history. Implementation Supervisor review, independent review,
Product Owner candidate acceptance, integration, and every production action
remain pending or not issued.

## Trust boundary and processing order

A correctly signed webhook is permission to schedule later verification. It is
not repository truth, authorization truth, or preparedness evidence. The
endpoint is exactly `POST /webhooks/github` through a small ASGI/Starlette
boundary. It performs no GitHub HTTP request and never acquires GitHub evidence
inline.

The semantic order is fixed:

```text
bounded raw-body read
  -> required header validation
  -> HMAC-SHA256 over exact raw bytes
  -> constant-time comparison
  -> raw payload SHA-256
  -> strict UTF-8
  -> strict JSON with duplicate-key rejection
  -> event/action validation
  -> trusted authorization classification
  -> PostgreSQL transaction
  -> acknowledgement
```

Required headers are `X-GitHub-Delivery`, `X-GitHub-Event`, and
`X-Hub-Signature-256`. Only `sha256=` with the standard-library `hmac` and
`hashlib` implementation is accepted; legacy SHA-1 is rejected. The HMAC covers
the exact received bytes and uses constant-time comparison. The webhook secret,
complete supplied or expected signatures, and raw request body are never
logged, persisted, archived, or returned.

Streaming intake defaults to 8 MiB and is configurable only up to the 25 MiB
application ceiling. The limit is enforced while consuming ASGI body chunks.
An oversized body returns 413 with no delivery, work, body persistence, or
attacker-controlled event. Authenticated input then uses strict UTF-8 and a
strict JSON object parser that rejects duplicate keys, non-finite numbers,
invalid Unicode scalars, malformed JSON, excessive recursion, and non-object
roots without echoing parser detail or body content.

## Routing and permission ceiling

The recognized events are `ping`, `installation`,
`installation_repositories`, `github_app_authorization`, `pull_request`,
`pull_request_review`, `check_run`, `check_suite`, and `status`.
`issue_comment` remains excluded. Unknown authenticated events and unknown
actions are accepted with no refresh authority.

Pull-request actions `opened`, `reopened`, `closed`, `edited`, `synchronize`,
`converted_to_draft`, `ready_for_review`, `review_requested`, and
`review_request_removed` schedule `REFRESH_GITHUB_PULL_REQUEST` after the
authorization gate. Pull-request-review actions `submitted`, `edited`, and
`dismissed` use the same work type. Webhook review content is routing input
only; trusted evidence is reacquired later.

The Checks matrix is exact:

| Event | Action | Result |
| --- | --- | --- |
| `check_run` | `created`, `completed` | `REFRESH_GITHUB_REPOSITORY` after authorization |
| `check_run` | `rerequested`, `requested_action` | no work plus `WEBHOOK_PERMISSION_CEILING_MISMATCH` |
| `check_suite` | `completed` | `REFRESH_GITHUB_REPOSITORY` after authorization |
| `check_suite` | `requested`, `rerequested` | no work plus `WEBHOOK_PERMISSION_CEILING_MISMATCH` |
| `check_run`, `check_suite` | any other action | no work |
| `status` | actionless valid payload | `REFRESH_GITHUB_REPOSITORY` after authorization |

No Checks, pull-request, or Statuses write permission is added.

Installation actions `created`, `deleted`, `new_permissions_accepted`,
`suspend`, and `unsuspend`, and installation-repositories actions `added` and
`removed`, may schedule only `REFRESH_GITHUB_AUTHORIZATION`. They do not create
`InstallationObservation`, `RepositoryAuthorization`, or `AUTHORIZED_READ`.
`github_app_authorization: revoked` is a durable audit/control signal with no
repository work.

## Trusted authorization gate

Repository-scoped routing derives positive numeric `repository_id`,
`installation_id`, and, where applicable, `pull_number`. Payload identity
relationships must agree. Current GS-I5 `RepositoryAuthorization` is loaded and
independently validated. Pull-request or repository refresh work is permitted
only when capability is exactly `AUTHORIZED_READ`, `write_enabled` is false,
the trusted repository identity matches, and the reported installation matches
the trusted authorization context. Missing, inconsistent, unreadable,
write-enabled, denied, or mismatched authorization creates no repository-read
work. A bounded authorization refresh may replace that proposed work only where
the accepted route has a valid installation context. A webhook never asserts
its own trusted authorization.

## Durable identity, replay, and security evidence

Delivery identity is provider `github` plus the exact validated
`X-GitHub-Delivery`. `raw_payload_digest` is SHA-256 over the exact request
bytes. PostgreSQL serializes the provider delivery identity under a
transaction-scoped advisory lock. The delivery uniqueness constraint and the
unique work-to-delivery constraint enforce:

```text
one delivery -> zero or one durable work record
```

A new accepted delivery appends the sanitized delivery projection, optional
matching work, and required audit or SecurityEventV1 evidence. Same identity and
same raw digest is `IDEMPOTENT_REPLAY` with no duplicate effect. Same identity
and a different raw digest is `INTEGRITY_CONFLICT`: the original delivery is
unchanged, no new work is added, and
`WEBHOOK_DELIVERY_INTEGRITY_CONFLICT` is appended. Concurrency preserves the
same result.

SecurityEventV1 kinds initially are
`WEBHOOK_DELIVERY_INTEGRITY_CONFLICT`, `WEBHOOK_SIGNED_SCHEMA_INVALID`,
`WEBHOOK_SIGNED_IDENTITY_MISMATCH`,
`WEBHOOK_AUTHORIZATION_CONTEXT_MISMATCH`, and
`WEBHOOK_PERMISSION_CEILING_MISMATCH`. Metadata is a bounded, whitelisted,
canonical projection with its JCS digest and an append-only PostgreSQL trigger.
It cannot contain raw body, secret, signature, token, private key, or arbitrary
parser detail. Missing or invalid authentication returns 403 before durable
state, preventing unauthenticated storage amplification.

The stable response mapping is 202 for a new accepted delivery, same-digest
replay, unsupported authenticated event, signed-input classification, or
durably recorded integrity conflict; 400 for malformed required headers; 403
for missing or invalid HMAC; 413 for bounded-body rejection; and 503 for a
durability failure. Success is returned only after commit. Rollback leaves no
partial delivery, work, audit, or security state.

## Migration, compatibility, and bounded scope

Migration `gs_i6_0005`, down revision `gs_i5_0004`, adds only the raw webhook
digest representation, the two new work types, and append-only security-event
persistence. It introduces no coalescing, timer, worker daemon, reconciler,
polling, or GS-I7 table. Migrations 0001 through 0004 remain byte-identical.

The two new work types are `REFRESH_GITHUB_REPOSITORY` and
`REFRESH_GITHUB_AUTHORIZATION`; the existing
`REFRESH_GITHUB_PULL_REQUEST` remains the only broker-eligible type. The legacy
synthetic worker claims only synthetic processing work. GS-I6 adds only the
direct dependency families `starlette` and `uvicorn`, changes no more than 50
authorized paths, uses synthetic webhook secrets and disposable local
PostgreSQL 16, and performs no live GitHub or real webhook operation.

## GS-I6-LIM-001

`GS-I6-LIM-001 = ACCEPTED_NON_BLOCKING`.

Distinct valid CI webhook deliveries may each create one repository refresh
work record. Each delivery still creates at most one work record and check or
status input never fans out into pull-request refresh rows. Coalescing, timer
scheduling, a worker daemon, reconciliation, and periodic polling are not part
of GS-I6.

`final_resolution = GS-I7`.
