---
schema_version: "0.2.0"
specification_id: "SPEC-0005"
title: "GitHub Steward Production Architecture Direction"
owner: "Harry5174"
specification_status: active
delivery_status: in_progress
dependencies:
  - "SPEC-0001"
supersedes: []
affected_paths:
  - ".afef/specifications/gs-d2-production-architecture.md"
acceptance_criteria:
  - id: "AC-0001"
    description: "The production direction preserves numeric GitHub identity, immutable evidence, deterministic assessment, separated authority, and read-before-write delivery."
  - id: "AC-0002"
    description: "GS-I4 is identified as an offline deterministic preparedness slice and not as deployment, authentication, live GitHub runtime, or production readiness."
---

# GS-D2 production architecture direction

The accepted production direction remains the modular monolith described by the
repository architecture baseline: GitHub owns remote truth, PostgreSQL owns
local workflow truth, and read, analysis, approval, execution, reconciliation,
and credential authority remain separated. Numeric GitHub repository, pull
request, application, user, team, status, check-run, and review identifiers are
semantic identities. Names, logins, slugs, owner/repository routes, and display
contexts do not silently replace those identities.

Deterministic evidence is sealed before conclusions are drawn. Canonical
observations, analysis views, profiles, and assessments are immutable and use
`jcs-sha256/v1`; assessments retain exact profile and analysis-view digest
bindings. Current state is represented by the existing versioned
compare-and-swap observation pointer. Source ordering is facet-aware; ambiguous
or regressing evidence cannot replace a current observation.

GS-I4 implements only the credential-free preparedness kernel of that direction:
recorded or fake GitHub evidence, bounded coherent acquisition, exact
profile-ID/version/digest application with profile-bound check policy,
application, deterministic assessment, immutable PostgreSQL persistence, and
current-pointer replay or promotion. It introduces no GitHub App authentication,
OAuth, webhook runtime, deployment, live GitHub access, GitHub mutation, LLM,
execution worker, or production credential flow. Those remain later, separately
authorized gates.
