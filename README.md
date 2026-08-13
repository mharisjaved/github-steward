# GitHub Steward

GitHub Steward is a single-tenant, GitHub App-backed control-plane agent whose
first implemented candidate decision slice deterministically assesses
pull-request review preparedness from coherent evidence and an explicit
versioned profile.

This repository contains the AFEF v0.2.0 adoption, the repository-owned
architecture baseline, and the bounded GS-I1 through GS-I4 records:

- [Project manifest](.afef/project-manifest.yaml)
- [Architecture specification](.afef/specifications/gs-architecture-baseline.md)
- [GS-A0 work record](.afef/work-records/gs-a0-adoption.yaml)
- [GS-I1 specification](.afef/specifications/gs-i1-local-foundation.md)
- [GS-I1 work record](.afef/work-records/gs-i1.yaml)
- [GS-I2 specification](.afef/specifications/gs-i2-durable-local-processing.md)
- [GS-I2 work record](.afef/work-records/gs-i2.yaml)
- [GS-I3 specification](.afef/specifications/gs-i3-public-read-only-acquisition.md)
- [GS-I3 work record](.afef/work-records/gs-i3.yaml)
- [Production architecture direction](.afef/specifications/gs-d2-production-architecture.md)
- [GS-I4 specification](.afef/specifications/gs-i4-deterministic-preparedness.md)
- [GS-I4 work record](.afef/work-records/gs-i4.yaml)

GS-I1 provides framework-free lifecycle contracts, strict constructed-value
RFC 8785 canonicalization with payload-only SHA-256 digests, domain-oriented
persistence ports, and one synchronous PostgreSQL/Alembic eight-table
foundation. GS-I2 adds durable local processing and recovery, while GS-I3 adds
bounded anonymous public read-only acquisition. Immutable observations,
analysis views, and audit events have
append-only repository interfaces and PostgreSQL trigger enforcement. Database
role-grant enforcement remains deferred.

The local GS-I4 candidate adds credential-free recorded/fake coherent
acquisition, exact
`PreparednessProfile` and `PreparednessAssessment` v1 values, normalized status,
check, review, and requested-reviewer evidence, facet-aware source ordering, and
immutable preparedness persistence. Every assessment request names the exact
profile ID/version/digest and persists that binding together with the exact
analysis-view ID/digest. Profiles bind their accepted check-conclusion subset,
configuration version/digest, and 600-second assessment-freshness window.
Commit-status semantics use only `context.casefold()`; display casing remains
provenance and cannot advance the pointer. Freshness is based on the sealed
evidence time with a fixed 600-second inclusive window. Only proven source
progression may advance the existing versioned observation pointer.

The canonicalization API accepts constructed Python values and does not parse
JSON text or bytes. Duplicate member names in raw JSON are therefore not
detectable after an ordinary parser has produced a Python mapping.

This is not the complete GitHub Steward product and makes no write,
deployment, operational, or production-readiness claim. GS-I4 performs no live
GitHub access and introduces no credential flow, mutation, webhook, OAuth, LLM,
execution worker, or production database role.
