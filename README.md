# GitHub Steward

GitHub Steward is a single-tenant, GitHub App-backed control-plane agent whose
first planned slice will deterministically assess pull-request review
preparedness.

This repository contains the AFEF v0.2.0 adoption, the repository-owned
architecture baseline, and the bounded GS-I1 local foundation:

- [Project manifest](.afef/project-manifest.yaml)
- [Architecture specification](.afef/specifications/gs-architecture-baseline.md)
- [GS-A0 work record](.afef/work-records/gs-a0-adoption.yaml)
- [GS-I1 specification](.afef/specifications/gs-i1-local-foundation.md)
- [GS-I1 work record](.afef/work-records/gs-i1.yaml)

GS-I1 provides framework-free lifecycle contracts, strict constructed-value
RFC 8785 canonicalization with payload-only SHA-256 digests, domain-oriented
persistence ports, and one synchronous PostgreSQL/Alembic eight-table
foundation. Immutable observations, analysis views, and audit events have
append-only repository interfaces and PostgreSQL trigger enforcement. Database
role-grant enforcement remains deferred.

The canonicalization API accepts constructed Python values and does not parse
JSON text or bytes. Duplicate member names in raw JSON are therefore not
detectable after an ordinary parser has produced a Python mapping.

This is not the complete GitHub Steward persistence model and makes no
integration, write, operational, or production-readiness claim. GitHub
credentials, APIs, real reads, writes, deployment, and production database
roles remain disabled.
