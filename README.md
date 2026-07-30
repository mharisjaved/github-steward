# GitHub Steward

GitHub Steward is a single-tenant, GitHub App-backed control-plane agent whose
first planned slice will deterministically assess pull-request review
preparedness.

This repository currently contains only the AFEF v0.2.0 adoption and the
repository-owned architecture baseline:

- [Project manifest](.afef/project-manifest.yaml)
- [Architecture specification](.afef/specifications/gs-architecture-baseline.md)
- [GS-A0 work record](.afef/work-records/gs-a0-adoption.yaml)

No production implementation has begun. GitHub credentials, APIs, real reads,
and writes remain disabled. GS-I1 requires separate Product Owner
authorization.
