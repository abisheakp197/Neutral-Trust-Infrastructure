# Governance

This document describes how the Neutral Trust Infrastructure (NTI) project is
governed. NTI is an open, vendor-neutral project intended for contribution to the
Linux Foundation Decentralized Trust (LFDT).

## Technical Steering Committee (TSC)

The project is led by a Technical Steering Committee (TSC). The initial proposed
TSC is:

| Name | Role | Project / Organization | Scope |
| :--- | :--- | :--- | :--- |
| Abisheak P. | Lead Architect | NTI (Neutral Trust Infrastructure) | Runtime enforcement layer |
| Tymofii Pidlisnyi | Maintainer | Independent Researcher — Agent Passport System (APS) | Receipt / Agent-DID interoperability |
| Steven Zhao (Xinghua) | Initial TSC Member (Standards Capacity) | Independent Researcher | Standards and specification governance (ORCID: 0009-0001-0512-1237) |

The TSC and the maintainer list in [MAINTAINERS.md](MAINTAINERS.md) contain the
same individuals. Tymofii Pidlisnyi participates as an independent researcher and
is the author of the Agent Passport System (APS). Steven Zhao (Xinghua)
participates as an independent researcher (ORCID: 0009-0001-0512-1237) and serves
as an Initial TSC Member (Standards Capacity), contributing standards and
specification governance rather than day-to-day code maintenance. Both
write in a personal capacity, with no organizational affiliation, and do not
represent any organization.

Additional seats will be added as the contributor base grows, with the explicit
goal of increasing organizational diversity (see the LFDT expectation of
maintainers from three or more independent organizations for Graduated status).

## Decision Making

Decisions are made by **rough consensus** of the TSC.

- **Rough consensus** means that a proposal proceeds when no TSC member has a
  sustained, reasoned objection, and the majority of members who express a view
  are in favor. It is not a formal vote and does not require unanimity.
- Proposals are raised as public GitHub issues or pull requests, so that
  discussion happens in the open.
- If consensus cannot be reached, the TSC may fall back to a simple majority
  vote of sitting members. A tie is resolved by the Chair.
- Any TSC member may escalate a decision to the wider community for input before
  consensus is declared.

## Roles

- **Maintainers** review and merge contributions and are listed in
  [MAINTAINERS.md](MAINTAINERS.md).
- **Contributors** propose changes via pull requests. All commits must carry a
  Developer Certificate of Origin (DCO) sign-off — see
  [CONTRIBUTING.md](CONTRIBUTING.md).
- **External Advisors** provide independent review and have no binding vote.

## Changing This Document

Changes to this governance document require rough consensus of the TSC and are
made through a pull request to this repository.

## Code of Conduct

All participants must follow the [Code of Conduct](CODE_OF_CONDUCT.md).
