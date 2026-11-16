# CyberPilot — Phase 2: Passive Exposure safety and Baseline development review

**Date:** 16 November 2026  
**Pull request:** https://github.com/txemisys/cyberpilot/pull/218  
**Roadmap:** Exposure #84 and Baseline #85.

## 1. Source-informed scope

The previous Phase 2 deliverables in PR #216 and #217 provided
offline Exposure normalization, declarative Baseline, persistent
questionnaire revisions, auditable work items and DNS ownership
challenges. A verified TXT record demonstrates control over the
challenge at observation time, but is **not equivalent** to
independently validated legal consent for scans or authorizing
collection from an arbitrary target.

This development round creates the remaining foundations while
deliberately retaining the no-LIVE-collector boundary.

## 2. C1 — Passive Exposure evidence and admission

- `exposure-passive-collection-policy.ts` defines read-only sources
  DNS, TLS handshake and HTTPS HEAD header observations; conservative
  ceilings, per-tenant scope, addresses and socket peer verification,
  explicit no-follow redirect and no-credentials requirements.
- Admission validates authorization existence, freshness,
  revocation, selected sources, canonical targets and independent
  consent. A signed-in user cannot independently elevate a DNS proof
  to permission to connect.
- DNS answers, TLS handshakes and HTTPS HEAD metadata from trusted
  collectors must meet separately checked constraints before
  becoming structured evidence. Source failures remain UNKNOWN.
- An integrity-digested ledger records attempts, number of calls,
  partial coverage, denied sources and cannot declare security
  certification or historical score changes.
- `exposure-passive-admission.ts` and the scoped endpoint expose
  a dry-run and **fail-closed** collection admission decision.
  They do not make network requests.
- The validators and ledger are production code used for future
  collectors; **no actual live HTTP/TLS collector is claimed**.

## 3. C2 — Durable scheduling and bounded quotas

- New PostgreSQL models `ExposurePassiveSchedule`,
  `ExposurePassiveReservation` and `ExposurePassiveEvent`
  provide per-organization policy versions, source selection,
  counters and immutable event history.
- Schedules start DISABLED and cannot become READY without
  verified legal consent in the database. The current service
  deliberately offers no operation that can set that value.
- RESERVE uses an idempotent request identifier and **records
  DENIED**, never issues an executable network lease.
  It preserves quota and audit evidence for attempted requests.
- Owner/admin RBAC and optimistic versions protect changes.
  Auditors may inspect historical evidence, but cannot alter
  collection policy.
- The web screen allows selecting sources, reading schedules,
  simulating DNS/TLS/HTTPS quotas, pausing and revoking; it
  communicates the missing independent consent explicitly.
- Management reporting includes safe JSON/CSV/Markdown exports
  without presenting schedules as real scans.

## 4. C3 — Internal technical review of Baseline

- A `BaselineReview` is tied to a particular submitted
  `BaselineRevision` and its verified report digest. Reviews
  of drafts or cross-tenant sources are rejected.
- `BaselineReviewEvent` stores each state change, finding digest,
  reviewer and audit metadata in the same database transaction.
- The workflow OPEN → IN_REVIEW → CHANGES_REQUESTED →
  IN_REVIEW → TECHNICALLY_REVIEWED supports review, clarification,
  reopening and optimistic concurrency.
- Review findings have bounded type/severity/status/description and
  optional opaque evidence references. Open blocking findings
  must be resolved or explicitly accepted as unknown before
  an internal review can complete.
- Owners, admins and auditors can perform internal technical
  reviews. Ordinary organization members have read-only access.
- A web workspace makes source versions, reviewer assignment,
  findings, status changes, history and comparisons accessible.
  Executive reports and safe exports preserve uncertainty.
- **TECHNICALLY_REVIEWED is an internal process status**. It does
  not prove control effectiveness, customer acceptance, external
  audit, regulatory compliance, or remediation.

## 5. Automated verification

- Full repository CI checks, security, LAB, Local stack E2E,
  existing Phase 2 development gates and a new exact-HEAD workflow.
- New adversarial tests: DNS rebinding, private addresses,
  mismatched peer, prohibited redirects, credential/body violations,
  foreign organization evidence, approval overclaim and digest
  tampering.
- PostgreSQL integration tests: schedule ownership, reservation
  idempotency, deny-by-default, audit, role restrictions, submitted
  Baseline revisions, reviewer findings, stale version conflicts
  and independent review reporting.

## 6. Deliberately outstanding

**Exposure #84:** real authorized DNS/TLS/HTTP passive collection
needs a separately authenticated, legally approved service,
atomic distributed rate limits, controlled network isolation,
actual socket-level validation and customer authorization.
Passing a simulated collector contract is not a live pilot.

**Baseline #85:** specific browser automation covering the complete
user flow (fill, save, reload, submit, reopen, follow-up, technical
review) is still to be verified in a suitably configured Playwright
environment. Current CI and PostgreSQL tests must not be
misrepresented as that browser journey.

**Never merge on a failing or incomplete exact-HEAD gate.**
Customer signatures and legal acceptance cannot be generated
by a development CI workflow.
