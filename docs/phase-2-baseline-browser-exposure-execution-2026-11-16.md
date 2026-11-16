# Phase 2 — Baseline browser acceptance and safe Exposure execution boundaries

Date: 2026-11-16. Draft PR #219. Development level A+B only.

## Baseline #85

The isolated LAB Chromium Playwright journey is implemented in
`tests/browser/baseline-persistence-review.spec.mjs`. It creates a
new LAB user and organization, answers and saves a questionnaire,
reloads saved answers from PostgreSQL, submits an immutable revision,
initializes and updates a human follow-up, creates/completes an
internal technical review, audits the state and reopens the draft.
This does not certify CIS or verify external customer controls.

The additional read-only dossier
`apps/web/lib/baseline-development-dossier.ts`, its tenant-scoped
service, API and reviewer interface cross-check source revisions,
submitted report digests, CAS histories and human follow-ups.
Missing audit events, cross-tenant sources and unverified reports
block technical traceability. Exported SHA-256 is a local integrity
check, **not an external signature**.

## Exposure #84

`packages/risk-engine/src/exposure-passive-execution-guard.ts`
contains a transport-injected executor **without a default network
transport**. It cannot be activated by ordinary product API routes.
Its caller must supply an independently issued, time-limited and
tenant-scoped execution lease, a trusted independent consent verifier,
an atomic durable reservation consumer and a controlled network worker.
Authorization is checked before every source. Both DNS resolution
checks surrounding TLS/HEAD consume actual quota. TCP/TLS/HEAD peer
identities must match public pinned DNS answers; redirect-following,
credentials and body collection are forbidden. Errors remain UNKNOWN.

The execution reconciler and portfolio check protocol counts,
source identities, event order, quota charges, SHA-256 local integrity,
tenant isolation and the prohibition of claims of security,
remediation, customer approval or historical CyberScore mutation.

**Missing for LIVE:** independent legally approved consent authority;
credential and service identity issuance; transactional executable
lease/consumption backed by PostgreSQL; a network-isolated collector
with actual DNS/TLS/HEAD socket-peer controls, transport limits,
distributed quotas and customer authorization. The current code
does **not** perform a LIVE scan or claim that these dependencies exist.

## Operational read-only evidence

`apps/web/lib/exposure-operational-closeout.ts`, the PostgreSQL
reader, reviewer-only API and dashboard at
`/organizations/[slug]/exposure/readiness` reconcile persisted
domain-ownership verification, schedule revisions, audit history,
reservation identity, quota counters, denial and potential anomalies.

The operational readiness report always requires separately
authenticated consent and a trusted collector. It never grants an
executable lease, enables schedules or signs customer approval.
This report and the Baseline dossier have deliberately bounded
tenant-scoped queries and cannot write data or fetch from external
providers.

## Acceptance and merge

- Each C round must exceed 1,000 net meaningful TS/TSX production
  lines separately, excluding tests, documentation and migrations.
- Run unit, risk-engine, TypeScript, PostgreSQL tests, LAB Chromium,
  local stack E2E, Security and all development acceptance workflows.
- Check every applicable workflow on the **same final PR HEAD**.
- Keep PR Draft until evidence passes and do not bypass branch
  protection, security gates or independent LIVE authorization.
- Close Baseline #85 only once its specific Playwright route is
  successfully verified on final HEAD. Leave Exposure #84 open until
  the separately authorized LIVE work is actually implemented.

An automated A+B completion is separate from level C real customer
signoff and does not convey approval to scan external systems.
