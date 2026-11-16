# CyberPilot — SME offline product integration, three development blocks

Development date: 2026-11-16. PR #221. This is not a real
customer security assessment or provider LIVE authorization.

## C1 — Persisted multi-source risk register

- Existing PostgreSQL SecurityEvidence, SecurityFinding,
  MultiSourceV2Assessment and BaselineFollowUp are read with tenant
  filtering, current reviewer membership and bounded collections.
- Evidence is grouped by domain, control and scope. Missing sources,
  contradictory values, expired records and database truncation
  are explicitly represented.
- Findings are grouped conservatively using their stable finding
  keys and rules: two distinct subjects cannot collapse merely
  because they share the same title or severity.
- Source states DECLARED, UNKNOWN, ERROR and STALE are never upgraded
  to a verified security posture; a stored v2 source label cannot
  independently authenticate a real tenant.
- The optional v2 assessment is displayed only with its stored model,
  source class and limitations. No legacy v1 CyberScore table writes.
- Exports JSON, CSV and Markdown include source IDs, uncertainty and
  local digest integrity, never customer certification.

## C2 — Auditable action tracking

- New provider-neutral IntegratedRiskAction and
  IntegratedRiskActionEvent Prisma models, PostgreSQL migration,
  tenant-scoped unique risk identity and immutable revision events.
- Action creation requires a real OPEN finding already in the
  tenant's persisted risk digest; free-form invented risk keys
  are rejected. Repeated creates remain idempotent.
- Owner assignment requires current membership in the same
  organization. Reviewers may read; OWNER/ADMIN modify.
- Transactional compare-and-swap revisions reject stale writes;
  the audit replays contiguous event numbers and checks the latest
  canonical snapshot SHA-256 against PostgreSQL state.
- Workflows include assign, prioritize, start, block, report done,
  accept time-bounded exceptions, reopen, update due date,
  comment, and expire an exception. Unbounded exceptions are denied.
- DONE_REPORTED is an operator declaration. EXCEPTION is a
  local workflow record; neither verifies remediation nor creates
  legal customer risk acceptance or changes provider accounts.

## C3 — Executive cockpit and report

- Real evidence and action read models join into an on-demand
  executive digest: open and high-priority risks, missing owners,
  overdue work, unresolved risks without actions, declared closures,
  stale sources, source conflicts, synthetic score snapshot origin
  and explicit gaps in assessed coverage.
- The cockpit never recalculates or promotes v2 into the historical
  CyberScore v1 series. Comparisons between reports must not
  imply security risk reduction from fewer reported findings alone.
- Exported JSON, CSV and Markdown are tenant-scoped and digest
  checked. An integrity hash is not a legal signature.
- Existing organization dashboard links to three screens:
  `/integrated-risks`, `/integrated-actions`, and
  `/integrated-executive`. No tenant connection is required.

## Development acceptance A+B

- Unit tests validate uncertainty, cross-tenant references,
  immutable digest tampering, duplicate identity, stale records,
  CAS state machines, expiry and false certification.
- PostgreSQL integration verifies real organization membership,
  risk-to-action creation, idempotency, stale-write rejection,
  auditor read-only role, cross-tenant failure and executive
  reconciliation with no external network calls.
- LAB Chromium journey uses an isolated LAB user and organization,
  LAB-provided synthetic findings, the integrated risk register,
  a persisted action CAS transition and the executive export.
- Prisma validate, migration deploy/status, typecheck, unit tests,
  security, LAB browser, local stack, backup/restore rehearsal and
  existing multi-source acceptance workflows must pass on the
  same HEAD before Ready for review or squash merge.
- Each C measures only net new production TS/TSX, excluding tests,
  migrations, documentation and existing unchanged code.

## LIVE boundary and next roadmap

This project can pass development A+B without credentials from
Microsoft or Google. It has not verified any customer's real
security posture, authorized Exposure scans, or completed legal
customer acceptance. Exposure LIVE #84, Google LIVE #213,
CyberScore calibration #215 and actual pilot #37 remain
separate follow-up tasks.

Only claim successful A+B after the GitHub final commit has all
required checks completed/success and the squash merge is verified.
