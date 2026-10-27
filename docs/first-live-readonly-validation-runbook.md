# First Microsoft 365 LIVE pilot — read-only validation runbook

> **HOLD — DO NOT START A MICROSOFT 365 TRIAL OR TENANT YET.**
> This document is a preparation artifact for the final, explicitly authorized validation window.
> All development before that decision uses LAB, synthetic Microsoft Graph responses and local E2E.
> Passing simulations is **not** evidence that LIVE works against Microsoft.

## 1. Authorization gate (before the trial clock starts)

- [ ] Project owner explicitly approves the date/time to start the Microsoft trial and confirms cost/cancellation terms independently.
- [ ] Freeze the candidate CyberPilot commit SHA; record CI, CodeQL, LAB browser and Local Stack E2E results.
- [ ] Confirm deployment environment, HTTPS public origin, redirect path and secure secret store. Never put client secrets, tokens or consent URLs with sensitive parameters into tickets, logs or screenshots.
- [ ] Confirm LAB authentication is disabled in the LIVE deployment (`LAB_AUTH_ENABLED=false`).
- [ ] Confirm isolated **scanner** app is used for Microsoft Graph, separate from sign-in. Do **not** configure `M365_REMEDIATION_*` credentials or request remediation consent.
- [ ] Confirm permissions against the actual scanner implementation and current Microsoft documentation before consenting; expected *read-only* application permissions in current CyberPilot UI are `Organization.Read.All`, `User.Read.All`, `RoleManagement.Read.Directory` and `AuditLog.Read.All`. Resolve any mismatch before proceeding.
- [ ] Prepare a customer/tenant administrator authorized to grant consent; obtain explicit approval of the scopes and evidence capture.
- [ ] Define test data, users, admins, domains and expected findings without exposing personal data in public logs.
- [ ] Verify database backup, encrypted storage, independent restoration, audit access and incident contact.
- [ ] Reserve time for fixes, repeat runs and end-of-trial cancellation checks.

**Stop:** Any missing prerequisite or write-permission request blocks real consent and scanning.

## 2. Evidence record (complete one row for every scenario)

| Field | Record |
| --- | --- |
| Scenario ID / operator / UTC start and end | |
| Release SHA / environment / Microsoft tenant alias (not secrets) | |
| Expected behavior and observed behavior | |
| Consent scopes approved (read-only) | |
| HTTP status / safe diagnostic code / audit event ID | |
| Before/after finding count, CyberScore, snapshot IDs / coverage | |
| Evidence location (restricted access, retention defined) | |
| Pass / Fail / Blocked and follow-up ticket | |

Record screenshots only with tenant identifiers and user details redacted. Do not capture authentication secrets, raw access tokens or authorization codes.

## 3. Ordered scenario matrix

| ID | Scenario | Expected evidence / acceptance |
| --- | --- | --- |
| P00 | Configuration preflight, without network consent | Public HTTPS callback accepted; localhost, unsafe URLs and configured write credentials block readiness |
| P01 | Consent initiated by authorized organization OWNER/ADMIN | State bound to user, organization and purpose; read-only scope list checked |
| P02 | Member/nonmember attempt | Server refuses cross-organization connection or synchronization; no tenant data disclosed |
| P03 | Invalid, expired or replayed callback state | Reject; no connection created; safe audit event |
| P04 | Consent denied or wrong tenant ID | Reject; wrong tenant cannot bind to organization |
| P05 | Successful read-only consent with intended tenant | Correct tenant identity, safe connection state and audit trail; no write scopes |
| P06 | Read-only Graph permission probe | READY only when all required evidence is available; PARTIAL/ERROR must not claim readiness |
| P07 | First inventory sync | Tenant, users, directory roles, MFA and domain evidence where permitted; source and UTC observation timestamp |
| P08 | Pagination / large user directory | No missing or duplicated pages; lease heartbeat and bounded resource use |
| P09 | Findings and CyberScore | Supported rules produce explainable findings; partial/unknown evidence is not classified secure |
| P10 | Guided remediation acknowledgment | Step progress and audit persisted; finding and score unchanged until fresh verification |
| P11 | Second sync / verification | New snapshots and trend; unchanged risky controls remain OPEN |
| P12 | Graph 401/403, 429, 5xx and truncated data | Safe error classification, backoff as implemented, preserved previous valid snapshots; no false resolutions |
| P13 | Connection error / expired permission / recovery | Operator guidance, re-consent if needed, successful repeat without tenant contamination |
| P14 | Two distinct organizations/tenants | Isolation of membership, records, results, reports and callback identities |
| P15 | Executive report / browser PDF | LIVE provenance, timestamp, model version, coverage and limitations; LAB evidence never presented as LIVE |
| P16 | Audit and log privacy | No secrets/tokens/authorization codes or unnecessary PII in output |
| P17 | Disconnect / end-of-pilot review | Access revoked as appropriate, secrets disabled, evidence retained only under agreed policy |

P00–P04 and failure branches should first be rehearsed with mocks in LAB; real-tenant scenarios run **only after explicit trial authorization**.

## 4. Execution order and stop rules

1. Capture baseline (commit, configuration, health, backup, timestamp and expected directory inventory).
2. Run P00–P06. If consent requires unexpected scopes, identity differs or probe is partial, **stop**, document and do not report LIVE readiness.
3. Run P07–P11 and collect row-by-row evidence; compare findings against a separately known expected inventory.
4. Run failure/recovery cases P12–P14 using controlled, non-destructive conditions; do not impair an unrelated production tenant.
5. Export and inspect PDF, audit events and privacy boundaries (P15–P16).
6. Complete P17. Mark every scenario Pass, Fail or Blocked; do not convert blocked scenarios into passes.

**Global abort conditions:** unexpected Graph write action or write scope, tenant mismatch, token/secret leak, cross-tenant exposure, broken backup/restore or irreversible action. Disable scanning and revoke application permissions where appropriate; preserve sanitized diagnostics and notify the operator.

## 5. Rollback and repeat plan

- Stop scheduled/manual sync jobs and disable scanner credentials in the deployment secret store.
- Revoke Microsoft app consent through the authorized administrator when ending or aborting the trial.
- Preserve last known-good CyberPilot snapshots; do not force findings to RESOLVED after failed Graph calls.
- Restore database only from a verified backup into an **isolated** environment first; verify migrations and tenancy. Do not overwrite production as a diagnostic shortcut.
- Record failed scenario, root cause, patch PR, successful CI/CodeQL/Playwright/E2E and precise repeat plan.
- At trial end, verify subscription status and any cancellation with Microsoft billing UI; do not assume auto-cancellation.

## 6. Exit criteria

A pilot may be called *real LIVE read-only validated* only when P00–P17 have documented results, all mandatory scenarios passed, failures have been re-run successfully, tenant boundaries and consent scopes are verified and the project owner signs off. If an external feature/licensing constraint prevents a scenario, mark it **Blocked** and explicitly state the unverified boundary. No percentage of LAB coverage alone satisfies this gate.
