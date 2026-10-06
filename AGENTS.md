# AGENTS.md — CyberPilot project context

This file is the persistent handoff context for AI agents and contributors working on CyberPilot.

Read this file before making changes.

## Repository

- GitHub: `txemisys/cyberpilot`
- Default branch: `main`
- Current main after PR #10: `08f0457a9e8e2357f9b036377a6f565dece210ba`
- Primary working language with the product owner: Spanish
- Code/docs are mostly English unless there is a reason not to be.

## Product vision

CyberPilot is a virtual CISO / security autopilot for SMEs, initially focused on Microsoft 365.

Core workflow:

```text
Discover → Prioritize → Fix → Prove
```

CyberPilot is not intended to replace antivirus, EDR, Microsoft Defender, MDM, SIEM, VPN, firewalls, or backups. It is the intelligence, orchestration, prioritization, remediation, and evidence layer above those systems.

Initial target customer:

- B2B SMEs
- roughly 10–100 employees
- Microsoft 365 centric
- no full-time CISO
- need practical security guidance, remediation, and evidence

Core principles:

- tenant isolation is a security boundary
- least privilege
- evidence over assumptions
- human approval for critical actions
- data minimization
- auditability
- do not log tokens or secrets
- OAuth/OIDC for real deployments
- MFA/RBAC
- encryption
- rate limits
- backups/monitoring before production
- CyberScore is not a certification

## Milestones

1. **Discover** — connect a real company and find a real issue with evidence and remediation.
2. **Fix** — safely remediate at least one supported problem after explicit administrator approval.
3. **Sell** — a real customer pays to remain connected.

## Current architecture

Monorepo managed with pnpm.

Main stack:

- Next.js 16
- React 19
- TypeScript
- Prisma 6
- PostgreSQL
- Better Auth
- Microsoft Graph integration
- Vitest in the Risk Engine / integrations
- GitHub Actions CI

Relevant packages/apps:

```text
apps/web
packages/database
packages/integrations
packages/risk-engine
docs
.github/workflows
```

## Authentication model

Real deployment authentication:

- Microsoft login through Better Auth
- Microsoft Entra app for user login is separate from the scanner app
- scanner and remediation executor are also separate applications

Development-only Lab authentication was added in PR #10.

Environment flag:

```env
LAB_AUTH_ENABLED="true"
```

Local email/password auth is enabled only when:

- `NODE_ENV !== "production"`
- `LAB_AUTH_ENABLED === "true"`

Do not weaken this production boundary.

## Microsoft 365 integration model

The integration uses separate trust boundaries:

### 1. Application login app

Used to sign CyberPilot users in.

Typical env vars:

```env
MICROSOFT_CLIENT_ID
MICROSOFT_CLIENT_SECRET
```

### 2. Read-only Microsoft 365 scanner app

Uses app-only Graph credentials.

Typical permissions currently include:

- `Organization.Read.All`
- `User.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All` for MFA registration evidence

Typical env vars:

```env
M365_GRAPH_CLIENT_ID
M365_GRAPH_CLIENT_SECRET
M365_GRAPH_REDIRECT_URI
```

### 3. Separate remediation executor app

Used only for approved automated remediation.

Current automated action requires:

```text
RoleManagement.ReadWrite.Directory
```

This is a high-impact permission.

Typical env vars:

```env
M365_REMEDIATION_CLIENT_ID
M365_REMEDIATION_CLIENT_SECRET
M365_REMEDIATION_REDIRECT_URI
```

Do not merge scanner and remediation permissions for convenience.

## Microsoft 365 Lab Mode

PR #9 added a Microsoft 365 Lab Mode so CyberPilot can be tested without:

- a Microsoft tenant
- Azure
- a payment card
- Microsoft Graph calls
- Microsoft credentials

The integration now has:

```text
IntegrationMode = LIVE | LAB
```

Lab Mode is explicit in the UI and database.

In LAB mode CyberPilot:

- does not acquire Microsoft tokens
- does not call Microsoft Graph
- does not request Microsoft admin consent
- does not mutate any real tenant
- executes the supported automated remediation only against synthetic local database objects

The deterministic lab scenario includes:

- six active synthetic identities
- five Global Administrator assignments
- one guest Global Administrator
- one non-Global admin explicitly not MFA-capable
- one initial `.onmicrosoft.com` domain
- one custom domain
- SPF present
- DMARC `p=none`
- one missing Microsoft 365 DKIM selector signal

Expected initial findings include:

- `M365_GLOBAL_ADMIN_COUNT_HIGH`
- `M365_GUEST_GLOBAL_ADMIN`
- `M365_ADMIN_MFA_NOT_CAPABLE`
- `DOMAIN_DMARC_MONITORING_ONLY`
- `DOMAIN_M365_DKIM_SELECTORS_PARTIAL`

The guest Global Administrator finding includes the exact synthetic role-assignment ID, so the normal approval/execution/verification path can be exercised safely.

Resetting the lab restores the deterministic baseline.

When switching from LAB to LIVE, synthetic inventory/findings/remediations/score history must be cleared so fake and real evidence are never mixed.

See:

`docs/microsoft-365-lab.md`

## Local Lab quickstart

PR #10 added local development auth so the whole product can be tested without Microsoft.

See:

`docs/local-lab-quickstart.md`

Expected local flow:

```text
Local Lab login
→ create organization
→ Start Microsoft 365 Lab
→ review findings
→ review CyberScore
→ approve remediation
→ execute synthetic remediation
→ verify finding resolution
→ inspect posture history
```

Typical local setup:

```bash
docker run --name cyberpilot-postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=cyberpilot \
  -p 5432:5432 \
  -d postgres:16
```

Then:

```bash
corepack enable
pnpm install
pnpm db:generate
pnpm db:push
pnpm dev
```

Typical local `apps/web/.env.local` minimum:

```env
DATABASE_URL="postgresql://postgres:postgres@localhost:5432/cyberpilot"
AUTH_SECRET="<strong local-only random value>"
BETTER_AUTH_URL="http://localhost:3000"
LAB_AUTH_ENABLED="true"
```

Microsoft variables may remain empty in Lab Mode.

## Data model and implemented capabilities

Current important models include:

- User
- Session
- Account
- Verification
- Organization
- Membership
- AuditEvent
- Integration
- IntegrationConsentState
- DirectoryIdentity
- DirectoryRoleDefinition
- DirectoryRoleAssignment
- Domain
- SecurityFinding
- SecurityScore
- Remediation

Current organization roles:

- OWNER
- ADMIN
- MEMBER
- AUDITOR

## Risk Engine and CyberScore v0

Implemented rules currently include:

### Microsoft 365 identity rules

- `M365_GLOBAL_ADMIN_COUNT_HIGH` — HIGH
- `M365_GUEST_GLOBAL_ADMIN` — CRITICAL
- `M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE` — CRITICAL
- `M365_ADMIN_MFA_NOT_CAPABLE` — HIGH

### Domain rules

- `DOMAIN_DMARC_MISSING`
- `DOMAIN_DMARC_INVALID`
- `DOMAIN_DMARC_MONITORING_ONLY`
- `DOMAIN_SPF_MISSING`
- `DOMAIN_SPF_MULTIPLE`
- `DOMAIN_M365_DKIM_SELECTORS_MISSING`
- `DOMAIN_M365_DKIM_SELECTORS_PARTIAL`

CyberScore v0 uses severity points, context multipliers, and per-rule caps.

CyberScore is explicitly not:

- certification
- compliance proof
- breach prediction
- guarantee of security

See:

`docs/cyberscore.md`

## Domain security

Domain scanning currently checks:

- SPF
- DMARC
- Microsoft 365 DKIM selector DNS signals

Important implementation notes:

- DMARC references the current standard; RFC 9989 replaced RFC 7489 in 2026.
- SPF is based on RFC 7208.
- Microsoft 365 standard DKIM selectors are:
  - `selector1._domainkey`
  - `selector2._domainkey`
- DNS resolver errors must not be treated as proof that a record is missing.
- Microsoft DKIM selector absence is a signal, not proof that all outbound mail is unsigned.

See:

`docs/domain-security.md`

## Remediation architecture

Remediation lifecycle:

```text
Finding
→ Proposed remediation
→ Explicit approval
→ Execution or guided action
→ Verification
→ Audit evidence
```

Modes:

- GUIDED
- AUTOMATED

Current automation-capable action:

```text
M365_DELETE_DIRECTORY_ROLE_ASSIGNMENT
```

This is currently used only for:

```text
M365_GUEST_GLOBAL_ADMIN
```

Safety requirements already implemented:

- exact provider object IDs stored as evidence
- approval and execution are separate state changes
- executor re-reads the exact target
- principal and role definition must match approved evidence
- executor deletes only the exact assignment
- post-action verification requires the assignment to be absent
- all significant events are audit logged
- missing exact evidence degrades automation to guided remediation

See:

`docs/remediation.md`

## Posture history

CyberScore snapshots are stored as immutable `SecurityScore` records.

Snapshots include:

- model version
- score
- risk points
- COMPLETE/PARTIAL coverage
- supported/unsupported finding counts
- contribution details
- calculated timestamp

Snapshots are not retroactively recalculated.

## Important PR history

### PR #1 — Foundation

Merged.

Included:

- pnpm monorepo
- Next.js app
- Prisma
- Better Auth
- Microsoft sign-in
- organizations/memberships
- audit events
- CI

### PR #2 — Microsoft 365 integration

Merged.

Included:

- read-only scanner app
- tenant consent/callback
- identities and directory roles
- Graph client
- first identity findings

### PR #3 — MFA posture + risk engine

Merged.

Included:

- MFA registration evidence
- `AuditLog.Read.All`
- MFA capability states
- initial Risk Engine tests

### PR #4 — CyberScore and prioritization

Merged.

Included:

- CyberScore v0
- prioritization
- Top Actions
- calculation details

### PR #5 — Domain/email security

Merged.

Included:

- domain inventory
- SPF/DMARC/DKIM observation
- domain security rules
- DNS evidence handling

### PR #6 — Posture history

Merged.

Included:

- immutable CyberScore snapshots
- partial/complete evidence coverage
- score history UI

### PR #7 — Secure remediation playbooks

Merged.

Included:

- remediation models/lifecycle
- approval endpoint
- automated exact role-assignment deletion
- verification/audit
- separate remediation executor app

### PR #8 — Tenant-scoped remediation consent

Merged.

Included:

- separate per-tenant admin consent
- non-destructive RBAC capability probe
- remediation capability status
- exact-tenant consent flow

### PR #9 — Microsoft 365 Lab Mode

Merged.

Main after merge:

`8968b9968186e501fb1588195072f381a026190c`

Included:

- LIVE/LAB integration modes
- deterministic synthetic tenant
- lab sync
- local synthetic remediation
- lab reset
- safe LAB → LIVE cleanup

### PR #10 — Development-only local Lab authentication

Merged.

Main after merge:

`08f0457a9e8e2357f9b036377a6f565dece210ba`

Included:

- local email/password auth
- development-only environment flag
- local Lab login UI
- local Lab quickstart docs

## Critical technical debt — do not forget

### 1. Finding resolution lifecycle correctness — fixed in PR #13

Finding resolution is now evidence-aware.

Semantics:

```text
explicit bad evidence → open/update finding
explicit good evidence → resolve finding
unknown/error/unavailable evidence → keep prior finding open
```

MFA and SPF/DMARC/DKIM evidence scopes resolve independently, and identity/role findings do not depend on MFA availability.

Keep this behavior covered by regression tests.

### 2. Prisma migrations — baseline introduced after PR #13

The repository now has a versioned Prisma baseline and CI applies migrations to a fresh PostgreSQL service.

Use:

- `pnpm db:migrate:dev` to create future development migrations
- `pnpm db:migrate:deploy` for staging/production deployment
- `pnpm db:migrate:status` to verify state
- `pnpm db:migrate:baseline` only once for an existing database that was previously created with `db:push` and already matches the baseline

Do not use ad-hoc `db:push` for staging or production.

### 3. No real Microsoft tenant E2E test yet

The product has not yet completed a real live tenant end-to-end validation.

Lab Mode is valuable but is not proof that all Microsoft Graph behavior works in production.

### 4. Remediation credential hardening

Current executor uses a client secret.

For production, prefer a stronger credential model where practical, such as:

- certificate-based credentials
- workload identity / federation
- managed identity depending on hosting

### 5. Broad remediation permission

`RoleManagement.ReadWrite.Directory` is high impact.

Keep the executor isolated and require explicit admin consent.

### 6. Other known limitations

- no `pnpm-lock.yaml` yet
- no mature ESLint configuration
- Microsoft sync is still synchronous
- PIM eligible roles are not fully modeled
- group/service-principal role assignments are not fully covered
- admin coverage can miss cases when Graph MFA report `isAdmin` is false/null and role inference is incomplete

## Safe testing guidance

Do not test destructive remediation in a real business tenant unless explicitly intended and carefully prepared.

For any future LIVE remediation E2E test:

- use a disposable isolated test tenant
- no production data
- maintain at least two normal member Global Administrators / break-glass paths
- never make the test guest the sole administrator
- verify exact role assignment IDs
- remove all test privilege afterward
- grant admin consent deliberately

A first LIVE test may validate consent/probe/read-only scanning before any destructive action.

## Immediate next step

The product owner wants to run CyberPilot locally for the first complete Lab Mode walkthrough.

At the time this file was created, the next task is:

1. determine the user's local OS
2. install/verify Node.js 22.12+, Git, Docker Desktop
3. clone/update the repository
4. start PostgreSQL
5. configure `apps/web/.env.local`
6. run:
   ```bash
   corepack enable
   pnpm install
   pnpm db:generate
   pnpm db:push
   pnpm dev
   ```
7. open `http://localhost:3000/login`
8. create a Local Lab account
9. create an organization
10. click **Start Microsoft 365 Lab**
11. inspect findings and CyberScore
12. approve and execute the synthetic Guest Global Administrator remediation
13. verify finding resolution and score/history changes

## Working style

When continuing development:

- inspect the repository before assuming implementation details
- prefer feature branches and PRs
- keep CI green before merge
- be explicit about security boundaries
- never pretend a LIVE Microsoft behavior has been validated if only LAB has been tested
- do not expose secrets in chat, logs, commits, or screenshots
- keep explanations concise and practical
- communicate with the product owner in Spanish unless asked otherwise


## Recent changes after PR #15

### PR #16 — PostgreSQL Lab remediation E2E

CyberPilot now has a database-backed regression test for the full deterministic Lab flow:

```text
seed Lab
→ CyberScore 11
→ approve guest Global Administrator remediation
→ execute exact Lab role-assignment removal
→ verify absence
→ re-sync
→ CyberScore 70
```

The test uses real PostgreSQL in CI and verifies:

- five initial open findings
- exact automated remediation payload
- guest Global Administrator assignment removal
- `M365_GUEST_GLOBAL_ADMIN` resolution
- `M365_GLOBAL_ADMIN_COUNT_HIGH` resolution
- three unrelated findings remain open
- score history records 11 → 70

The LIVE Microsoft Graph remediation path is not exercised or modified by this E2E.

### Local Lab password recovery

Local Lab authentication supports development-only password recovery.

- `Forgot password?` requests a Better Auth reset token.
- The one-time reset URL is printed only to the local `pnpm dev` terminal.
- Token lifetime is 10 minutes.
- Existing sessions are revoked after password reset.
- This terminal delivery mechanism is disabled in production.

### LIVE read-only readiness

The next production-facing phase is read-only Microsoft 365 validation before any real write capability.

The scanner remains separate from the remediation executor.

Required scanner application permissions:

- `Organization.Read.All`
- `User.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`

A connected LIVE tenant can run a non-destructive readiness probe that uses only Microsoft Graph GET requests against:

- organization
- users
- directory role definitions
- directory role assignments
- authentication registration report

The probe must never invoke the remediation executor.

Per-scope outcomes:

```text
200/success → AVAILABLE
403         → PERMISSION_REQUIRED
other error → ERROR
```

Do not persist access tokens, secrets, or raw probe payloads.

## Immediate next production milestone

After the LIVE read-only readiness probe is merged and validated, the next milestone is a first real tenant read-only test:

1. configure a dedicated scanner Entra application
2. grant only the documented read-only application permissions
3. connect one controlled test tenant
4. run the read-only readiness probe
5. run the first inventory sync
6. compare normalized CyberPilot evidence with the tenant
7. keep remediation credentials unconfigured during this phase

Do not enable real Microsoft 365 write remediation until the read-only path has been validated independently.


### PR #18 — first LIVE tenant onboarding preflight

Because there is currently no real Microsoft tenant available, CyberPilot prepares the first-customer LIVE path instead of pretending to validate Graph.

The disconnected workspace UI now includes a LIVE preflight that clearly shows:

- whether scanner server configuration is ready;
- that a tenant administrator is required for consent;
- the exact four read-only scanner permissions;
- whether remediation credentials are configured;
- a preference that remediation remains unconfigured for the first LIVE tenant.

The Microsoft consent route also requires complete scanner credentials, not only client ID + redirect URI, before starting admin consent.

Runbook: `docs/first-live-tenant-runbook.md`.

For the first real tenant, leave all `M365_REMEDIATION_*` variables empty and validate read-only access before any write capability.


### PR #19 — Prove v1 executive security report

CyberPilot now exposes a dedicated organization executive report at:

`/organizations/[slug]/report`

The report is server-rendered from stored organization evidence and uses the latest immutable `SecurityScore` snapshot as the headline score/coverage/time.

It includes:

- CyberScore snapshot and score delta
- evidence coverage
- open finding counts by severity
- Top Actions generated from current supported open findings
- Microsoft 365 source/mode and last sync
- domain SPF/DMARC/M365-DKIM posture
- remediation status and verified remediation evidence
- explicit CyberScore non-certification disclaimer
- prominent LAB synthetic-evidence warning when applicable

The report has print CSS and a **Print / Save as PDF** action using the browser's native print-to-PDF path. No server-side PDF binary generation is required for v1.

Do not present a LAB report as evidence from a real tenant.


### PR #20 — executive report polish after real PDF review

A real browser-exported PDF revealed several presentation issues.

Fixes include:

- print CSS explicitly forces white backgrounds to prevent dark-theme bleed/black blocks
- report UI warns users to disable browser **Headers and footers** for a clean PDF
- headline improvement uses the first comparable immutable snapshot, so a Lab history such as 11 → 70 is shown as +59 even if the latest re-evaluation is 70 → 70
- remediation evidence excludes stale non-verified playbooks whose finding is already resolved
- verified remediations remain visible as historical evidence

Browser-generated date/URL/page-number headers are controlled by the browser print dialog, not reliably by page CSS.


### PR #21 — Prove v2 commercial executive report

The executive report now has a commercial first page designed for owners, management and MSP handoff.

Additions:

- explicit executive posture classification:
  - CRITICAL when any Critical finding is open
  - NEEDS ATTENTION when a High finding is open or CyberScore < 80
  - HEALTHY only when no Critical/High findings are open and CyberScore >= 80
- visible security progress from first comparable immutable snapshot to current score
- compact CyberScore trend from immutable snapshots
- dedicated **What CyberPilot fixed** section using VERIFIED remediations
- print page break after the executive first page so technical evidence starts on a separate page

The posture label is a prioritization aid, not certification or compliance attestation.


### PR #22 — Prove v2.1 print layout polish

A real Prove v2 PDF showed that the executive first page overflowed, pushing **What CyberPilot fixed** and the executive summary onto a mostly empty second page.

Prove v2.1:

- places **What CyberPilot fixed** and **Executive summary** in a compact two-column block on the first page;
- reduces print spacing and trend height without removing evidence;
- shows snapshot time as well as date in the CyberScore trend, so multiple snapshots from the same day are distinguishable;
- preserves the explicit page break before **Top priorities**.

Target output: a compact 3-page PDF where page 1 is executive, page 2 starts technical priorities/findings, and page 3 contains domain/remediation evidence.
