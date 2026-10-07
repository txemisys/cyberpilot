# CyberPilot Architecture

## Current stage

CyberPilot is beyond the initial foundation stage.

The current architecture supports the complete Lab workflow and is preparing for the first real Microsoft 365 customer pilot:

```text
Discover → Prioritize → Fix → Verify → Prove
```

The first real customer pilot is intentionally read-only. The immediate architectural goal is not broader feature coverage; it is safe staging operation and validation against one controlled LIVE tenant.

## Architectural goals

1. Strong tenant isolation.
2. Least-privilege integrations.
3. Explainable, evidence-backed security findings.
4. Complete auditability of security-sensitive actions.
5. Minimal collection and retention of customer data.
6. Separate trust boundaries for login, scanning and remediation.
7. Simple infrastructure until real operational requirements justify more complexity.
8. Production changes must be observable, reversible where practical and validated through CI.

## Current components

### Web application

The Next.js application is the user-facing surface and the current API boundary.

It contains authenticated organization workflows, Microsoft consent callbacks, read-only probe/sync routes, Lab controls, remediation approval/execution routes, pilot readiness and the executive report.

### PostgreSQL

PostgreSQL is the system of record for organizations, memberships, integrations, normalized evidence, findings, CyberScore snapshots, remediations, audit events, consent state and application-level rate limits.

Versioned Prisma migrations are the deployment mechanism.

### Authentication

Better Auth handles application authentication.

Real deployments use Microsoft sign-in. Development-only Local Lab email/password authentication is explicitly disabled in production.

### Integration layer

Microsoft 365 is the first provider.

The integration separates:

1. application login credentials;
2. dedicated read-only scanner credentials;
3. separate high-impact remediation credentials.

Scanner and remediation permissions must not be merged for convenience.

### Microsoft 365 LIVE scanner

The first pilot scanner requests only:

- `Organization.Read.All`
- `User.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`

A non-destructive readiness probe validates those evidence scopes before the first full sync.

### Microsoft 365 Lab

Lab Mode provides deterministic synthetic evidence without Microsoft credentials, Microsoft Graph calls or real tenant mutations.

It remains a testing environment and must never be presented as LIVE customer evidence.

### Risk engine

The Risk Engine converts normalized evidence into explainable findings and priorities.

Finding resolution is evidence-aware:

```text
explicit bad evidence       → open/update
explicit healthy evidence   → resolve
unknown/error/unavailable   → preserve prior finding
```

### CyberScore and posture history

CyberScore snapshots are immutable records tied to a model version and evidence coverage.

Historical snapshots are not retroactively recalculated.

### Remediation

The architecture supports guided and explicitly approved automated remediation.

The remediation executor is a separate Microsoft application because its permission boundary is materially higher than the read-only scanner.

The first customer pilot does not enable LIVE write remediation.

### Prove / executive report

CyberPilot generates an executive security report from stored evidence and immutable score history.

LAB reports are visibly synthetic and cannot be represented as customer evidence.

### Operational controls

Current operational controls include:

- production configuration validation;
- database-backed health check;
- HTTP security headers;
- versioned migrations;
- PostgreSQL-backed sensitive-route rate limiting;
- reproducible dependency installs;
- CodeQL;
- redacted structured operational logging.

See `docs/deployment-readiness.md` for the canonical readiness status.

## Tenant boundary

Every customer-owned record must be attributable to an organization.

Application code must not rely solely on UI filtering for tenant isolation. Authorization checks must be enforced at server boundaries and covered by tests.

## Security-sensitive credentials

Provider credentials must:

- never be returned to the browser after authorization;
- never be logged;
- be encrypted before persistence when persisted;
- be accessible only to the minimum component requiring them;
- support revocation and rotation.

Prefer stronger credential models such as workload identity, managed identity or certificates when the hosting environment supports them.

## Auditability and observability

Business/security actions produce `AuditEvent` records.

Operational failures use a separate redacted structured logging path. Operational logs do not replace audit history.

## Background processing

Microsoft synchronization is still synchronous.

Do not introduce a worker merely to match an old architecture diagram. Add asynchronous processing when pilot telemetry shows a real need such as request timeouts, tenant size, scheduling or retry requirements.

## Immediate architectural milestone

The next milestone is:

```text
reproducible main
→ real HTTPS staging
→ managed logs/alerts
→ backup restore exercise
→ CSP validation
→ first controlled LIVE tenant read-only pilot
```

Success means CyberPilot can safely connect one real Microsoft 365 tenant, validate the documented read-only scopes, synchronize evidence, produce traceable findings/CyberScore and generate an executive report without requesting Microsoft write permissions.

Only after that pilot should the architecture expand toward scheduled background sync, multi-customer operational tooling or LIVE remediation.
