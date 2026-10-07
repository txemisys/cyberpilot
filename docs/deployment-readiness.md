# Staging and production readiness

This document is the canonical operational-readiness source for CyberPilot.

It distinguishes what is already implemented from what still blocks staging, the first customer pilot, or broader production use. It deliberately does not choose a cloud provider.

## Readiness status

| Area | Status | Notes |
| --- | --- | --- |
| Production configuration validation | DONE | Required secrets/URLs validated; Local Lab auth rejected in production. |
| Versioned Prisma migrations | DONE | Staging/production use `db:migrate:deploy` and `db:migrate:status`. |
| Database health endpoint | DONE | `GET /api/health` checks PostgreSQL and returns 503 on failure. |
| Baseline HTTP security headers | DONE | Includes HSTS in production. |
| Sensitive product-route rate limits | DONE | PostgreSQL-backed fixed-window limits protect consent, probe, sync, Lab and remediation actions. |
| Reproducible dependency installs | DONE | `pnpm-lock.yaml` is committed and CI uses `pnpm install --frozen-lockfile`. |
| CodeQL | DONE | Runs on PRs, main and weekly schedule. |
| Structured operational logging | PARTIAL | Redacted JSON events exist; managed collection/alerting is not yet configured. |
| Dependency Review | BLOCKING PRODUCTION | Workflow prerequisite is GitHub Dependency Graph/alerts at repository level. |
| Managed staging deployment | BLOCKING PILOT | A real HTTPS staging environment has not yet been established. |
| Centralized monitoring and alerting | BLOCKING PILOT | Required before relying on staging for a customer pilot. |
| Backup/restore regression rehearsal | DONE | CI performs PostgreSQL dump/restore into an isolated database and verifies data through Prisma. |
| Managed staging backup/restore exercise | BLOCKING PILOT | CI proves mechanics only; the chosen managed PostgreSQL platform must still be exercised operationally. |
| Content Security Policy | BLOCKING PRODUCTION | Introduce a verified Next.js-compatible policy, preferably report-only first. |
| Protected deployment environment | BLOCKING PRODUCTION | Production secrets/deployments need an explicit protected environment boundary. |
| Secret rotation process | BLOCKING PRODUCTION | Manual or automated operational process still required. |
| Shared auth rate-limit storage for horizontal scaling | POST-PILOT | Required before horizontally scaling Better Auth traffic. |
| Background worker / async sync | POST-PILOT | Introduce only when real tenant latency/volume justifies it. |
| LIVE Microsoft write remediation | POST-PILOT | First customer pilot remains read-only. |

## Deployment sequence

A deployment should follow this order:

```text
build artifact
→ inject runtime secrets
→ validate production configuration
→ apply Prisma migrations
→ start web application
→ health check
→ smoke test authentication
→ smoke test organization access
→ smoke test read-only Microsoft probe when a tenant is connected
```

## Required production configuration

Required:

- `DATABASE_URL`
- strong `AUTH_SECRET` of at least 32 characters
- HTTPS `BETTER_AUTH_URL`
- Microsoft login client ID and secret
- dedicated Microsoft 365 scanner client ID and secret
- HTTPS scanner redirect URI

`LAB_AUTH_ENABLED` must not be `true`.

The remediation executor is optional and should remain completely unset for the first real tenant. If any `M365_REMEDIATION_*` value is configured, all three values must be configured and the redirect URI must use HTTPS.

## Health endpoint

`GET /api/health`

Success:

```json
{
  "status": "ok",
  "database": "ok"
}
```

Failure returns HTTP 503.

The endpoint intentionally exposes no tenant information, secret values, environment names, database hostnames or provider tokens.

## HTTP security baseline

The web application sends:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- restrictive `Permissions-Policy`
- `Strict-Transport-Security` in production

A Content Security Policy remains outstanding and should be introduced with a verified Next.js-compatible nonce/hash strategy. Prefer report-only validation before enforcement.

## Rate limiting

Authenticated high-impact product actions are protected by a PostgreSQL-backed fixed-window limiter.

See `docs/rate-limiting.md` for exact scopes and thresholds.

This control is implemented and must no longer be listed as outstanding.

## Security CI and dependency reproducibility

CyberPilot commits `pnpm-lock.yaml` and normal CI installs with:

```bash
pnpm install --frozen-lockfile
```

CodeQL is active.

Dependency Review remains blocked until GitHub Dependency Graph / alerts are enabled at repository level.

See `docs/security-ci.md`.

## Operational observability

CyberPilot emits redacted structured operational events for critical failures.

Before the first customer pilot, configure a managed collector/error-monitoring platform and define:

- transport;
- retention;
- access control;
- alert destinations;
- severity thresholds;
- incident ownership;
- regional/data-residency requirements;
- deletion policy.

See `docs/observability.md`.

## Database

Deployments must use:

```bash
pnpm db:migrate:deploy
pnpm db:migrate:status
```

Never run `db:push` in staging or production.

CyberPilot continuously rehearses logical dump/restore in CI. Before the first customer pilot, define database backup ownership and complete at least one restore exercise on the chosen managed PostgreSQL platform into a separate environment.

See `docs/backup-restore.md`.

## Secret handling

Use the hosting platform's secret manager or protected environment variables.

Never put real values in:

- Git
- Docker images
- CI logs
- issue comments
- screenshots
- CyberPilot audit metadata

## First staging acceptance checklist

Staging is usable only when:

- production configuration validation passes;
- migrations apply from the released revision;
- `/api/health` returns 200;
- HTTPS is enforced by the platform;
- Local Lab auth is unavailable;
- Microsoft login redirects to the expected tenant/account flow;
- organization membership boundaries still work;
- no remediation credentials are configured for the first pilot;
- structured logs contain no access tokens or secrets;
- centralized log/error collection is active;
- alert ownership is defined;
- database backup ownership is defined;
- a restore exercise has succeeded.

## First customer pilot gate

The first customer pilot remains read-only.

Before connecting a customer tenant:

1. staging acceptance checklist is complete;
2. managed monitoring/alerting is active;
3. backup/restore has been exercised;
4. dedicated scanner credentials are configured;
5. all `M365_REMEDIATION_*` values remain unset;
6. the documented four read-only Microsoft permissions are the only scanner permissions granted.

See `docs/first-customer-pilot.md` and `docs/first-live-tenant-runbook.md`.

## Production gate after the pilot

Do not describe CyberPilot as production-hardened until at least the following are complete:

- Dependency Review is active;
- CSP is validated and enforced;
- deployment environments are protected;
- secret rotation ownership/process exists;
- backup restore testing is repeatable;
- operational monitoring and alert ownership are proven in practice.

Items such as horizontal auth scaling, asynchronous workers and LIVE write remediation are intentionally deferred until real pilot evidence justifies them.
