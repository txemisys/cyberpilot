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
| Structured operational logging | DONE FOR DEVELOPMENT | Redacted JSON events can be collected locally with Alloy/Loki/Grafana; production retention/alert routing remains an operational choice. |
| Dependency Review | BLOCKING PRODUCTION | Workflow prerequisite is GitHub Dependency Graph/alerts at repository level. |
| Zero-cost local integration environment | DONE | Docker Compose provides PostgreSQL + Alloy/Loki/Grafana; Tailscale Funnel is optional for public HTTPS callbacks. |
| Optional Render deployment example | AVAILABLE | `render.yaml` remains an optional managed-hosting path, not a development or pilot prerequisite. |
| Staging smoke automation | DONE | Manual workflow validates HTTPS, minimal DB-backed health response, HSTS and security/CSP headers against a deployed URL. |
| Tenant-free LIVE Graph simulation | DONE | The normal LIVE sync path is exercised against Microsoft-shaped OAuth/Graph responses without a Microsoft account or tenant, including pagination, malformed payloads, retries, atomic rollback, lease renewal and 10,000-user scale. |
| Stable HTTPS integration endpoint | BLOCKING REAL-TENANT VALIDATION ONLY | Required only when moving from simulation to actual Microsoft OAuth/admin consent; may be supplied by Tailscale Funnel or another controlled HTTPS endpoint. |
| Local observability stack | DONE | Alloy/Loki/Grafana run locally at zero infrastructure cost. |
| Production monitoring and alert routing | BLOCKING PRODUCTION | Must be selected and tested before broader production operation; no vendor is required during development. |
| Backup/restore regression rehearsal | DONE | CI performs PostgreSQL dump/restore into an isolated database and verifies data through Prisma. |
| Local backup/restore path | DONE | `pnpm dev:backup` and `pnpm dev:restore` exercise logical backup/restore locally; CI independently rehearses restore. |
| Content Security Policy | PARTIAL | Production emits a report-only baseline; staging validation plus nonce/hash hardening are required before enforcement. |
| Protected deployment environment | BLOCKING PRODUCTION | Production secrets/deployments need an explicit protected environment boundary. |
| Secret rotation process | DOCUMENTED / BLOCKING PRODUCTION DRILL | Provider-neutral rotation + rollback runbook exists; named owners, production secret boundary and a staging-like drill are still required. |
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

A production-only Content Security Policy now runs in report-only mode. Enforcement remains outstanding until staging validates Next.js/auth flows and a nonce/hash strategy removes unnecessary inline-script/style allowances.

See `docs/content-security-policy.md`.

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

CyberPilot emits redacted structured operational events for critical failures and Microsoft 365 sync lifecycle metrics (start, completion, duration, normalized object counts, coverage and safe failure classifications).

For local development, use the repository's Alloy/Loki/Grafana stack. Before broader production operation, define:

- transport;
- retention;
- access control;
- alert destinations;
- severity thresholds;
- incident ownership;
- regional/data-residency requirements;
- deletion policy.

See `docs/observability.md` and `docs/local-development.md`.

Render is retained only as an optional managed deployment example. See `docs/staging-render.md`.

## Database

Deployments must use:

```bash
pnpm db:migrate:deploy
pnpm db:migrate:status
```

Never run `db:push` in staging or production.

CyberPilot continuously rehearses logical dump/restore in CI and provides local backup/restore commands for development. A provider-specific restore exercise is required only when a managed production database is actually selected.

See `docs/backup-restore.md`.

## Secret rotation

CyberPilot now has a provider-neutral rotation and rollback runbook covering the application auth secret, Microsoft login/scanner credentials, database credentials and post-pilot remediation credentials.

The documentation does not by itself close the production blocker. Before production, assign primary/backup owners, select the protected production secret boundary and complete a staging-like rotation drill without exposing values.

See `docs/secret-rotation.md`.

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

A LIVE integration environment is usable when:

Run the manual `Staging smoke test` workflow against the deployed HTTPS URL as part of this acceptance. See `docs/staging-smoke.md`.


- production configuration validation passes;
- migrations apply from the released revision;
- `/api/health` returns 200;
- HTTPS is provided by a controlled endpoint when Microsoft OAuth is exercised;
- Local Lab auth is unavailable;
- Microsoft login redirects to the expected tenant/account flow;
- organization membership boundaries still work;
- no remediation credentials are configured for the first pilot;
- structured logs contain no access tokens or secrets;
- structured logs are inspectable locally or in the selected runtime;
- backup/restore mechanics have been exercised;
- no paid managed service is required merely to validate application functionality.

## First customer pilot gate

The first customer pilot remains read-only.

Before connecting a customer tenant:

1. the LIVE integration checklist is complete;
2. a controlled HTTPS callback is available for Microsoft OAuth;
3. backup/restore has been exercised locally or in CI;
4. dedicated scanner credentials are configured;
5. all `M365_REMEDIATION_*` values remain unset;
6. the documented four read-only Microsoft permissions are the only scanner permissions granted.

See `docs/first-customer-pilot.md` and `docs/first-live-tenant-runbook.md`.

## Production gate after the pilot

Do not describe CyberPilot as production-hardened until at least the following are complete:

- Dependency Review is active;
- CSP is validated and enforced;
- deployment environments are protected;
- secret rotation owners are assigned and the documented rotation/rollback drill has been completed;
- backup restore testing is repeatable;
- operational monitoring and alert ownership are proven in practice.

Items such as horizontal auth scaling, asynchronous workers and LIVE write remediation are intentionally deferred until real pilot evidence justifies them.


## Automated pilot-readiness evidence

The repository now continuously proves the following without a Microsoft tenant or paid development service:

- local PostgreSQL/Loki/Alloy/Grafana stack boots in CI;
- Prisma migrations apply and remain valid;
- the application health endpoint reports PostgreSQL readiness;
- structured application logs reach Loki;
- logical PostgreSQL backup and isolated restore succeed;
- the Microsoft 365 LIVE path is simulated with Graph-shaped responses;
- pagination, retry/backoff, payload guards, tenant isolation and sync concurrency are covered;
- LIVE sync publication is atomic and rolls back on mid-write failure;
- sync leases renew during long-running collection;
- LAB re-evaluation remains independent of LIVE-only Microsoft gates;
- repeated 10,000-user paginated LIVE snapshots remain duplicate-free;
- sync lifecycle metrics contain counts/durations/safe failure codes rather than customer payloads.

These automated checks are evidence about the repository and CI environment. They do not claim that a developer laptop, public HTTPS endpoint, Microsoft login, admin consent or a real customer tenant has been exercised.
