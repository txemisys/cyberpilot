# Render staging deployment

CyberPilot's first concrete managed staging target is Render.

This choice is intentionally narrow: one Node web service and one managed PostgreSQL 16 database. It does not introduce Kubernetes, a background worker, Redis, or additional infrastructure before pilot evidence requires them.

## Infrastructure as code

The repository root contains `render.yaml`.

It defines:

- one Node web service;
- one PostgreSQL 16 database;
- database connectivity through Render's private connection string;
- no public database allow list;
- `/api/health` as the application health check;
- immutable dependency installation through `pnpm install --frozen-lockfile`;
- Prisma migrations and production configuration validation in the pre-deploy phase;
- generated `AUTH_SECRET`;
- Microsoft credentials and public callback URLs as dashboard-provided secrets/placeholders.

## Current staging region and compute

The Blueprint currently declares `frankfurt` for both the application and database so they remain colocated.

Before provisioning, change the region if customer/data-residency requirements require another location. Render does not allow every resource region to be changed in place after creation.

The declared compute plans are:

- web: `0.5c-512mb`;
- PostgreSQL: `0.1c-256mb`.

These are intended as a small paid staging baseline, not a production sizing recommendation.

Applying the Blueprint can create billable Render resources. Do not provision it without explicit approval of the account/workspace and expected spend.

## Required secrets before first successful deploy

Provide these values through Render, never Git:

- `BETTER_AUTH_URL`
- `MICROSOFT_CLIENT_ID`
- `MICROSOFT_CLIENT_SECRET`
- `M365_GRAPH_CLIENT_ID`
- `M365_GRAPH_CLIENT_SECRET`
- `M365_GRAPH_REDIRECT_URI`

For the first pilot, leave every `M365_REMEDIATION_*` variable unset.

The public URLs must use HTTPS. The scanner redirect URI must point to the deployed callback route.

## Deployment behavior

Build:

```bash
corepack enable
pnpm install --frozen-lockfile
pnpm build
```

Pre-deploy:

```bash
pnpm db:migrate:deploy
pnpm db:migrate:status
pnpm production:check
```

Start:

```bash
pnpm --filter @cyberpilot/web start
```

Render injects the runtime `PORT` value used by the web service.

## Health and TLS

Render should be configured from the Blueprint to call:

```text
GET /api/health
```

CyberPilot considers the instance healthy only when the application can reach PostgreSQL.

Render provides HTTPS for the service URL and manages TLS for custom domains. If a custom domain is added later, update `BETTER_AUTH_URL` and the Microsoft redirect URI before switching traffic.

## Database recovery

The staging database must use a paid plan with recovery capability before it is accepted for a customer pilot.

CyberPilot already rehearses logical `pg_dump` / `pg_restore` in CI. After the managed database exists, perform one provider-level restore into a separate database and validate:

- migration status;
- `/api/health`;
- organization data;
- representative findings;
- immutable CyberScore history.

See `docs/backup-restore.md`.

## Operational acceptance

A Render deployment is not considered pilot-ready merely because it serves HTTP.

Before the first customer tenant:

1. production configuration check passes;
2. health checks remain stable;
3. HTTPS works on the intended public hostname;
4. Local Lab authentication is unavailable;
5. database recovery is exercised on Render;
6. logs are collected centrally and alert ownership is configured;
7. no remediation credentials are present;
8. Microsoft read-only readiness probe succeeds.

## Observability boundary

Render's platform logs, metrics, health checks and deployment notifications are useful infrastructure signals.

CyberPilot's structured application events should also be routed to a managed log/error destination before the first customer pilot. The collector and alert destination remain a separate readiness item until configured and tested.
