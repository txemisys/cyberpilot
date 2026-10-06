# Staging and production readiness

This document defines the minimum operational baseline before CyberPilot is exposed to a real customer.

It deliberately does not choose a cloud provider yet.

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

CyberPilot must not start a real production deployment with Local Lab settings.

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

A Content Security Policy is still outstanding because it must be introduced together with a verified Next.js-compatible nonce/hash strategy rather than a policy that silently breaks authentication or framework scripts.

## Database

Deployments must use:

```bash
pnpm db:migrate:deploy
pnpm db:migrate:status
```

Never run `db:push` in staging or production.

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

Before treating staging as usable:

- production configuration validation passes;
- migrations apply from the released revision;
- `/api/health` returns 200;
- HTTPS is enforced by the platform;
- Local Lab auth is unavailable;
- Microsoft login redirects to the expected tenant/account flow;
- organization membership boundaries still work;
- no remediation credentials are configured unless explicitly testing them;
- logs contain no access tokens or secrets;
- database backup/restore ownership is defined;
- error monitoring ownership is defined.

## Still required before production

The current readiness baseline does not yet provide:

- rate limiting;
- mature CSP;
- centralized application/error monitoring;
- automated backup restore testing;
- secret rotation automation;
- dependency/SAST/secret scanning beyond the existing CI checks;
- protected deployment environments.

Those remain production-hardening work and must not be implied as complete.
