# Staging smoke test

CyberPilot includes a manual GitHub Actions smoke test for a managed staging deployment.

The workflow is:

```text
.github/workflows/staging-smoke.yml
```

It accepts only a public HTTPS base URL. It does not require Microsoft credentials, customer credentials, database credentials or application secrets.

## What it validates

The smoke test checks:

1. the supplied target uses HTTPS;
2. the URL does not embed credentials;
3. `GET /api/health` returns HTTP 200;
4. the health JSON is exactly the minimal expected shape:
   ```json
   {
     "status": "ok",
     "database": "ok"
   }
   ```
5. baseline production security headers are present;
6. HSTS is enabled;
7. the CSP report-only header is present;
8. blocking CSP has not been enabled before the documented staging validation gate.

The exact health response check is intentional: adding database hostnames, environment names, tenant metadata or other operational details to the public health response should fail the smoke test.

## Running it

From GitHub Actions, run **Staging smoke test** manually and supply the deployed HTTPS base URL.

For the initial Render target, use the actual Render service URL or the approved custom staging hostname.

Do not include:

- credentials in the URL;
- query-string secrets;
- access tokens;
- tenant IDs that are not meant to be public.

## What it does not validate

This workflow is deliberately unauthenticated and non-destructive. It does not validate:

- Microsoft sign-in;
- tenant admin consent;
- Microsoft Graph permissions;
- organization authorization boundaries;
- customer evidence;
- managed database restore;
- centralized log ingestion;
- LIVE remediation.

Those remain separate staging/pilot acceptance steps.

## Promotion gate

A green smoke test is necessary but not sufficient for the first customer pilot.

Before the pilot, also complete the managed database restore exercise, configure managed log/error collection and manually validate the documented read-only Microsoft readiness flow.
