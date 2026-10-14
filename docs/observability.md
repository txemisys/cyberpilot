# Operational observability

CyberPilot emits structured operational events for important failures.

This is a provider-neutral baseline. It can later feed a managed logging/error platform without changing event semantics.

## Output

Operational events are JSON lines written to stdout/stderr.

Example shape:

```json
{
  "timestamp": "2026-10-07T08:00:00.000Z",
  "eventId": "uuid",
  "level": "error",
  "event": "integration.microsoft_365.sync_failed",
  "organizationRef": "hashed-reference",
  "resourceRef": "hashed-reference",
  "metadata": {
    "failureCode": "SYNC_FAILED"
  },
  "error": {
    "name": "Error"
  }
}
```

Organization/resource identifiers are hashed before logging.

## Redaction policy

Metadata keys matching secret-bearing concepts are replaced with `[REDACTED]`, including:

- authorization
- cookie
- token
- secret
- password
- credential
- client secret
- access token
- refresh token
- ID token

Nested objects and arrays are sanitized recursively.

Operational error summaries intentionally do **not** include:

- `error.message`
- stack traces
- provider response bodies
- Graph payloads
- access/refresh tokens

Provider errors may expose only the error class name and a numeric HTTP status when present.

## Instrumented failures

Current structured events include:

- database health unavailable;
- Microsoft 365 inventory sync failure;
- scanner connection/tenant verification failure;
- remediation consent/capability verification failure;
- automated remediation execution failure;
- post-remediation verification sync failure.

Audit events remain a separate business/security history. Operational logs do not replace audit records.

## Zero-cost development collection

The default development collector is self-hosted:

```text
CyberPilot stdout/stderr
→ local log file
→ Grafana Alloy
→ Loki
→ Grafana
```

Start it with `pnpm dev:stack` and run the application with `pnpm dev:observed`.

See `docs/local-development.md`.

No managed logging vendor is required to implement or validate CyberPilot functionality.

## Optional managed collection

A managed host such as Render can later provide infrastructure logs and notifications. External log streaming can be added when retention, cross-service correlation, alerting or compliance requirements justify it.

See `docs/observability-render.md` for the optional Render path.

## Production collector requirements

Before broader production deployment, define:

- log transport;
- retention period;
- access control;
- alert destinations;
- severity thresholds;
- incident ownership;
- regional/data-residency requirements;
- deletion policy.

At minimum, alerts should exist for:

- repeated health/database failures;
- sustained Microsoft sync failures;
- remediation failures;
- unexpected spikes in HTTP 5xx;
- authentication anomalies from the auth platform/proxy.

## Data minimization

Do not add raw user email addresses, tenant names, tenant IDs, Graph response bodies or security tokens to operational logs merely for debugging convenience.

When additional correlation is required, prefer hashed stable references and explicit failure codes.
