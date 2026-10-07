# Rate limiting and sensitive-route protection

CyberPilot uses separate rate-limit layers for authentication traffic and authenticated product actions.

## Authentication endpoints

Better Auth provides client-request rate limiting in production. CyberPilot currently relies on that authentication-layer protection for `/api/auth/*`.

Before horizontally scaling authentication traffic, configure Better Auth with explicitly shared rate-limit storage and validate trusted proxy/IP handling.

## CyberPilot sensitive actions

High-impact authenticated product routes use a PostgreSQL-backed fixed-window limiter.

The rate-limit subject stored by CyberPilot is a SHA-256 hash of:

```text
organizationId:userId
```

Raw client IP addresses are not persisted by this limiter.

Current limits:

| Action | Limit |
| --- | ---: |
| Start scanner admin consent | 4 / 5 min |
| Start remediation admin consent | 3 / 5 min |
| Run read-only Microsoft probe | 6 / 5 min |
| Run Microsoft 365 sync | 4 / 5 min |
| Activate/reset Microsoft 365 Lab | 4 / 5 min |
| Approve remediation | 10 / 1 min |
| Execute automated remediation | 3 / 5 min |

Limits run only after authentication, organization membership lookup and OWNER/ADMIN authorization.

Rejected requests return HTTP 429 with `Retry-After` and `Cache-Control: no-store`.

## Storage and concurrency

Rate-limit counters are stored in `RequestRateLimit` with a unique key over:

- scope;
- hashed subject;
- fixed window start.

Each request uses an atomic Prisma upsert that increments the active bucket.

Expired buckets are opportunistically removed.

## Boundaries

This is application-level abuse protection, not volumetric DDoS protection.

Production hosting should still provide reverse-proxy/CDN/network protections, connection limits and attack mitigation.

Initial thresholds are defensive defaults and should be tuned from pilot telemetry without weakening remediation safeguards.
