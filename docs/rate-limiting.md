# Rate limiting and sensitive-route protection

CyberPilot uses separate rate-limit layers for authentication traffic and authenticated product actions.

## Auth endpoints

Better Auth provides its own client-request rate limiting in production.

At this stage CyberPilot does not override Better Auth's default rate-limit storage. That means auth rate-limit state may be process-local depending on deployment topology.

Before horizontally scaling authentication traffic, move Better Auth rate limiting to an explicitly shared database/secondary/custom storage and validate proxy IP handling.

## CyberPilot sensitive actions

High-impact authenticated product routes use a PostgreSQL-backed fixed-window limiter.

The rate-limit subject is a SHA-256 hash of:

```text
organizationId:userId
```

CyberPilot does not persist a raw IP address for these limits.

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

Limits are applied only after authentication, organization membership lookup and OWNER/ADMIN authorization, so unauthenticated requests cannot create arbitrary database buckets.

A rejected request returns HTTP 429 and a `Retry-After` header.

## Storage

Rate-limit counters live in `RequestRateLimit` and use a unique key across:

- scope
- hashed subject
- fixed window start

The increment is performed atomically with a Prisma upsert.

Expired rows are opportunistically cleaned when limits are consumed.

## What this does not solve

This is not a general DDoS protection layer.

Infrastructure-level protections are still expected from the hosting/reverse-proxy/CDN layer, including connection limits and volumetric attack mitigation.

Rate-limit values are initial defensive defaults and should be tuned from real pilot telemetry rather than weakened reactively.
