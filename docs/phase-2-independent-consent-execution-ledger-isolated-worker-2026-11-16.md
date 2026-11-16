# CyberPilot Exposure — independent consent, execution ledger and isolated socket transport

Date: 2026-11-16. PR #220. Phase 2 / issue #84.

## Three independent functional blocks

1. **Consent verification (C1):** detached canonical Ed25519 grant
   verification with tenant, domain, actor, source, time and scope
   restrictions, trusted operator keyring interface, an independently
   authenticated revocation provider contract and fail-closed reports.
   The product route never accepts public trust keys or revocation
   records, and the built-in authority returns no trusted keys.
   Signature verification does not sign customer consent.

2. **Durable lease and quota accounting (C2):** separate PostgreSQL
   `ExposureExecutionLease` and `ExposureExecutionCharge` models,
   bounded per-source counts, idempotent request IDs, CAS revision
   checks, SERIALIZABLE issuance/consumption, terminal settlement,
   organization-scoped history and reviewer-only read UI.
   No public route calls `issueWithAuthority`,
   `consumeWithAuthority`, `settleWithAuthority` or
   `closeWithAuthority`.

3. **Node-level isolated transport and internal coordinator (C3):**
   DNS TXT apex, TXT _dmarc, MX and IPv4 A pinning, TLS 443 handshake
   using independently verified certificate + SNI, and HTTPS HEAD
   only. The worker exposes no default instance and requires all:
   an explicit operator gate; worker isolation; a trusted backend
   consent/quota adapter; an unexpired per-tenant executable lease;
   `CYBERPILOT_PASSIVE_LIVE_ENABLED=true`; LAB auth disabled.
   Every DNS query and socket action must first call an independent
   authorization callback and consume a durable reservation.
   No redirects, cookies, authentication, response bodies, arbitrary
   paths, active scanning or other ports.

## Exact network cost

- DNS passive source: three queries (TXT apex, TXT _dmarc, MX).
- TLS: two IPv4 A re-resolution queries (before and after socket)
  plus one TLS 443 connection.
- HTTPS headers: two IPv4 A queries plus one HEAD.
- All three sources: **7 DNS calls + 1 TLS + 1 HEAD = 9**
  accounted network operations. Default caps remain 8 DNS, 1 TLS,
  1 HEAD and 10 total. No IPv6 probing until an independent quota
  and policy expansion. Source failures remain UNKNOWN.
- A successful socket connection is **not** a verified security
  control, customer certification or proof of risk reduction.

## Safety and deployment status

This PR **does not** include a configured independent legal
consent authority or an authenticated remote withdrawal service;
the default adapter always denies. No customer approval or tenant
credential exists here. No autonomous scheduled worker has been
deployed. No production LIVE collection has been performed or
authorized. Tests use signed synthetic grants and fail-closed
worker gates without contacting third parties.

Deployment of a real passive run requires a separately operated
authority with verified legal approval, key rotation, signed
withdrawal state, secured worker identity and egress isolation.
Operators must independently audit the consent source, the worker
network namespace, exact domain scope, time windows, rate limits
and per-operation PostgreSQL transactions before enabling it.
A customer-supplied DNS token never permits arbitrary external
traffic.

## Required acceptance

- TypeScript and Prisma generation/migrations.
- PostgreSQL integration on denied, idempotent tenant isolation.
- Cryptographic test fixtures with real Ed25519 signatures.
- Transport rejection tests with zero socket attempts.
- Regression checks for conservative DNS quota accounting.
- Security, full CI, local stack E2E, LAB Chromium, PostgreSQL
  backup/restore and development acceptance on exact final HEAD.
- Keep the PR Draft until every required workflow succeeds.
- Keep issue #84 open until genuine independent consent and real
  LIVE customer acceptance are demonstrated without bypassing
  any safeguards.

No score, historical evidence, external account or tenant
is mutated by these development features.
