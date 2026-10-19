# Microsoft 365 LIVE simulation

CyberPilot can exercise the normal LIVE Microsoft 365 synchronization path without owning a Microsoft tenant.

This is different from Lab Mode:

- Lab Mode seeds CyberPilot's database directly with synthetic normalized evidence.
- LIVE simulation executes the normal `MicrosoftGraphClient` and `syncMicrosoft365Integration` code paths.
- Network calls are replaced only inside automated tests with Microsoft-shaped OAuth and Graph responses.
- The integration itself is stored as `mode = LIVE`, so normalization, persistence, findings and CyberScore use the same path as a real tenant.

## What the simulation covers

The automated LIVE simulation validates:

- app-only token handling;
- Microsoft Graph collection shapes;
- tenant-ID verification;
- user normalization;
- Member/Guest mapping;
- Entra role definitions and assignments;
- authentication-registration/MFA evidence;
- least-privilege read-only application-role assumptions;
- persistence into PostgreSQL;
- evidence-backed findings;
- CyberScore snapshots;
- partial coverage when authentication-registration evidence returns HTTP 403.

The simulation deliberately uses no real Microsoft account, tenant, subscription or API.

## What it cannot prove

Only a real tenant can finally prove:

- Microsoft admin-consent UX;
- actual Entra service-principal permission assignment;
- real token issuance behavior for the registered scanner app;
- tenant-specific Graph licensing/availability differences;
- callback behavior through the public HTTPS endpoint;
- correctness against real customer directory evidence.

Therefore LIVE simulation reduces the real-tenant validation to a final compatibility/evidence check; it does not replace that final check.

## Running

The test is part of the normal web test suite:

```bash
pnpm test
```

With PostgreSQL available and migrations applied, the LIVE simulation runs automatically as `microsoft-365-live-sim.e2e.test.ts`.


## Resilience scenarios

The simulation also exercises transport and reconciliation behavior that commonly differs in real tenants:

- paginated Graph collections through `@odata.nextLink`;
- rejection of off-origin pagination URLs;
- bounded retry of HTTP 429 responses while honoring `Retry-After`;
- bounded retry of transient 5xx responses;
- rejection of unexpected application permissions in the Graph token;
- reconciliation between consecutive LIVE syncs, including removal of stale identities and role assignments.

Retries are intentionally bounded so a degraded Microsoft service cannot hold a CyberPilot request indefinitely.


## Tenant isolation and sync concurrency

Every Microsoft 365 sync is scoped to a single persisted integration. Inventory reconciliation uses `integrationId`, while findings and scores remain scoped to the owning organization.

CyberPilot also uses a PostgreSQL-backed sync lease per integration:

- only one sync may mutate a given integration at a time;
- a concurrent request receives a conflict rather than interleaving writes;
- the lease is released in a `finally` block on success or failure;
- an abandoned lease expires after 30 minutes and can be replaced;
- separate organizations/integrations can still sync independently.

Automated tests verify cross-organization evidence is not changed by another tenant's sync and that repeated identical LIVE syncs do not duplicate inventory/findings.


## Payload and resource guards

The Graph boundary validates response shape before data reaches persistence. CyberPilot rejects malformed collection envelopes and invalid required fields for organizations, users, role definitions, role assignments and authentication-registration evidence.

Operational limits are also enforced:

- 10 second timeout for Microsoft OAuth token acquisition;
- 15 second timeout per Graph request;
- 2 minute cumulative deadline per paginated Graph collection, shared across token acquisition, requests and retries;
- 5 MiB maximum response body;
- 100 pages maximum per collection;
- 100,000 items maximum per collection.

These are defensive application limits rather than claims about Microsoft service limits. They exist to fail closed when an upstream response is malformed, unexpectedly large or non-terminating.


## Persisted failure state

LIVE sync failures persist only a safe classification on the integration, never the upstream response body or exception message.

Current failure codes are:

- `GRAPH_AUTHORIZATION_FAILED`
- `GRAPH_PAYLOAD_INVALID`
- `GRAPH_THROTTLED`
- `GRAPH_UNAVAILABLE`
- `TENANT_MISMATCH`
- `SYNC_FAILED`

`lastErrorAt` and `lastErrorCode` are written by the sync engine itself, so failures are recorded consistently even outside the HTTP route. A later successful atomic sync clears both values.


## Bulk snapshot publication

LIVE directory inventory is now published as a complete transactional snapshot instead of row-by-row upserts:

- current role assignments, role definitions and identities are removed inside the transaction;
- the new snapshot is inserted with bulk `createMany` operations;
- findings and CyberScore are calculated before commit;
- if any bulk write or evaluation fails, the entire transaction rolls back.

This keeps atomic publication while reducing database round-trips from O(number of directory objects) to a small constant number of bulk statements. Domains remain individually upserted because their count is small and organization-level uniqueness has different semantics.

The tenant-free E2E suite exercises a 2,500-user LIVE snapshot twice and verifies inventory remains duplicate-free.


## Lease heartbeat

The per-integration sync lease is renewed periodically while a synchronization is running. Production leases remain valid for 30 minutes and are refreshed every 5 minutes. This prevents a legitimately long Graph/DNS collection phase from expiring the lease and allowing a second sync to overlap.

The heartbeat is token-bound: only the process that acquired the lease can renew or release it. The sync also performs a final renewal/health check before returning.

## LAB / LIVE route separation

The shared sync endpoint now branches on integration mode before applying first-pilot LIVE gates. A connected LAB integration can be re-evaluated without Microsoft scanner credentials or a READY Graph probe. LIVE integrations still require the static first-pilot configuration gate and the latest successful read-only probe.


## Lease fencing

Lease renewal is also used as a fencing check immediately before atomic publication. If the original sync no longer owns the token-bound lease, CyberPilot raises `SYNC_LEASE_LOST` and refuses to publish the collected snapshot.

This closes the stale-worker race where a paused process resumes after another process has taken over an expired lease. The stale process cannot overwrite the newer owner's work, and its token-scoped cleanup cannot delete the replacement lease.
