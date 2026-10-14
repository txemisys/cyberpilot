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
