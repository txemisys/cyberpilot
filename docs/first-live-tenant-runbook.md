# First LIVE Microsoft 365 tenant runbook

This runbook is for CyberPilot's first controlled real-tenant validation.

The goal is to prove the **read-only scanner** against a real Microsoft 365 tenant before enabling any Microsoft write capability.

## Safety boundary

For the first LIVE tenant:

- use a dedicated scanner Entra application;
- do not reuse the CyberPilot login application;
- leave every `M365_REMEDIATION_*` variable empty;
- do not grant `RoleManagement.ReadWrite.Directory`;
- do not enable any automated Microsoft remediation;
- run the read-only readiness probe before the first full inventory sync.

CyberPilot's first LIVE test must be observational only.

## Required customer/admin access

The person completing Microsoft consent must be able to grant tenant-wide admin consent for the scanner application's application permissions.

The CyberPilot user initiating the flow must be an organization `OWNER` or `ADMIN`.

## Scanner application permissions

Configure exactly these Microsoft Graph **application** permissions:

- `Organization.Read.All`
- `User.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`

Do not add `Directory.Read.All` merely for convenience.

Do not add any write permission.

## CyberPilot server configuration

Set these server-side values:

```text
M365_GRAPH_CLIENT_ID
M365_GRAPH_CLIENT_SECRET
M365_GRAPH_REDIRECT_URI
```

The redirect URI must exactly match the callback configured in the scanner Entra application.

For a production/public environment use HTTPS.

Never commit real IDs/secrets to the repository.

## First connection procedure

1. Confirm CyberPilot shows **LIVE connection preflight → Scanner server configuration: READY**.
2. Confirm the remediation executor shows **NOT CONFIGURED**.
3. Select **Connect Microsoft 365 read-only**.
4. Sign in with the controlled tenant administrator and review Microsoft admin consent.
5. Grant consent only if the permission list matches the four documented read-only application permissions.
6. CyberPilot verifies the tenant ID using Microsoft Graph before persisting the LIVE connection.
7. Do **not** run automated remediation consent.
8. Run **Test read-only Microsoft access**.
9. Require all five probe areas to report healthy access before treating coverage as complete:
   - organization;
   - users;
   - directory role definitions;
   - directory role assignments;
   - authentication registration.
10. If authentication registration returns `PERMISSION_REQUIRED`, verify that `AuditLog.Read.All` received admin consent.
11. If any other scope returns `PERMISSION_REQUIRED`, verify the corresponding scanner permission rather than adding broad permissions.
12. Only after the probe is satisfactory, run **Sync Microsoft 365**.

## Evidence validation after first sync

Compare CyberPilot with the tenant for:

- tenant display name and tenant ID;
- verified domains;
- active user count;
- guest identities;
- Global Administrator membership;
- administrator MFA capability evidence;
- SPF, DMARC and Microsoft 365 DKIM observations.

Record discrepancies as product defects. Do not manually "correct" CyberPilot database evidence to make the comparison pass.

## Success criteria

The first LIVE read-only validation is successful when:

- consent is tenant-scoped and auditable;
- the scanner uses no Microsoft write permission;
- the readiness probe has no unexpected errors;
- the full sync completes;
- normalized evidence matches the controlled tenant closely enough to explain every generated finding;
- CyberScore coverage accurately reflects any unavailable evidence;
- the remediation executor remains unconfigured.

## What comes after

Only after read-only LIVE behavior is independently validated should CyberPilot test the separate remediation application.

That must be a distinct milestone, with separate admin consent, explicit human approval, exact evidence matching and a controlled test tenant.
