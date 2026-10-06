# First customer pilot

This is the commercial/operational definition of the first CyberPilot customer pilot.

The pilot is intentionally read-only.

## Customer promise

CyberPilot will:

- connect to one controlled Microsoft 365 tenant;
- collect only the evidence needed for the supported controls;
- identify and prioritize evidence-backed risks;
- explain the top actions;
- generate an executive security report;
- make no Microsoft 365 write changes during the first pilot.

## Customer prerequisites

The customer provides:

- a Microsoft 365 / Entra tenant;
- a tenant administrator able to grant the documented read-only application permissions;
- a CyberPilot organization owner/admin;
- a technical contact who can compare CyberPilot evidence with the tenant;
- permission to perform a read-only security assessment.

## Read-only permissions

The scanner requests only:

- `Organization.Read.All`
- `User.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`

The remediation executor is not part of the first pilot.

## Pilot sequence

```text
Create workspace
→ configure scanner
→ tenant admin consent
→ read-only readiness probe
→ first evidence sync
→ review findings with customer
→ generate executive report
→ agree remediation plan
```

## Pilot success criteria

The pilot is successful when:

- the tenant connection is verified;
- all expected read-only evidence scopes are available or any missing scope is explicitly reported;
- the first LIVE sync completes;
- CyberPilot findings are traceable to tenant evidence;
- CyberScore coverage accurately reflects evidence availability;
- the customer can identify the top actions without reading raw Graph data;
- the executive report can be shared with management;
- no write permission was required.

## Customer-facing boundaries

Do not claim that CyberPilot:

- certifies the organization;
- proves compliance;
- guarantees security;
- predicts breaches;
- validates controls that CyberPilot does not currently implement.

## After the pilot

Only after the read-only pilot is accepted should a customer optionally evaluate the separate remediation application.

That later phase requires separate Microsoft admin consent and explicit CyberPilot administrator approval for every supported high-impact action.
