# Microsoft 365 Lab Mode

Microsoft 365 Lab Mode lets CyberPilot exercise its security workflow without a Microsoft tenant, Azure subscription, payment card, or external Microsoft API calls.

It is intended for local development, demos, automated validation, and product iteration.

## Safety boundary

Lab Mode is explicit.

An integration has one of two modes:

```text
LIVE
LAB
```

The workspace displays a visible **Microsoft 365 Lab Mode** banner when synthetic evidence is active.

Lab Mode never:

- requests Microsoft admin consent;
- acquires Microsoft Graph tokens;
- calls Microsoft Graph;
- changes a real tenant;
- uses Microsoft remediation credentials.

The lab executor only mutates synthetic objects stored in CyberPilot's own database.

## Deterministic scenario

Activating or resetting the lab creates a reproducible Microsoft 365-shaped environment containing:

- six active identities;
- five Global Administrator role assignments;
- one guest Global Administrator;
- one non-Global administrator that is explicitly not MFA-capable;
- one initial `.onmicrosoft.com` domain;
- one custom domain with SPF present;
- DMARC in monitoring mode (`p=none`);
- one of the two Microsoft 365 DKIM selector signals missing.

The initial scenario is designed to produce evidence for:

- `M365_GLOBAL_ADMIN_COUNT_HIGH`;
- `M365_GUEST_GLOBAL_ADMIN`;
- `M365_ADMIN_MFA_NOT_CAPABLE`;
- `DOMAIN_DMARC_MONITORING_ONLY`;
- `DOMAIN_M365_DKIM_SELECTORS_PARTIAL`.

The guest Global Administrator finding includes the exact synthetic role-assignment ID, so the normal automated remediation playbook can be exercised safely.

## Workflow

A developer can run:

```text
Start Microsoft 365 Lab
  ↓
Re-evaluate lab
  ↓
Review findings
  ↓
Review CyberScore
  ↓
Approve guest Global Admin remediation
  ↓
Execute approved remediation
  ↓
Verify exact synthetic role assignment was deleted
  ↓
Re-evaluate findings
  ↓
Observe finding resolution and score history
```

The same Risk Engine, finding persistence, CyberScore, remediation proposal, approval, verification, and audit paths are used by LIVE and LAB modes.

Only evidence acquisition and write execution differ.

## Reset behavior

**Reset lab scenario** restores the deterministic initial state.

Resetting removes the lab integration's:

- directory identities;
- role definitions;
- role assignments;
- domains;
- findings and their remediation attempts;
- posture-score snapshots.

It then recreates the baseline scenario and performs a fresh evaluation.

This destructive reset is limited to the current organization's LAB integration.

## Switching to LIVE

If a user later connects a real Microsoft 365 tenant, CyberPilot:

1. verifies the real tenant through the normal Microsoft Graph connection flow;
2. removes synthetic LAB inventory, findings, remediation attempts, and score history;
3. changes the integration mode to `LIVE`;
4. waits for fresh evidence from the real tenant.

This prevents synthetic posture history from being presented as real Microsoft 365 evidence.

## Database setup

Lab Mode adds the `IntegrationMode` enum and the `Integration.mode` field.

Until CyberPilot has a formal migration deployment pipeline, local development databases must be updated with the project's Prisma schema workflow before Lab Mode can be used.

Production deployment should use versioned Prisma migrations rather than an ad-hoc schema push.
