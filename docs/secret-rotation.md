# Production secret rotation

This runbook defines CyberPilot's provider-neutral secret-rotation process. It does not require a specific cloud host or secret manager.

It is deliberately operational rather than vendor-specific: the exact UI/API used to rotate a value depends on the production platform selected later.

## Scope

The production secret inventory includes:

- `AUTH_SECRET`;
- Microsoft login application client secret;
- Microsoft 365 read-only scanner application client secret;
- `DATABASE_URL` or the database credential embedded in it;
- any deployment/runtime secret used by the selected hosting platform;
- post-pilot remediation credentials only if LIVE remediation is intentionally enabled later.

For the first customer pilot, all `M365_REMEDIATION_*` values remain unset and are therefore outside the active rotation set.

## Principles

1. Never paste current or replacement values into Git, issues, chat, screenshots, audit metadata or application logs.
2. Prefer an overlap rotation when the provider supports two valid credentials at once: create the replacement, deploy it, validate it, then revoke the old credential.
3. If overlap is unavailable, schedule a controlled maintenance window and prepare rollback before revocation.
4. Treat every rotation as incomplete until the application health check and the affected authentication/integration path have been exercised.
5. Record only secret names, timestamps, owner, outcome and safe identifiers in the operational change record.

## Required ownership

Before production launch, assign a named operational owner and backup owner for secret rotation.

| Secret group | Primary owner | Backup owner | Validation path |
| --- | --- | --- | --- |
| Application auth secret | Assign before production | Assign before production | Sign-in/session smoke test |
| Microsoft login app secret | Assign before production | Assign before production | Microsoft sign-in |
| Microsoft scanner app secret | Assign before production | Assign before production | Read-only probe + LIVE sync |
| Database credential | Assign before production | Assign before production | `/api/health` + migration status |
| Remediation executor | Post-pilot only | Post-pilot only | Isolated remediation capability probe |

Do not mark the production secret-rotation blocker complete until these owners exist.

## Rotation triggers

Rotate a credential when any of the following occurs:

- suspected or confirmed exposure;
- a team member with access leaves or changes responsibilities;
- the provider reports credential compromise;
- the credential approaches its provider-defined expiry;
- a production-environment migration changes the trust boundary;
- the organization reaches its chosen periodic rotation interval.

A suspected compromise is an incident, not a routine maintenance task. Revoke or disable the exposed credential as soon as safely possible and follow the incident process.

## Standard overlap procedure

Use this sequence where the provider supports overlapping credentials:

1. Create a replacement credential in the provider/secret manager.
2. Store the replacement in the production secret boundary without exposing it in logs or shell history.
3. Deploy/restart the application with the replacement configured.
4. Run `pnpm db:migrate:status` if the database credential changed.
5. Verify `GET /api/health`.
6. Exercise the affected path:
   - auth secret: sign-in and authenticated organization access;
   - Microsoft login secret: Microsoft sign-in/callback;
   - scanner secret: read-only Microsoft probe, then a controlled read-only sync;
   - database credential: health endpoint plus a DB-backed application page.
7. Confirm no unexpected authentication, Graph or database errors in redacted operational logs.
8. Revoke the old credential.
9. Repeat the health/affected-path checks after revocation.
10. Record completion using only safe metadata: secret name, owner, time, deployment revision, result and rollback status.

## Non-overlap procedure

If the provider permits only one active credential:

1. Prepare the replacement and rollback instructions before changing production.
2. Announce a maintenance window if user impact is possible.
3. Stop or drain traffic if required by the selected runtime.
4. Replace the credential in the provider and production secret boundary.
5. Restart/redeploy.
6. Run the validation path for that credential.
7. If validation fails, execute the prepared rollback immediately.
8. Restore normal traffic only after validation succeeds.

## Rollback

A rotation must have a rollback path before the old credential is destroyed.

Where overlap is available, rollback means restoring the prior runtime configuration while the old credential is still valid.

Where overlap is not available, rollback may require issuing another credential. Document that provider-specific limitation before production use.

Do not retain obsolete credentials merely for convenience after a successful rotation.

## AUTH_SECRET considerations

Treat rotating `AUTH_SECRET` as potentially session-impacting. Validate behavior in staging before the first production rotation and plan for users to re-authenticate if necessary.

Do not claim zero-session-impact until the deployed Better Auth configuration has been exercised under rotation.

## Microsoft credentials

The login application and the read-only scanner application are separate trust boundaries and must be rotated independently.

For the scanner credential, the required post-rotation validation is:

1. static first-pilot configuration check;
2. Microsoft read-only access probe;
3. one controlled read-only sync;
4. verification that only the documented four read-only Graph application roles remain granted.

Do not introduce remediation credentials while rotating scanner credentials for the first pilot.

## Database credentials

After database credential rotation:

1. verify the application can connect via `/api/health`;
2. run `pnpm db:migrate:status`;
3. exercise one DB-backed authenticated request;
4. verify backup tooling can still authenticate before the next planned backup window.

Never use `db:push` as part of a production credential rotation.

## Emergency revocation

For suspected exposure:

1. identify the affected trust boundary;
2. create a replacement if possible;
3. revoke/disable the exposed credential;
4. deploy the replacement;
5. validate the affected path;
6. review operational logs and audit events for suspicious use;
7. rotate adjacent credentials only when there is evidence or a credible shared exposure path;
8. document the incident without copying secret values.

## Drill before production

Before CyberPilot is described as production-hardened, perform one non-emergency rotation drill in a staging-like environment for:

- an application/runtime secret;
- the Microsoft scanner credential;
- the database credential or an equivalent isolated database credential.

The drill should prove that the team can rotate, validate and roll back without exposing secret values.

## Completion criteria

The production secret-rotation blocker is complete only when:

- primary and backup owners are assigned;
- the production secret manager / protected environment has been selected;
- the provider-specific steps are appended to this runbook or linked from it;
- at least one staging-like drill has been completed successfully;
- the drill record contains no secret values.
