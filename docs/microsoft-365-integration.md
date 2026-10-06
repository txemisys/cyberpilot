# Microsoft 365 security integration

CyberPilot uses two separate Microsoft Entra application concerns.

## 1. CyberPilot sign-in

The application sign-in integration authenticates users who access CyberPilot.

It must not be used as the background security scanner.

Environment variables:

```text
MICROSOFT_CLIENT_ID
MICROSOFT_CLIENT_SECRET
```

## 2. Microsoft 365 security scanner

The scanner is a separate multi-tenant Entra application intended for app-only Microsoft Graph access after a customer administrator grants tenant-wide consent.

Environment variables:

```text
M365_GRAPH_CLIENT_ID
M365_GRAPH_CLIENT_SECRET
M365_GRAPH_REDIRECT_URI
```

The scanner obtains access tokens with the OAuth 2.0 client credentials flow using:

```text
scope=https://graph.microsoft.com/.default
```

No user refresh token is required for this background scanning model.

## Initial application permissions

The first inventory slice should request only:

- `Organization.Read.All`
- `User.Read.All`
- `RoleManagement.Read.Directory`
- `AuditLog.Read.All`

These permissions support organization, user, role-definition, role-assignment, and authentication-registration inventory. `AuditLog.Read.All` is required for Microsoft Graph's `userRegistrationDetails` report.

Broader permissions such as `Directory.Read.All` should not be requested merely for convenience when narrower permissions are sufficient.

## Initial data collected

CyberPilot initially normalizes:

- Microsoft tenant ID;
- tenant display name;
- verified domains;
- directory users;
- account enabled state;
- user type;
- directory role definitions;
- directory role assignments.

The first implementation intentionally excludes mailbox contents, files, Teams content, and other customer data that is not required for the security outcome.

## Consent flow

The customer administrator will be redirected to Microsoft's admin-consent endpoint.

The callback must:

1. validate a cryptographically protected state value;
2. require an authenticated CyberPilot user;
3. require sufficient CyberPilot organization privileges;
4. validate the returned tenant ID;
5. obtain an app-only Graph token;
6. call Microsoft Graph to verify the tenant;
7. persist the tenant connection;
8. create an audit event.

A tenant ID received from the callback must never be trusted without verification.

## Security constraints

- Never log access tokens or client secrets.
- Never expose scanner credentials to browser JavaScript.
- Keep the Graph base URL fixed.
- Validate tenant IDs before constructing Microsoft identity URLs.
- Use explicit Graph fields with `$select`.
- Persist normalized evidence rather than unnecessary raw directory payloads.
- Treat integration errors as tenant-scoped data.

## First evidence-backed findings

The first scanner rules intentionally use only evidence available through the initial least-privilege permission set.

### M365_GLOBAL_ADMIN_COUNT_HIGH

CyberPilot opens a high-severity finding when five or more active user identities hold the Global Administrator role.

The rule follows Microsoft's current Microsoft Entra role guidance to keep the number of Global Administrators below five.

### M365_GUEST_GLOBAL_ADMIN

CyberPilot opens a critical finding for each active guest identity that holds the Global Administrator role.

Microsoft guidance for increased tenant security states that guests should not be assigned highly privileged directory roles.

### Finding lifecycle

Findings use stable organization-scoped keys.

On each successful synchronization:

- currently observed risks are opened or refreshed;
- evidence and `lastSeenAt` are updated;
- findings from these rules that are no longer observed are marked `RESOLVED`;
- failed scans do not automatically resolve findings.

This prevents a temporary Microsoft Graph failure from being interpreted as remediation.

## MFA evidence

CyberPilot reads:

```text
GET /reports/authenticationMethods/userRegistrationDetails
```

The scanner stores only normalized posture required for security decisions:

- whether Microsoft classifies the identity as an administrator;
- `isMfaRegistered`;
- `isMfaCapable`;
- `isPasswordlessCapable`;
- registered authentication-method names;
- Microsoft report update timestamp;
- CyberPilot observation timestamp.

CyberPilot does not interpret a missing registration record as "MFA disabled".

The MFA findings require Microsoft to return an explicit `isMfaCapable = false`.

### M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE

A critical finding is opened when an active Global Administrator explicitly has `isMfaCapable = false`.

### M365_ADMIN_MFA_NOT_CAPABLE

A high finding is opened when another active administrator explicitly has `isMfaCapable = false`.

`isMfaCapable` is preferred over `isMfaRegistered` for this finding because Microsoft defines MFA capability as having a strong authentication method that is currently allowed by the authentication-methods policy. A registered method alone might no longer be allowed.

CyberPilot does not currently label `isPasswordlessCapable` as "phishing-resistant MFA". That property is useful evidence, but it is not by itself a direct proof that a tenant enforces phishing-resistant authentication for administrator sign-ins.

## Permission expansion and re-consent

Adding `AuditLog.Read.All` to the scanner application's configured Microsoft Graph application permissions requires administrator consent.

Existing customer tenants must grant the expanded consent before MFA evidence can be synchronized.


## Separate remediation application

CyberPilot does not grant write permissions to the read-only Microsoft 365 scanner.

Automated Microsoft 365 remediation uses a separate Entra application and separate client credentials.

The first remediation action removes one exact Microsoft Entra directory-role assignment after explicit CyberPilot approval. Microsoft Graph requires `RoleManagement.ReadWrite.Directory` for this operation.

Because that permission can manage directory RBAC, CyberPilot treats it as a distinct high-impact trust boundary rather than adding it to the scanning application.


## LIVE read-only readiness check

Before relying on a connected tenant, an organization owner or administrator can run **Test read-only Microsoft access**.

The probe uses only Microsoft Graph `GET` requests and tests these evidence scopes independently:

| Evidence | Probe | Required application permission |
| --- | --- | --- |
| Tenant identity | `GET /organization` | `Organization.Read.All` |
| Users | `GET /users?...&$top=1` | `User.Read.All` |
| Entra role definitions | `GET /roleManagement/directory/roleDefinitions?...&$top=1` | `RoleManagement.Read.Directory` |
| Entra role assignments | `GET /roleManagement/directory/roleAssignments?...&$top=1` | `RoleManagement.Read.Directory` |
| Authentication registration | filtered `GET /reports/authenticationMethods/userRegistrationDetails` | `AuditLog.Read.All` |

The probe never calls the remediation executor and never sends POST, PATCH, PUT, or DELETE requests to Microsoft Graph.

A `403` is recorded as `PERMISSION_REQUIRED`; other failures are recorded as `ERROR`. CyberPilot stores only the resulting capability status and audit metadata, not access tokens or raw Graph responses.

### Production configuration expectations

- Scanner and remediation are separate Entra applications.
- Scanner credentials are server-only and must not be exposed to browser JavaScript.
- `LAB_AUTH_ENABLED` must remain disabled in production.
- Public application and consent callback URLs should use HTTPS.
- Secrets must come from the deployment secret manager rather than source control.
- Do not configure the remediation app merely to make read-only scanning work.
