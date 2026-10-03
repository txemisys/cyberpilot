# Remediation architecture

CyberPilot's Fix workflow turns a supported security finding into a versioned remediation playbook.

The core lifecycle is:

```text
Finding
  ↓
Proposed remediation
  ↓
Explicit approval
  ↓
Execution or guided action
  ↓
Verification
  ↓
Audit evidence
```

## Safety principles

Remediation follows these rules:

- read-only scanning and write-capable remediation use separate Microsoft Entra applications;
- automated actions require explicit approval;
- approval and execution are separate state transitions;
- automation acts on exact provider object identifiers captured as evidence;
- the executor re-reads the target before changing it;
- provider evidence must still match the approved action;
- execution is verified after the write;
- every approval, success, failure, and verification is audit logged;
- missing exact evidence degrades an automated playbook to guided mode.

## Modes

### Guided

CyberPilot supplies:

- a concrete remediation goal;
- ordered steps;
- verification steps;
- the related finding and severity.

The administrator performs the change outside CyberPilot and then re-runs a security synchronization so the finding can be re-evaluated from fresh evidence.

### Automated

Automated playbooks include a narrowly scoped action type and provider-object evidence.

The first automated action is:

```text
M365_DELETE_DIRECTORY_ROLE_ASSIGNMENT
```

It is used only for the `M365_GUEST_GLOBAL_ADMIN` finding.

CyberPilot captures:

- guest principal ID;
- exact unified role-assignment ID;
- expected role-definition ID.

Before deletion the executor fetches that exact role assignment from Microsoft Graph and verifies the principal and role definition still match the approved evidence.

After deletion, CyberPilot fetches the same role assignment again and requires it to be absent before marking the remediation verified.

## Microsoft permission boundary

The security scanner remains read-only.

The remediation executor uses a separate Entra application configured through:

```text
M365_REMEDIATION_CLIENT_ID
M365_REMEDIATION_CLIENT_SECRET
```

The first automated action requires the Microsoft Graph application permission:

```text
RoleManagement.ReadWrite.Directory
```

Administrator consent is required.

Microsoft documents this permission as allowing an application to manage directory RBAC, including role membership. Because this is a high-impact permission, it must not be added to the read-only scanner application merely for convenience.

## Failure behavior

A failed automated action does not resolve the finding.

The remediation stores a stable failure code and audit event.

Examples include:

- evidence mismatch;
- provider permission failure;
- provider API failure;
- verification failure.

A subsequent security sync can generate another remediation attempt when appropriate while preserving prior attempts as historical evidence.

## Current playbooks

CyberPilot currently defines playbooks for:

- reducing excessive Global Administrator assignments;
- removing a guest Global Administrator assignment;
- making privileged administrators MFA-capable;
- publishing or correcting DMARC;
- moving DMARC toward enforcement;
- publishing or consolidating SPF;
- publishing or completing Microsoft 365 DKIM selector DNS.

Only the guest Global Administrator role-assignment removal is currently marked as automation-capable. The others remain guided until CyberPilot has a safe provider-specific write path and verification strategy.
