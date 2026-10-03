# CyberPilot Architecture

## Current stage

CyberPilot is in the foundation stage. This document describes the initial architecture and the constraints that should guide implementation.

## Architectural goals

1. Strong tenant isolation.
2. Least-privilege integrations.
3. Explainable security findings.
4. Complete auditability of security-sensitive actions.
5. Minimal collection of customer data.
6. Simple infrastructure until scale requires additional complexity.

## Initial components

### Web application

The Next.js application is the initial user-facing surface and API boundary.

### PostgreSQL

PostgreSQL is the system of record for organizations, memberships, integrations, findings, evidence, remediations, and audit events.

### Background worker

External synchronization and security evaluations will eventually run asynchronously. The worker is not introduced until the first integration requires it.

### Integration layer

Provider-specific logic belongs behind integration interfaces. Microsoft Graph will be the first implementation.

### Risk engine

The risk engine will convert normalized security evidence into findings and priorities. Provider collection logic and risk evaluation should remain separate.

## Tenant boundary

Every customer-owned record must be attributable to an organization.

Application code must not rely solely on UI filtering for tenant isolation. Authorization checks must be enforced at server boundaries and tested.

## Security-sensitive credentials

OAuth refresh tokens and equivalent provider credentials must:

- never be returned to the browser after initial authorization;
- never be logged;
- be encrypted before persistence;
- be accessible only to the minimum application component requiring them;
- support revocation and rotation.

## Auditability

Security-sensitive state changes should produce an audit event recording, at minimum:

- organization;
- actor;
- action;
- resource type;
- resource identifier where applicable;
- timestamp;
- non-secret contextual metadata.

## Next architectural milestone

The next milestone is authentication and organization context, followed by the Microsoft 365 OAuth integration.
