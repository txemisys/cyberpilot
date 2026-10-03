# CyberPilot

**CyberPilot** is a cybersecurity management platform for small and medium-sized businesses without a dedicated cybersecurity team.

> **Discover what puts your business at risk. Prioritize what matters. Fix it. Prove that you are protected.**

CyberPilot is not intended to replace antivirus, EDR, Microsoft Defender, MDM, SIEM, or other specialist security products. Instead, it acts as an intelligence, orchestration, and risk-management layer on top of the tools a company already uses.

## Vision

Small and medium-sized businesses often have security tools but lack the expertise, time, and context required to answer fundamental questions:

- Are we reasonably protected?
- What are our most important risks?
- What should we fix first?
- Can CyberPilot fix it for us?
- What should we do during a security incident?
- How can we prove our security posture to customers, insurers, auditors, or partners?

CyberPilot aims to answer those questions continuously.

The long-term goal is to become a **virtual cybersecurity team for SMEs**.

## Core product

CyberPilot is built around four outcomes:

### Discover
Continuously identify relevant security weaknesses across identities, Microsoft 365, email, domains, devices, cloud services, and externally exposed assets.

### Prioritize
Translate technical findings into understandable business risks. CyberPilot should not show a company hundreds of alerts. It should answer:

> **What are the three most important things we should fix today?**

### Fix
Provide guided remediation and, when technically possible and sufficiently safe, automated remediation. High-impact actions always require explicit administrator approval.

### Prove
Continuously collect evidence showing the company's current security posture for customer questionnaires, audits, cyber insurance, supplier assessments, compliance readiness, and security reports.

## Initial customer

The first version targets **B2B companies with approximately 10–100 employees** that:

- use Microsoft 365;
- do not employ a full-time CISO;
- depend heavily on email and cloud identities;
- handle customer, employee, financial, or commercial data;
- may receive security questionnaires from customers;
- need better security without operating enterprise security infrastructure.

Microsoft 365 is the first ecosystem. Google Workspace and additional security platforms can follow later.

## MVP

The initial commercial MVP is intentionally narrow.

### Microsoft 365 Security Assessment

A company connects its Microsoft 365 tenant to CyberPilot using OAuth.

Initial capabilities:

- Microsoft tenant connection;
- identity inventory;
- privileged account detection;
- MFA posture;
- inactive and potentially abandoned accounts;
- privileged role exposure;
- domain inventory;
- SPF analysis;
- DKIM analysis;
- DMARC analysis;
- basic external exposure checks;
- security findings;
- risk prioritization;
- CyberScore;
- remediation guidance;
- audit history;
- executive security report.

## First product milestones

### Milestone 1 — Discover
A real company connects Microsoft 365 and CyberPilot identifies at least one relevant security issue within minutes, explains why it matters, shows supporting evidence, and provides a clear remediation path.

### Milestone 2 — Fix
CyberPilot safely remediates at least one type of security problem after explicit administrator approval.

### Milestone 3 — Sell
A real customer pays to keep CyberPilot continuously connected to its environment.

## CyberScore

CyberPilot will provide an understandable representation of the company's security posture.

The score is **not a certification**.

A finding may be evaluated using factors such as:

```text
risk =
    severity
  × exposure
  × privilege
  × business_context
  × confidence
```

Examples include:

- privileged administrator without MFA;
- former employee account still enabled;
- domain without DMARC;
- externally exposed vulnerable service;
- unmanaged device;
- compromised credential.

The scoring system must remain explainable.

## Product principles

### Actionable over technical
CyberPilot should explain security in language that a business owner or IT administrator can act on.

### Priorities over alerts
CyberPilot should reduce security noise, not create another dashboard containing hundreds of warnings.

### Evidence over assumptions
Every important finding should include evidence, source, timestamp, confidence, and recommended action.

### Human approval for critical actions
CyberPilot must not autonomously perform destructive actions such as deleting accounts, wiping devices, or making broad access-control changes.

### Integrate before reinventing
CyberPilot will integrate with existing security technologies rather than initially building its own antivirus, EDR, SIEM, VPN, firewall, or backup engine.

### Security by design
CyberPilot itself will have access to highly sensitive security information. Security therefore begins with the first commit.

## Initial architecture

```text
                        Internet
                           │
                           ▼
                  ┌─────────────────┐
                  │ CyberPilot Web  │
                  └────────┬────────┘
                           │
            ┌──────────────┼───────────────┐
            │              │               │
            ▼              ▼               ▼
       PostgreSQL       Job Queue      Risk Engine
                                            │
                                            ▼
                                   Integration Layer
                                      │          │
                                      ▼          ▼
                               Microsoft Graph   DNS /
                                                APIs
```

Infrastructure complexity should only be introduced when an actual operational requirement justifies it.

## Proposed stack

| Area | Technology |
|---|---|
| Frontend | Next.js + TypeScript |
| Backend | TypeScript / Node.js |
| Database | PostgreSQL |
| ORM | Prisma or Drizzle |
| Authentication | OAuth / OIDC |
| Microsoft integration | Microsoft Graph |
| Background processing | Managed queue |
| Secrets | Managed KMS / secrets service |
| CI/CD | GitHub Actions |
| Observability | OpenTelemetry + error monitoring |
| Cloud | Managed cloud services |

Kubernetes is intentionally outside the initial MVP.

## Repository structure

Expected direction:

```text
cyberpilot/
├── apps/
│   ├── web/
│   └── worker/
├── packages/
│   ├── database/
│   ├── integrations/
│   ├── risk-engine/
│   ├── security/
│   ├── shared/
│   └── ui/
├── infrastructure/
├── docs/
└── .github/
    └── workflows/
```

## Core domain model

Initial entities are expected to include:

```text
Organization
User
Membership

Integration
IntegrationCredential

Identity
Device
Domain
Asset

Finding
Evidence
Risk
Remediation

AuditEvent
SecurityScore
```

CyberPilot is multi-tenant from the beginning.

**Tenant isolation is a security boundary.**

## Microsoft integration

The first external integration will use **Microsoft Graph**.

Initial areas of interest include users, groups, directory roles, privileged identities, authentication posture, tenant metadata, devices, and security configuration.

Actual information available will depend on Microsoft APIs, tenant configuration, permissions, and licensing.

CyberPilot should always distinguish between:

```text
secure
insecure
unknown / insufficient evidence
```

It must never assume that an unavailable signal means that a control is secure.

## Risk engine

Security checks should be represented as reusable rules rather than scattered throughout application code.

Conceptually:

```yaml
id: IDENTITY_PRIVILEGED_ACCOUNT_WITHOUT_MFA

title: Privileged account without MFA

severity: critical

conditions:
  privileged: true
  mfa_enabled: false

remediation:
  playbook: require_mfa

evidence:
  source: microsoft_graph
```

Rules should eventually support detection, severity, confidence, business context, evidence, remediation, automation, framework mappings, and versioning.

## Remediation

CyberPilot will support two remediation modes.

### Guided remediation
CyberPilot explains what is wrong, why it matters, what should be changed, how to make the change, and how to verify the result.

### Automated remediation
When APIs support safe automation:

```text
Finding
   ↓
Proposed remediation
   ↓
Administrator approval
   ↓
API action
   ↓
Verification
   ↓
Audit event
   ↓
Evidence
```

## Future capabilities

These are part of the product vision but are not necessarily part of the first MVP.

### Incident Mode
Guided response for compromised accounts, phishing, ransomware, lost devices, payment fraud, suspected data exposure, and unknown suspicious activity.

### CyberPassport
A shareable, evidence-backed security profile for customers, partners, insurers, auditors, procurement teams, and supply-chain assessments.

### Security questionnaire automation
Upload a customer or supplier questionnaire and reuse verified CyberPilot evidence to draft answers, with human review.

### Compliance readiness
Potential mappings include CIS Controls, ISO 27001, NIS2-related controls, Cyber Essentials, and customer-specific requirements.

CyberPilot must clearly distinguish between **readiness/evidence assistance** and **formal certification**.

### Employee security
Potential future capabilities include security onboarding, offboarding, lightweight training, phishing simulation, identity hygiene, and compromised credential detection.

### Vendor risk
CyberPilot may eventually allow companies to assess important suppliers and request security evidence from them.

## Security requirements

CyberPilot itself is a high-value target.

Baseline requirements include:

- strong tenant isolation;
- least privilege;
- OAuth / OIDC;
- MFA;
- RBAC;
- encryption in transit;
- encryption at rest;
- managed secrets;
- encrypted provider tokens;
- key rotation;
- complete audit logging;
- secure session management;
- CSRF protection;
- restrictive security headers;
- input validation;
- rate limiting;
- dependency scanning;
- secret scanning;
- SAST;
- protected production deployments;
- backup and recovery procedures;
- security logging and monitoring.

Provider access tokens and other credentials must never appear in application logs.

## Data minimization

CyberPilot should collect the minimum amount of customer data required to provide a security outcome.

For example, when evaluating MFA it may be sufficient to retain:

```text
identity_id
mfa_enabled
source
checked_at
```

rather than copying unrelated identity or mailbox information.

## Development workflow

```text
Issue
  ↓
Feature branch
  ↓
Implementation
  ↓
Tests
  ↓
Pull request
  ↓
Review
  ↓
Security checks
  ↓
Merge
  ↓
Staging
  ↓
Production
```

Direct changes to `main` should be avoided once the project foundation has been established.

## Roadmap

### Sprint 1 — Foundation

- [ ] establish repository structure;
- [ ] initialize Next.js;
- [ ] configure TypeScript;
- [ ] configure linting and formatting;
- [ ] establish PostgreSQL;
- [ ] create multi-tenant data model;
- [ ] implement application authentication;
- [ ] implement organizations and memberships;
- [ ] create audit-event model;
- [ ] configure GitHub Actions;
- [ ] enable dependency and secret scanning;
- [ ] establish staging deployment.

### Sprint 2 — Microsoft 365

- [ ] register Microsoft application;
- [ ] implement OAuth;
- [ ] secure token storage;
- [ ] token refresh;
- [ ] connect and disconnect tenant;
- [ ] Microsoft Graph client;
- [ ] import identities;
- [ ] import directory roles;
- [ ] identify privileged users;
- [ ] audit integration actions.

### Sprint 3 — Risk engine

- [ ] Finding model;
- [ ] Evidence model;
- [ ] rule engine;
- [ ] severity and confidence model;
- [ ] CyberScore;
- [ ] privileged identity checks;
- [ ] MFA checks;
- [ ] prioritized dashboard.

### Sprint 4 — Domain security

- [ ] domain inventory;
- [ ] DNS collection;
- [ ] SPF analysis;
- [ ] DKIM analysis;
- [ ] DMARC analysis;
- [ ] domain findings;
- [ ] remediation guidance.

### Sprint 5 — Remediation

- [ ] remediation playbooks;
- [ ] approval flow;
- [ ] verification;
- [ ] audit history;
- [ ] posture history;
- [ ] weekly report;
- [ ] executive security report.

## Current status

CyberPilot is currently in the **foundation stage**.

The first engineering objective is to build a secure and maintainable base for the Microsoft 365 security MVP.

The immediate product objective is simple:

> **Connect a real company, find a real security problem, and help fix it.**

## Contributing

CyberPilot is currently in early development.

Until the architecture and public interfaces stabilize, significant changes should be discussed through GitHub issues before implementation.

## License

A final licensing model has not yet been selected.

Until a license is explicitly added to this repository, **no open-source license should be assumed**.
