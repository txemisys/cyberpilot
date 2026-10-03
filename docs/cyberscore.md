# CyberScore v0

CyberScore is an explainable posture indicator for the security controls that CyberPilot can currently observe.

It is **not** a certification, compliance grade, breach prediction, or guarantee of security.

## Design goals

CyberScore v0 must be:

- deterministic;
- explainable finding by finding;
- conservative when evidence is unavailable;
- resistant to duplicate-alert inflation;
- useful for prioritization;
- explicit about partial coverage.

## Current formula

The score starts at 100.

Each supported open finding receives base risk points from its severity:

| Severity | Base points |
|---|---:|
| INFO | 1 |
| LOW | 3 |
| MEDIUM | 7 |
| HIGH | 15 |
| CRITICAL | 25 |

A rule then applies a documented context multiplier.

Conceptually:

```text
finding_risk_points =
  severity_points
  × privilege_multiplier
```

Risk points are rounded to one decimal place.

CyberScore is then:

```text
CyberScore =
  max(0, 100 - sum(capped_rule_contributions))
```

## Why rule caps exist

Several findings can represent the same underlying control failure.

For example, five administrators without MFA should be worse than one administrator without MFA, but that single control family should not reduce the entire company score without limit.

Each rule therefore defines a maximum contribution.

Current rule metadata:

| Rule | Severity | Privilege multiplier | Rule cap |
|---|---:|---:|---:|
| M365_GLOBAL_ADMIN_MFA_NOT_CAPABLE | CRITICAL | 1.60 | 40 |
| M365_GUEST_GLOBAL_ADMIN | CRITICAL | 1.60 | 40 |
| M365_ADMIN_MFA_NOT_CAPABLE | HIGH | 1.35 | 30 |
| M365_GLOBAL_ADMIN_COUNT_HIGH | HIGH | 1.30 | 30 |

These values are product heuristics, not external certification thresholds. They should be versioned and recalibrated as CyberPilot adds more controls and real customer evidence.

## Coverage

A score is only meaningful in the context of the evidence CyberPilot can observe.

The UI must indicate partial coverage when:

- required provider permissions are missing;
- a capability is in an error state;
- an open finding exists for which the current Risk Engine has no scoring metadata.

A score of 100 under partial coverage must never be interpreted as proof that the organization has no material security risk.

## Top actions

CyberPilot ranks supported open findings using their calculated risk points.

The first three become the current Top Actions.

Each action includes:

- finding title;
- severity;
- risk points;
- explicit remediation;
- a short rationale showing the scoring inputs.

This is intended to answer:

> What are the three most important things we should fix next?

## Current limitations

CyberScore v0 currently covers only the first Microsoft 365 identity controls implemented by CyberPilot.

It does not yet incorporate:

- domain and email security;
- endpoint/device posture;
- credential exposure;
- vulnerability exposure;
- business-critical asset value;
- conditional access policy quality;
- phishing-resistant MFA enforcement;
- incident history;
- vendor risk;
- customer-specific context.

The model should remain visibly versioned until coverage and calibration are mature.


## Domain-security controls

CyberScore v0 also supports evidence-backed domain and email-authentication rules.

The first domain controls cover:

- missing or invalid DMARC;
- monitoring-only DMARC (`p=none`);
- missing or multiple SPF policy records;
- missing or incomplete Microsoft 365 DKIM selector DNS records.

The domain rules use lower context multipliers where the DNS signal alone cannot prove the full mail flow. In particular, absence of Microsoft 365 DKIM selector CNAMEs does not prove that a domain never signs mail if another provider is responsible for outbound mail.

DNS lookup errors are treated as unknown/error coverage. They are not converted into security findings that claim a record is missing.
