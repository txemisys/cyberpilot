# Domain and email security

CyberPilot's first domain-security scanner analyzes verified Microsoft 365 domains using public DNS evidence.

## Standards

The initial implementation follows:

- SPF: RFC 7208;
- DMARC: RFC 9989, published in May 2026 and replacing RFC 7489;
- Microsoft 365 DKIM custom-domain selector discovery using `selector1._domainkey` and `selector2._domainkey`.

## Data source

Verified domains are collected from Microsoft Graph organization metadata.

CyberPilot stores:

- domain name;
- whether Microsoft marks it as the default domain;
- whether it is the tenant's initial Microsoft domain;
- SPF status and observed SPF TXT records;
- DMARC status, policy, and observed DMARC TXT records;
- Microsoft 365 DKIM selector DNS observations;
- DNS observation timestamp.

All of this evidence is public DNS or Microsoft tenant metadata.

## SPF

CyberPilot looks for TXT records beginning with `v=spf1`.

Current normalized states:

- `PRESENT`: exactly one SPF record was observed;
- `MISSING`: no SPF record was observed;
- `MULTIPLE`: more than one SPF record was observed;
- `ERROR`: DNS resolution failed for a reason other than a normal no-record response.

CyberPilot does not yet fully evaluate the SPF mechanism tree, DNS lookup count, redirect/include recursion, or whether every legitimate sender is represented.

## DMARC

CyberPilot queries:

```text
_dmarc.<domain>
```

Current normalized states:

- `MISSING`: no DMARC policy record was observed;
- `MONITORING`: one valid-looking DMARC record with `p=none`;
- `ENFORCING`: one valid-looking DMARC record with `p=quarantine` or `p=reject`;
- `INVALID`: multiple DMARC records or a record without a supported `p` policy;
- `ERROR`: DNS resolution failed.

The scanner intentionally does not claim that an enforcing record alone proves full DMARC conformance. Alignment and actual sending behavior require additional evidence.

## Microsoft 365 DKIM DNS

For verified Microsoft 365 custom domains, CyberPilot checks the DNS names:

```text
selector1._domainkey.<domain>
selector2._domainkey.<domain>
```

Current normalized states:

- `PUBLISHED`: both selector CNAMEs resolve;
- `PARTIAL`: only one selector CNAME resolves;
- `MISSING`: neither selector CNAME resolves;
- `ERROR`: the lookup fails unexpectedly.

This is a DNS-configuration signal. It does not independently prove that every outbound message is DKIM-signed, and it does not apply to mail sent through a different provider.

## Initial-domain handling

Microsoft's initial `.onmicrosoft.com` domain is retained in inventory but excluded from custom-domain findings.

## Failure semantics

A DNS timeout or resolver failure is not equivalent to a missing control.

CyberPilot records DNS errors as `ERROR`, marks score coverage as partial, and avoids opening a "missing record" finding from failed evidence collection.
