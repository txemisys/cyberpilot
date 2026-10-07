# Content Security Policy

CyberPilot uses a production-only Content Security Policy in **Report-Only** mode before enforcement.

This is intentional. Next.js and authentication flows must be observed in a real staging environment before a blocking policy is enabled.

## Current policy

The current baseline includes:

- `default-src 'self'`
- `base-uri 'self'`
- `object-src 'none'`
- `frame-ancestors 'none'`
- `form-action 'self'`
- `script-src 'self' 'unsafe-inline'`
- `style-src 'self' 'unsafe-inline'`
- `img-src 'self' data: blob:`
- `font-src 'self' data:`
- `connect-src 'self'`
- `worker-src 'self' blob:`
- `manifest-src 'self'`
- `media-src 'self'`
- `frame-src 'none'`

The initial baseline deliberately retains `'unsafe-inline'` for scripts/styles to avoid pretending that nonce/hash hardening is complete before staging observation. Removing it belongs to the enforcement-hardening phase.

## Report destination

Set:

```env
CSP_REPORT_URI="https://managed-collector.example/csp"
```

to append a `report-uri` directive.

Accepted values are:

- a same-origin relative path such as `/api/csp-report`;
- an absolute HTTPS URL.

HTTP, protocol-relative, malformed, newline-bearing, or semicolon-bearing values are ignored so an environment variable cannot inject arbitrary response headers/directives.

CyberPilot does not expose a public CSP-report ingestion endpoint by default. This avoids turning an unauthenticated endpoint into a log-amplification surface.

## Staging validation

Before moving from `Content-Security-Policy-Report-Only` to enforcement:

1. deploy the policy to managed staging;
2. exercise login/logout;
3. create/access an organization;
4. run the Microsoft consent/read-only probe flow;
5. run Lab Mode;
6. open the executive report and browser print flow;
7. inspect CSP violations in the managed collector/browser tooling;
8. distinguish framework-required behavior from accidental third-party origins;
9. tighten script/style directives with a verified nonce/hash strategy;
10. repeat the full smoke test with no unexpected violations.

## Production gate

CSP remains **PARTIAL** until:

- staging has produced representative violation data;
- a nonce/hash strategy is validated for Next.js;
- authentication and Microsoft flows work under enforcement;
- unexpected external origins are removed or explicitly justified;
- the blocking `Content-Security-Policy` header replaces report-only mode.

Do not describe CSP hardening as complete while `'unsafe-inline'` remains required.
