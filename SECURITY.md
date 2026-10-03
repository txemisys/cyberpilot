# Security Policy

CyberPilot is security-sensitive software and should be treated as a high-value target.

## Reporting a vulnerability

Please do not disclose suspected vulnerabilities through a public GitHub issue.

Until a dedicated security contact and disclosure process are published, repository maintainers should be contacted privately through an appropriate private channel.

## Development requirements

Contributions must avoid:

- committing credentials, tokens, certificates, or production configuration;
- logging OAuth access or refresh tokens;
- logging customer secrets or unnecessary personal data;
- weakening tenant boundaries;
- introducing high-impact automated remediation without explicit authorization and auditability.

Security-sensitive changes should include tests for authorization boundaries and failure conditions whenever practical.

## Current status

CyberPilot is in early development and is not yet intended for production security monitoring.
