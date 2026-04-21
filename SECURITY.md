# Security Policy

## Reporting Vulnerabilities

If you find a security vulnerability in this project, please report it responsibly.

**Email:** leslie.gutschow@horizondigital.dev

Please include:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

We will respond within 48 hours and provide a fix timeline.

## Scope

This policy covers:
- Cyphera Open KMIP Server (`open-kmip-server`)
- KMIP protocol handler
- REST API
- Storage layer
- Authentication/session management

## Known Limitations (Alpha)

This project is in alpha. The following are known and tracked:

- Key material is stored as plaintext in SQLite (envelope encryption planned)
- Per-key authorization not yet enforced (owner field exists, enforcement coming)
- Session tokens are not TLS-channel-bound
- No OIDC/SSO integration yet

These are documented in our internal tracking and will be addressed before GA.
