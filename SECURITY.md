# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| `main`  | Yes       |

Once version tags exist, only the latest tagged release is supported. Older tags receive no backports.

## Reporting a Vulnerability

Email **derek@slenk.com** with:

- A description of the vulnerability and affected component
- Steps to reproduce or a proof-of-concept
- Your assessment of impact

Alternatively, use GitHub's built-in private disclosure: navigate to the repository **Security** tab and click **"Report a vulnerability"**.

**Acknowledgement window:** 72 hours. No PGP required.

Please do not open a public issue for security vulnerabilities.

## Scope

Defects in AreYouSievious itself as deployed by a self-hoster — the FastAPI backend, the Svelte frontend, the ManageSieve/IMAP client code, and the Sieve parser/generator.

Vulnerabilities in upstream dependencies (FastAPI, Svelte, Starlette, python-multipart, etc.) should be reported to those projects directly. If an upstream vulnerability has a specific, exploitable impact on AreYouSievious deployments, report it here as well so a dependency bump can be tracked.

## Out of Scope

- Denial-of-service via deliberate resource exhaustion by an authenticated user
- Vulnerabilities that require physical access to the mail server host
- Issues in the mail server itself (Dovecot, Postfix, etc.) rather than in this application
