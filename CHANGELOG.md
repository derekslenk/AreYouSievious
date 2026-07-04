# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- TLS context hardening: verify outbound IMAP TLS certificate chain; add connect/read timeouts to ManageSieve and IMAP sockets (Phase CP1)
- ReDoS budget: replaced unbounded backtracking regex in Sieve quoted-string parser with a linear alternative
- CRLF header-injection guard: strip `\r` and `\n` from Sieve script names before passing to ManageSieve `PUTSCRIPT`/`SETACTIVE` commands
- Bump `python-multipart` to `>=0.0.18` (CVE-2024-53981 — multipart form-data ReDoS)
- DNS rebinding guard: reject requests whose `Host` header does not match the configured allowed-hosts list (P1)
- Trusted-proxy IP detection: read client IP from `X-Forwarded-For` only when request originates from a trusted proxy CIDR (P1)
- SSRF protection, rate limiting, and security headers added to FastAPI middleware stack
- Request-boundary hardening: Pydantic DTOs (`SaveScriptRequest`, `ActivateScriptRequest`, `CreateFolderRequest`) replace raw `request.json()` calls; body-size limit middleware; CSRF middleware; explicit `allow_methods` and `allow_headers` on CORS (P1)

### Added

- GitHub Actions CI workflow (`.github/workflows/ci.yml`): runs pytest and frontend build on every push and pull request (P1)
- Sieve parser regression test suite (`backend/tests/`) covering round-trip stability, else/elsif handling, address-part/`:comparator` parsing, and ReDoS budget (Phase CP1)
- Frontend `rebuildOrder` unit test covering delete-after-reorder desync scenario
- Footer with GitHub link and privacy policy page
- Browser back/forward navigation between views
- Drag-and-drop reordering for rules, conditions, and actions
- Hierarchical `AGENTS.md` files for AI-assisted development

### Changed

- CORS configuration tightened: explicit `allow_methods` and `allow_headers` replace wildcard (P1)
- `save_script` endpoint converted from `async def` to `sync def` to avoid event-loop blocking on ManageSieve I/O

### Fixed

- Sieve parser round-trip stability: `else`/`elsif` blocks and `address` tests with `:comparator` modifiers now survive a parse → generate cycle without mutation (Phase CP1)
- Frontend `rebuildOrder`: script rule order is now rebuilt from rule IDs rather than array index, fixing a desync when a rule is deleted after reordering (Phase CP1)
- Frontend dependency vulnerabilities patched
