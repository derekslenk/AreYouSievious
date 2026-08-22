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

- `POST /api/scripts/preview` renders one Rule through the backend generator, and the SPA's duplicate generator (`previewRule`) is deleted. The preview is now the bytes a save writes, asserted as such; the duplicate had diverged five ways, including showing nothing for a Rule whose last Condition was deleted while a save wrote invalid Sieve (areyousievious-8fg.17)

- GitHub Actions CI workflow (`.github/workflows/ci.yml`): runs pytest and frontend build on every push and pull request (P1)
- Sieve parser regression test suite (`backend/tests/`) covering round-trip stability, else/elsif handling, address-part/`:comparator` parsing, and ReDoS budget (Phase CP1)
- Sieve fixture corpus (`backend/test_scripts/`): twelve hand-written one-construct fixtures plus sievelib's parser corpus vendored under MIT in `vendor/`, with a per-fixture recognition census and a pinned recogniser-reach total (areyousievious-8fg.3)
- Frontend `rebuildOrder` unit test covering delete-after-reorder desync scenario
- Footer with GitHub link and privacy policy page
- Browser back/forward navigation between views
- Drag-and-drop reordering for rules, conditions, and actions
- Hierarchical `AGENTS.md` files for AI-assisted development

### Changed

- Closed wire vocabularies: `match`, `match_type` and an Action's `type` are Pydantic `Literal`s pinned against `sieve_transform`'s own vocabulary tuples, so a body naming a construct that does not exist is a 422 instead of a silently mis-generated script. The SPA now imports the generated `api-types.d.ts`, making `toWire` a type-checked whitelist (areyousievious-8fg.18)

- CORS configuration tightened: explicit `allow_methods` and `allow_headers` replace wildcard (P1)
- `save_script` endpoint converted from `async def` to `sync def` to avoid event-loop blocking on ManageSieve I/O

### Fixed

- Condition header is a free-text field with suggestions rather than a closed dropdown: a rule on an unlisted header (`x-spam-flag`) rendered as an empty select and lost its value the moment that select was opened (areyousievious-8fg.18)

- Sieve parser round-trip stability: `else`/`elsif` blocks and `address` tests with `:comparator` modifiers now survive a parse → generate cycle without mutation (Phase CP1)
- Frontend `rebuildOrder`: script rule order is now rebuilt from rule IDs rather than array index, fixing a desync when a rule is deleted after reordering (Phase CP1)
- Frontend dependency vulnerabilities patched
