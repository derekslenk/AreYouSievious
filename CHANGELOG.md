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

- sievelib AST oracle in CI: every fixture is parsed, regenerated and compared by an independent grammar, so a change to what a script MEANS fails the build. Normalises only the differences made on purpose (`require`, header-name case, string escaping) and is tested to bite in both directions (areyousievious-8fg.13)
- Runtime pre-flight before PUT: a Rule whose last Condition was deleted generates `if anyof ( ) {`, and the save is now refused with the compiler diagnostic rather than sent (areyousievious-8fg.13)

- `docs/DEPLOY.md`: Coolify deployment runbook (Dockerfile build pack, the environment variables that matter in production, and the two behaviours that surprise operators — in-memory sessions, and the SSRF guard refusing a private mail server). The app now warns at startup when `AYS_TRUSTED_PROXIES` is empty, which behind a reverse proxy means every client shares one login rate-limit bucket

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

- Sieve escapes now follow RFC 5228 §2.4.2, where a backslash before any character is that character. Previously only `\"` and `\\` were handled, so every other escape survived parsing and was escaped again on the way out — `:regex "^a\.b$"` (dot matches anything) became `"^a\\.b$"` (literal dot), and `addflag "\Flagged Big"` became the flag `\Flagged Big` (areyousievious-8fg.13)
- Multi-line top-level commands are read as one statement instead of one line at a time. A multi-line `vacation` became four raw blocks, and generation separates entries with a blank line — so a blank line was injected into the vacation message text (areyousievious-8fg.13)

- Narrowing projection: a block is only read as an editable Rule when every construct in it is one the builder models. Previously a partly-understood block was projected anyway — an `allof` holding one `header` test and two `date` tests came back carrying the header test alone, so a rule that filed mail only during office hours regenerated to file it at every hour (areyousievious-8fg.11)
- Tagged arguments now parse in any order, as RFC 5228 §2.7.1 allows and the RFC's own example writes: `address :is :all "from" "x"` was previously unreadable while `address :all :is "from" "x"` was fine (areyousievious-8fg.11)
- Round-trip fidelity (areyousievious-8fg.15): a disabled rule's name no longer accretes a `# --- ` marker per save; a second `require` statement extends rather than replaces the first; a multi-line `require` is read whole instead of leaving fragments that regenerated into invalid Sieve; and `require` is now derived from content instead of only ever growing

- Sieve recogniser now has a lexical model (sievelib's Lexer), closing three data-corrupting defects that all regenerated as valid Sieve: a `{` inside a quoted folder name merged the following rule into the previous one and dropped its condition; a nested `if` lost its inner condition, leaving the inner action firing on the outer one; and a commented-out action was resurrected as live (areyousievious-8fg.10)

- Condition header is a free-text field with suggestions rather than a closed dropdown: a rule on an unlisted header (`x-spam-flag`) rendered as an empty select and lost its value the moment that select was opened (areyousievious-8fg.18)

- Sieve parser round-trip stability: `else`/`elsif` blocks and `address` tests with `:comparator` modifiers now survive a parse → generate cycle without mutation (Phase CP1)
- Frontend `rebuildOrder`: script rule order is now rebuilt from rule IDs rather than array index, fixing a desync when a rule is deleted after reordering (Phase CP1)
- Frontend dependency vulnerabilities patched
