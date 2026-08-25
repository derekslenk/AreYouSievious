# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Security

- `source`, the bytes an entry is re-emitted from on save, crosses the wire and is never trusted on arrival: `span_is_faithful` re-parses it and refuses anything that is not exactly the entry it accompanies — one entry, no `require`, no preamble, no tail, value-equal to the submitted entry. The preamble, `require` bytes and tail have no entry to compare against, so `preflight_error`'s boundary check holds them to the same standard (areyousievious-8fg.14)
- A `Rule.name` or `RawBlock.comment` carrying a line break or a NUL is refused before save. Both fields are interpolated into a single `# ` comment line, so either byte would end that comment and turn the rest of the field into a live statement the mail server executes; the same guard already refused a lone CR there for the same reason. NUL stays allowed in `RawBlock.text` and an entry's `source` — a script that already has one on the server can still be saved unchanged (areyousievious-bvy)
- TLS context hardening: verify outbound IMAP TLS certificate chain; add connect/read timeouts to ManageSieve and IMAP sockets (Phase CP1)
- ReDoS budget: replaced unbounded backtracking regex in Sieve quoted-string parser with a linear alternative
- CRLF header-injection guard: strip `\r` and `\n` from Sieve script names before passing to ManageSieve `PUTSCRIPT`/`SETACTIVE` commands
- Bump `python-multipart` to `>=0.0.18` (CVE-2024-53981 — multipart form-data ReDoS)
- DNS rebinding guard: reject requests whose `Host` header does not match the configured allowed-hosts list (P1)
- Trusted-proxy IP detection: read client IP from `X-Forwarded-For` only when request originates from a trusted proxy CIDR (P1)
- SSRF protection, rate limiting, and security headers added to FastAPI middleware stack
- Request-boundary hardening: Pydantic DTOs (`SaveScriptRequest`, `ActivateScriptRequest`, `CreateFolderRequest`) replace raw `request.json()` calls; body-size limit middleware; CSRF middleware; explicit `allow_methods` and `allow_headers` on CORS (P1)

### Added

- Parsing now decomposes a Sieve file into `preamble + requires_source + Σ entry.source + tail`, where every byte of the original belongs to exactly one term and each entry's span carries the blank lines and comments immediately above it. Saving re-emits an entry's span byte-for-byte when re-parsing it agrees with the entry, and renders it canonically only when it does not — so parsing and saving a script with no edits is byte-identical, not just construct-for-construct equivalent, and editing one Rule no longer reformats every other Rule into house style. Two exceptions are deliberate: a file with a `fileinto` and no `require` statement is invalid Sieve, so a save adds the canonical `require` line; and an empty script saves as a single newline. See `docs/adr/0002-the-file-is-a-sequence-of-spans.md` (areyousievious-8fg.14)
- Preview and save can now render an unedited rule differently: preview always shows house style, which is what discloses to the user what a rule would look like *if* edited before they commit to a save that re-emits the original bytes instead. Both still go through the one `generate_entry`, so they cannot drift from each other (areyousievious-8fg.14)
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

- `require` pruning (areyousievious-8fg.15) now happens only on a save that regenerates at least one entry, rather than on every save. A script saved with no edits keeps its `require` line exactly as written, even if it over-declares an extension nothing in the file uses — rewriting that line would break the byte-identical guarantee above for a file nobody asked to change (areyousievious-8fg.14)
- Closed wire vocabularies: `match`, `match_type` and an Action's `type` are Pydantic `Literal`s pinned against `sieve_transform`'s own vocabulary tuples, so a body naming a construct that does not exist is a 422 instead of a silently mis-generated script. The SPA now imports the generated `api-types.d.ts`, making `toWire` a type-checked whitelist (areyousievious-8fg.18)

- CORS configuration tightened: explicit `allow_methods` and `allow_headers` replace wildcard (P1)
- `save_script` endpoint converted from `async def` to `sync def` to avoid event-loop blocking on ManageSieve I/O

### Fixed

- A `require` no longer comes back declared twice when something stands above it. The parser leaves a `require` that follows another entry unharvested, so its own bytes carry the declaration — but the generator rendered a canonical `require` line from the computed set anyway and the block re-emitted its copy underneath, so a file with a bracketed licence header above its `require` (legal Sieve: RFC 5228 §2.3 makes a comment not a command) declared `fileinto` twice and was no longer byte-identical on an unedited save. The computed set now subtracts what the file's own bytes already declare, and `span_is_faithful` can vouch for such a block's span — re-parsed in the position it came from, held to the same value equality as any other entry (areyousievious-3xk)
- A `require` statement sent in `preamble` rather than `requires_source` is refused. `preamble` is documented as immovable non-`require` bytes, and one placed there parsed into the head's requires rather than its entries — so it passed the boundary check and was written alongside the canonical line, declaring the same extension twice. Cosmetic (RFC 5228 §3.2 permits the repetition) and unreachable from the SPA, but an unenforced shape is not a shape (areyousievious-5vp)
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
