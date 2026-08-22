<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# backend

## Purpose
FastAPI application that serves the Svelte SPA as static files and provides a REST API proxying ManageSieve and IMAP operations to the user's mail server. Contains the bidirectional Sieve-to-JSON transform pipeline.

## Key Files
| File | Description |
|------|-------------|
| `app.py` | Composition root only — `create_app(config)` factory wiring exception handlers, middleware stack, and `include_router` calls, plus the CLI entry point. No business logic; routes live in `routers/` |
| `config.py` | Every environment variable, read into a frozen `Settings`. `settings()` reads the environment fresh and is called exactly once, by `create_app`; everything below it receives that instance (`Depends(get_settings)`, or `request.app.state.settings`) |
| `dependencies.py` | The per-request dependencies routers RECEIVE: `get_settings` (reads `request.app.state.settings`), `get_session` (cookie or Bearer, raises 401), and `get_script_store` / `get_folder_store`, which yield an open adapter and close it when the request ends |
| `api_models.py` | Pydantic request/response DTOs. Every model is `extra="forbid"` with `max_length` caps; `EntryDTO` is a `kind`-discriminated `RuleDTO \| RawBlockDTO` |
| `auth.py` | `SessionManager` holding credentials in process memory (plaintext, 30 min idle timeout). Never persisted |
| `middleware.py` | `BodySizeLimitMiddleware` (Content-Length + streamed-byte cap) and `CSRFMiddleware` (double-submit cookie) |
| `ssrf.py` | SSRF + DNS-rebinding guards. `validate_host` pins an IP at login; `assert_host_resolves_to` re-checks at every connect |
| `protocol_names.py` | `validate_script_name` / `validate_folder_name` / `ProtocolNameError` — one rule for both ManageSieve and IMAP framing, rejected before any protocol call |
| `mail_dial.py` | **The only way to open a mail-server connection.** `open_imap` / `open_sieve` apply the whole dialling policy: rebinding re-check, dial the pinned IP, TLS SNI on the hostname, timeouts. Both take the caller's `Settings`; `build_tls_context` caches on it, so no dial can use a different vintage than its app. Both also translate what the transport RAISES into `mail_errors` — `OSError` kin, `imaplib.IMAP4.error`/`abort`, and sievelib's own `Error` — so a dead server is a 502, not a 500 |
| `sieve_transform.py` | Core Sieve parser (`SieveParser`), generator (`SieveGenerator`), and data models (`Rule`, `Condition`, `Action`, `RawBlock`, `SieveScript`) |
| `mail_stores.py` | The two mail-server seams as `Protocol`s: `ScriptStore` (list/get/put/activate/delete) and `FolderStore` (list/create). Kept separate — a single seven-operation store would be a union, not an abstraction |
| `mail_errors.py` | The semantic vocabulary the seams fail in (`MailStoreError` + `ScriptNotFound`, `ScriptRejected`, `QuotaExceeded`, `FolderRejected`, `MailServerUnavailable`, `AuthFailed`). Protocol-free AND HTTP-free; `app.py` owns the status mapping |
| `managesieve_client.py` | `SieveClient` context manager for ManageSieve (port 4190) — the ScriptStore adapter. Owns the script operations and translates sievelib's falsy returns + `errcode`/`errmsg` into `mail_errors`; dialling policy lives in `mail_dial` |
| `imap_store.py` | `ImapFolderStore` context manager for IMAP (port 993) — the FolderStore adapter. Owns what to say once connected; maps `imaplib.IMAP4.abort`/`error` on LOGIN to `MailServerUnavailable`/`AuthFailed` (abort first — it subclasses error), exposes `verify_credentials` for the login route (which has no session, so no store), and `create_folder` raises `FolderRejected` (it returned a bool the router had to interpret) and checks the SUBSCRIBE status as well as CREATE; dialling policy lives in `mail_dial`. Reads LIST with `imapclient`'s grammar and mUTF-7 codec, never a regex (`.12`) — the regex dropped NIL-delimiter rows, truncated names at an escaped quote, and raised TypeError on a literal — and a refused LIST raises rather than returning an empty listing (`AUTHENTICATIONFAILED` -> `AuthFailed`, anything else -> `MailServerUnavailable`). Named for the seam, not the protocol |
| `fetch_grak_script.py` | Standalone utility to pull scripts off a real server into `test_scripts/`. Not imported by the app |
| `requirements.txt` | Runtime dependencies: fastapi, uvicorn, sievelib, imapclient, python-multipart |
| `requirements-dev.txt` | pytest, pytest-asyncio, httpx, ruff, basedpyright, pre-commit |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `routers/` | One module per URL area: `auth`, `scripts`, `folders`, `health`, `static`. Do NOT cross-import between routers — shared helpers belong in `dependencies.py` |
| `tests/` | 26 pytest files plus a shared conftest.py and `fakes.py` (in-memory ScriptStore/FolderStore), mostly regression locks tied to a bead id in the module docstring |
| `test_scripts/` | Sample Sieve scripts used as round-trip fixtures (see `test_scripts/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Router registration order matters: the static router ends with a catch-all `GET /{full_path:path}`, so every real route must be included before it or the SPA fallback swallows it.
- Endpoints use sync `def` (not `async def`) by convention; `import_script` is sync so a slow ManageSieve PUT runs in the threadpool instead of blocking the event loop (see `tests/test_import_event_loop.py`). `auth_status` is the only intentionally-async handler.
- Outbound IMAP TLS is verified by default. `AYS_IMAP_INSECURE=1` (or `true` / `yes`) skips chain + hostname verification for self-signed test setups and logs a warning — never set this in production (CWE-295).
- Auth: `get_session` from `dependencies.py`, as a `Depends` — routers receive the session, they do not fetch it
- ManageSieve/IMAP ops arrive as an injected seam: `store: ScriptStore = Depends(get_script_store)`. The dependency owns the `with`, so handlers never construct an adapter — and a test substitutes with `app.dependency_overrides[get_script_store] = lambda: fake` rather than patching `SieveClient.__enter__`
- **Never read `config.settings()` below `create_app`.** Take `cfg: Settings = Depends(get_settings)`, or receive it as an argument. `mail_dial` reading the process global is what made four of nine Settings fields inert when passed to `create_app` — the app honoured them and the connection did not (`tests/test_config_reaches_the_dial.py`)
- **Never construct a connection directly.** Go through `mail_dial.open_imap` / `open_sieve`; a hand-built `imaplib.IMAP4_SSL(host, …)` re-resolves DNS after the rebinding guard and reopens a TOCTOU. `tests/test_mail_dial.py` greps the source tree to enforce this.
- **Never import a protocol library outside the dial and its adapters.** `imaplib`, `sievelib`, `imapclient`, `ssl` and `socket` are allowlisted per module in `tests/test_mail_dial.py` (`_MAY_IMPORT`). A module that cannot import them cannot speak them — which is what the older call-denylist missed: `routers/auth.py` imported `imaplib`, passed the lock because it did not dial, and grew a private ladder mapping protocol errors to statuses. If you need the conversation, put it behind `ScriptStore`/`FolderStore`, do not widen the allowlist.
- Request bodies use Pydantic `BaseModel` subclasses from `api_models.py`
- All mutating endpoints return `{"ok": True, ...}`
- Errors caused by the REQUEST map to 4xx, never 5xx: `HostValidationError` and `ProtocolNameError` have app-level handlers covering every sink. Do NOT add a local `except ValueError` in a router — it would turn unrelated `ValueError`s into user-input errors. Failures originating UPSTREAM keep a 5xx that says so (`MailServerUnavailable` → 502, `QuotaExceeded` → 507); what must never happen is an upstream failure surfacing as a bare 500 that reads like our own bug.
- The transport RAISES as well as returning falsy. `mail_dial` wraps both dials in `transport_failures_are_semantic`, and the adapters map their library's own exceptions (`imaplib.IMAP4.abort` before `IMAP4.error` — abort subclasses error). A `ConnectionRefusedError` reaching a handler is a 500 that blames this app for the mail server being down.
- Mail-server failures raise from `mail_errors.py`; `app.py`'s `_MAIL_ERROR_STATUS` table maps each to its status, registered once on the `MailStoreError` base. Routers keep no `try/except` — add the status to the table, not a handler to the router.

### Sieve Transform Pipeline
1. **Parse**: `SieveParser` walks Sieve text line-by-line, producing `Rule` objects
2. **Preserve**: Unrecognized constructs become `RawBlock` (opaque, preserved verbatim)
3. **Generate**: `SieveGenerator` renders rules back to Sieve, auto-computing `require` extensions
4. **Order**: `SieveScript.entries` is ONE ordered sequence of `Rule | RawBlock` — position IS the evaluation order. `.rules` and `.raw_blocks` are read-only filtered views. There is no separate `order` array; the parallel-array representation it replaced could drop a rule on save when the arrays disagreed.

### Testing Requirements
- `cd backend && python -m pytest tests/ -v` — 26 files. Install with `pip install -r requirements.txt -r requirements-dev.txt`.
- Lint/format: `ruff check backend/` and `ruff format --check backend/`. CI runs both.
- Round-trip fidelity is asserted as a *fixed point* over every `test_scripts/*.sieve` fixture, in both text and AST. Counting rules is not sufficient — count-only assertions stayed green while action order silently changed.
- Regression tests name the bead they lock in their module docstring; keep that convention when adding one.
- Prefer `tests/fakes.py`'s in-memory stores over mocks for route tests: they hold real state, so a test asserts what a request LEFT BEHIND rather than which methods were called, and `reject_next(...)` arms a specific failure. Pass `validate=True` to run sievelib over anything PUT — an independent oracle, deliberately not our own parser, since checking our generator with our parser only proves the two agree. It is opt-in because sievelib rejects `include`, `addheader` and `spamtest`, which real servers accept.

### Common Patterns
- Python dataclasses for domain models, Pydantic for API schemas
- Fresh connection per request (no connection pooling)
- Guards reject *before* the sink, so a malformed value never reaches the wire

## Dependencies

### External
- `fastapi` + `uvicorn` — Web framework and ASGI server
- `sievelib` — ManageSieve protocol client (its AST is NOT used; the parser is hand-rolled)
- `imapclient` — IMAP grammar + modified-UTF-7 codec ONLY: `response_parser.parse_response`,
  `imap_utf7`, and `ProtocolError` (the grammar's own failure; it does not subclass
  ValueError, so catching the parser needs the name). `imapclient.IMAPClient` is NOT used —
  imaplib remains the transport, and `_RAW_DIAL_CALLS` in `tests/test_mail_dial.py` enforces it
- `python-multipart` — File upload handling for the import endpoint

<!-- MANUAL: -->
