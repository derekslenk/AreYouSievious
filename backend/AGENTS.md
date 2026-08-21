<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# backend

## Purpose
FastAPI application that serves the Svelte SPA as static files and provides a REST API proxying ManageSieve and IMAP operations to the user's mail server. Contains the bidirectional Sieve-to-JSON transform pipeline.

## Key Files
| File | Description |
|------|-------------|
| `app.py` | Composition root only — `create_app(config)` factory wiring exception handlers, middleware stack, and `include_router` calls, plus the CLI entry point. No business logic; routes live in `routers/` |
| `config.py` | Every environment variable, read once into a frozen `Settings`. `settings()` is the process-wide cached instance; inside a request prefer `request.app.state.settings` |
| `dependencies.py` | Shared per-request dependency: `get_session(request)` reads the `ays_session` cookie or Bearer header, raises 401 |
| `api_models.py` | Pydantic request/response DTOs. Every model is `extra="forbid"` with `max_length` caps; `EntryDTO` is a `kind`-discriminated `RuleDTO \| RawBlockDTO` |
| `auth.py` | `SessionManager` holding credentials in process memory (plaintext, 30 min idle timeout). Never persisted |
| `middleware.py` | `BodySizeLimitMiddleware` (Content-Length + streamed-byte cap) and `CSRFMiddleware` (double-submit cookie) |
| `ssrf.py` | SSRF + DNS-rebinding guards. `validate_host` pins an IP at login; `assert_host_resolves_to` re-checks at every connect |
| `protocol_names.py` | `validate_script_name` / `validate_folder_name` / `ProtocolNameError` — one rule for both ManageSieve and IMAP framing, rejected before any protocol call |
| `mail_dial.py` | **The only way to open a mail-server connection.** `open_imap` / `open_sieve` apply the whole dialling policy: rebinding re-check, dial the pinned IP, TLS SNI on the hostname, timeouts |
| `sieve_transform.py` | Core Sieve parser (`SieveParser`), generator (`SieveGenerator`), and data models (`Rule`, `Condition`, `Action`, `RawBlock`, `SieveScript`) |
| `mail_stores.py` | The two mail-server seams as `Protocol`s: `ScriptStore` (list/get/put/activate/delete) and `FolderStore` (list/create). Kept separate — a single seven-operation store would be a union, not an abstraction |
| `mail_errors.py` | The semantic vocabulary the seams fail in (`MailStoreError` + `ScriptNotFound`, `ScriptRejected`, `QuotaExceeded`, `MailServerUnavailable`, `AuthFailed`). Protocol-free AND HTTP-free; `app.py` owns the status mapping |
| `managesieve_client.py` | `SieveClient` context manager for ManageSieve (port 4190). Owns the script operations; dialling policy lives in `mail_dial` |
| `imap_client.py` | `IMAPClient` context manager for IMAP (port 993). Owns what to say once connected; dialling policy lives in `mail_dial` |
| `fetch_grak_script.py` | Standalone utility to pull scripts off a real server into `test_scripts/`. Not imported by the app |
| `requirements.txt` | Runtime dependencies: fastapi, uvicorn, sievelib, python-multipart |
| `requirements-dev.txt` | pytest, pytest-asyncio, httpx, ruff, basedpyright, pre-commit |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `routers/` | One module per URL area: `auth`, `scripts`, `folders`, `health`, `static`. Do NOT cross-import between routers — shared helpers belong in `dependencies.py` |
| `tests/` | 20 pytest files plus a shared conftest.py, mostly regression locks tied to a bead id in the module docstring |
| `test_scripts/` | Sample Sieve scripts used as round-trip fixtures (see `test_scripts/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Router registration order matters: the static router ends with a catch-all `GET /{full_path:path}`, so every real route must be included before it or the SPA fallback swallows it.
- Endpoints use sync `def` (not `async def`) by convention; `import_script` is sync so a slow ManageSieve PUT runs in the threadpool instead of blocking the event loop (see `tests/test_import_event_loop.py`). `auth_status` is the only intentionally-async handler.
- Outbound IMAP TLS is verified by default. `AYS_IMAP_INSECURE=1` (or `true` / `yes`) skips chain + hostname verification for self-signed test setups and logs a warning — never set this in production (CWE-295).
- Auth: `get_session(request)` from `dependencies.py` extracts/validates the session, raises HTTP 401
- ManageSieve/IMAP ops use context managers: `with SieveClient(session) as client:`
- **Never construct a connection directly.** Go through `mail_dial.open_imap` / `open_sieve`; a hand-built `imaplib.IMAP4_SSL(host, …)` re-resolves DNS after the rebinding guard and reopens a TOCTOU. `tests/test_mail_dial.py` greps the source tree to enforce this.
- Request bodies use Pydantic `BaseModel` subclasses from `api_models.py`
- All mutating endpoints return `{"ok": True, ...}`
- Errors caused by the REQUEST map to 4xx, never 5xx: `HostValidationError` and `ProtocolNameError` have app-level handlers covering every sink. Do NOT add a local `except ValueError` in a router — it would turn unrelated `ValueError`s into user-input errors. Failures originating UPSTREAM keep a 5xx that says so (`MailServerUnavailable` → 502, `QuotaExceeded` → 507); what must never happen is an upstream failure surfacing as a bare 500 that reads like our own bug.
- Mail-server failures raise from `mail_errors.py`; `app.py`'s `_MAIL_ERROR_STATUS` table maps each to its status, registered once on the `MailStoreError` base. Routers keep no `try/except` — add the status to the table, not a handler to the router.

### Sieve Transform Pipeline
1. **Parse**: `SieveParser` walks Sieve text line-by-line, producing `Rule` objects
2. **Preserve**: Unrecognized constructs become `RawBlock` (opaque, preserved verbatim)
3. **Generate**: `SieveGenerator` renders rules back to Sieve, auto-computing `require` extensions
4. **Order**: `SieveScript.entries` is ONE ordered sequence of `Rule | RawBlock` — position IS the evaluation order. `.rules` and `.raw_blocks` are read-only filtered views. There is no separate `order` array; the parallel-array representation it replaced could drop a rule on save when the arrays disagreed.

### Testing Requirements
- `cd backend && python -m pytest tests/ -v` — 20 files. Install with `pip install -r requirements.txt -r requirements-dev.txt`.
- Lint/format: `ruff check backend/` and `ruff format --check backend/`. CI runs both.
- Round-trip fidelity is asserted as a *fixed point* over every `test_scripts/*.sieve` fixture, in both text and AST. Counting rules is not sufficient — count-only assertions stayed green while action order silently changed.
- Regression tests name the bead they lock in their module docstring; keep that convention when adding one.

### Common Patterns
- Python dataclasses for domain models, Pydantic for API schemas
- Fresh connection per request (no connection pooling)
- Guards reject *before* the sink, so a malformed value never reaches the wire

## Dependencies

### External
- `fastapi` + `uvicorn` — Web framework and ASGI server
- `sievelib` — ManageSieve protocol client (its AST is NOT used; the parser is hand-rolled)
- `python-multipart` — File upload handling for the import endpoint

<!-- MANUAL: -->
