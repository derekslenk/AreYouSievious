# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Frontend
cd frontend && npm install            # install deps
cd frontend && npm run dev             # dev server on :5173 (proxies /api to :8091)
cd frontend && npm run build           # production build -> frontend/dist/

# Backend
cd backend && pip install -r requirements.txt
cd backend && python app.py --port 8091 --static ../frontend/dist

# Docker
docker compose up --build
```

No test suite, linter, or formatter is configured.

## Architecture

Self-hosted Sieve email filter management UI. Single-process FastAPI backend serves the Svelte SPA as static files and proxies ManageSieve/IMAP to the user's mail server. No database — all state lives on the mail server. No stored credentials — session-only with in-memory encrypted creds (30 min timeout).

### Request flow

Browser → FastAPI REST API → ManageSieve (port 4190) / IMAP (port 993) → Mail server

Every API call extracts a session token from the `ays_session` cookie (or `Authorization: Bearer` header), looks up in-memory credentials, and opens a fresh ManageSieve/IMAP connection via context managers (`SieveClient`, `IMAPClient`). Connections are not pooled.

### Sieve transform pipeline

The core complexity is bidirectional Sieve ↔ JSON conversion in `backend/sieve_transform.py`:

1. **Parse**: Hand-rolled `SieveParser` (not sievelib's AST) walks Sieve text line-by-line, recognizing `if/elsif` blocks as `Rule` objects
2. **Preserve**: Anything not recognized becomes a `RawBlock` (opaque text preserved verbatim)
3. **Generate**: `SieveGenerator` renders rules back to Sieve text, auto-computing `require` extensions
4. **Order**: `SieveScript.order` tracks interleaved sequence of `("rule", idx)` / `("raw", idx)` tuples to maintain original script ordering

The round-trip must be lossless for supported constructs — never destroy Sieve the parser doesn't understand.

### Data model (backend/sieve_transform.py)

`SieveScript` → contains `Rule[]`, `RawBlock[]`, `order[]`
`Rule` → `Condition[]` + `Action[]` with match type (anyof/allof)
`Condition` → header/address test with match_type (contains/is/matches/regex)
`Action` → fileinto, fileinto_copy, redirect, keep, discard, stop, addflag, reject

### Frontend routing

`App.svelte` uses a `view` store (`login` | `dashboard` | `editor` | `raw`) for client-side routing — no router library. The `api.js` client auto-dispatches `ays:logout` custom events on 401 responses.

### Backend endpoint conventions

- Endpoints use sync `def` (not `async def`) — exception: `auth_status` and `import_script` which need `await`
- Auth: `get_session(request)` extracts/validates session, raises HTTP 401
- ManageSieve/IMAP ops use context managers: `with SieveClient(session) as client:`
- Request bodies use Pydantic `BaseModel` subclasses
- All mutating endpoints return `{"ok": True, ...}`

## Key conventions

- Python: dataclasses for domain models, Pydantic for API request schemas
- Svelte 5 with plain JavaScript (no TypeScript)
- Frontend state via Svelte writable stores in `lib/stores.js`
- Vite dev server proxies `/api` to backend at `:8091`
