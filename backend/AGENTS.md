<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-04-08 -->

# backend

## Purpose
FastAPI application that serves the Svelte SPA as static files and provides a REST API proxying ManageSieve and IMAP operations to the user's mail server. Contains the bidirectional Sieve-to-JSON transform pipeline.

## Key Files
| File | Description |
|------|-------------|
| `app.py` | FastAPI app: auth endpoints, script CRUD, folder operations, static file serving |
| `auth.py` | Session management with in-memory encrypted credentials (30 min timeout) |
| `sieve_transform.py` | Core Sieve parser (`SieveParser`), generator (`SieveGenerator`), and data models (`Rule`, `Condition`, `Action`, `SieveScript`) |
| `managesieve_client.py` | `SieveClient` context manager for ManageSieve protocol (port 4190) |
| `imap_client.py` | `IMAPClient` context manager for IMAP operations (port 993) |
| `fetch_grak_script.py` | Utility to fetch a Sieve script from a server for testing |
| `requirements.txt` | Python dependencies (FastAPI, uvicorn, cryptography, etc.) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `test_scripts/` | Sample Sieve scripts from various mail clients for parser testing (see `test_scripts/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Endpoints use sync `def` (not `async def`) except `auth_status` and `import_script`
- Auth: `get_session(request)` extracts/validates session, raises HTTP 401
- ManageSieve/IMAP ops use context managers: `with SieveClient(session) as client:`
- Request bodies use Pydantic `BaseModel` subclasses
- All mutating endpoints return `{"ok": True, ...}`

### Sieve Transform Pipeline
1. **Parse**: `SieveParser` walks Sieve text line-by-line, producing `Rule` objects
2. **Preserve**: Unrecognized constructs become `RawBlock` (opaque, preserved verbatim)
3. **Generate**: `SieveGenerator` renders rules back to Sieve, auto-computing `require` extensions
4. **Order**: `SieveScript.order` tracks interleaved `("rule", idx)` / `("raw", idx)` for original ordering

### Testing Requirements
- No automated tests; test by running `python app.py --port 8091`
- Use `test_scripts/*.sieve` for parser round-trip verification

### Common Patterns
- Python dataclasses for domain models, Pydantic for API request schemas
- Fresh connection per request (no connection pooling)

## Dependencies

### External
- `fastapi` + `uvicorn` — Web framework and ASGI server
- `cryptography` — Fernet encryption for session credentials
- `python-multipart` — File upload handling

<!-- MANUAL: -->
