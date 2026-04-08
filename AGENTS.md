<!-- Generated: 2026-04-08 | Updated: 2026-04-08 -->

# AreYouSievious

## Purpose
Self-hosted Sieve email filter management UI. Single-process FastAPI backend serves a Svelte SPA and proxies ManageSieve/IMAP to the user's mail server. No database — all state lives on the mail server. Session-only auth with in-memory encrypted credentials.

## Key Files
| File | Description |
|------|-------------|
| `CLAUDE.md` | AI assistant instructions, architecture overview, and dev commands |
| `Dockerfile` | Multi-stage build: Node frontend + Python backend |
| `docker-compose.yml` | Container orchestration with env vars for mail server |
| `README.md` | Project overview, setup, and screenshots |
| `CONTRIBUTING.md` | Contribution guidelines |
| `LICENSE` | MIT license |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `backend/` | FastAPI REST API, ManageSieve/IMAP clients, Sieve parser/generator (see `backend/AGENTS.md`) |
| `frontend/` | Svelte 5 SPA for visual rule editing (see `frontend/AGENTS.md`) |
| `docs/` | Architecture docs and screenshots (see `docs/AGENTS.md`) |
| `.github/` | Issue templates, PR template, CI workflows (see `.github/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- No test suite, linter, or formatter is configured
- Build with `cd frontend && npm run build` to verify frontend changes
- Backend has no automated tests; verify by running `python app.py --port 8091`
- All Sieve state lives on the mail server; no local database to manage

### Request Flow
```
Browser -> FastAPI REST API -> ManageSieve (4190) / IMAP (993) -> Mail server
```

### Key Architectural Constraints
- Connections are not pooled; each API call opens a fresh connection via context managers
- The Sieve parser is hand-rolled (not sievelib); unrecognized constructs become `RawBlock` (preserved verbatim)
- Round-trip must be lossless for supported constructs
- Frontend uses Svelte 4 compat syntax (`export let`, `$:`, `on:click`) despite Svelte 5

<!-- MANUAL: -->
