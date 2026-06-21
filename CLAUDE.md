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

Self-hosted Sieve email filter management UI. Single-process FastAPI backend serves the Svelte SPA as static files and proxies ManageSieve/IMAP to the user's mail server. No database — all state lives on the mail server. No stored credentials — session-only, plaintext in process memory for the session lifetime (30 min timeout). Expects a single-tenant host.

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


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->
