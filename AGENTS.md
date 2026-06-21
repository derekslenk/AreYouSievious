<!-- Generated: 2026-04-08 | Updated: 2026-04-08 -->

# AreYouSievious

## Purpose
Self-hosted Sieve email filter management UI. Single-process FastAPI backend serves a Svelte SPA and proxies ManageSieve/IMAP to the user's mail server. No database — all state lives on the mail server. Session-only auth with in-memory credentials (plaintext for session lifetime; expects a single-tenant host).

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

<!-- lean-ctx -->
## lean-ctx

Prefer lean-ctx MCP tools over native equivalents for token savings:
`ctx_read` > Read/cat, `ctx_search` > Grep/rg, `ctx_shell` > bash, `ctx_tree` > ls/find.
Native Edit/Write/Glob stay as-is; use `ctx_edit` only when Edit needs an unavailable Read.
Full rules: LEAN-CTX.md (open on demand — do not auto-load).
<!-- /lean-ctx -->

<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:970c3bf2 -->
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
   bd dolt push
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->

<!-- BEGIN BEADS CODEX SETUP: generated by bd setup codex -->
## Beads Issue Tracker

Use Beads (`bd`) for durable task tracking in repositories that include it. Use the `beads` skill at `.agents/skills/beads/SKILL.md` (project install) or `~/.agents/skills/beads/SKILL.md` (global install) for Beads workflow guidance, then use the `bd` CLI for issue operations.

### Quick Reference

```bash
bd ready                # Find available work
bd show <id>            # View issue details
bd update <id> --claim  # Claim work
bd close <id>           # Complete work
bd prime                # Refresh Beads context
```

### Rules

- Use `bd` for all task tracking; do not create markdown TODO lists.
- Run `bd prime` when Beads context is missing or stale. Codex 0.129.0+ can load Beads context automatically through native hooks; use `/hooks` to inspect or toggle them.
- Keep persistent project memory in Beads via `bd remember`; do not create ad hoc memory files.

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.
<!-- END BEADS CODEX SETUP -->
