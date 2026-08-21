<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# docs

## Purpose
Project documentation: architecture notes, decision records, agent-skill configuration, and the UI screenshots used by the README.

## Key Files
| File | Description |
|------|-------------|
| `ARCHITECTURE.md` | Long-form architecture write-up. **Partly stale** — tracked by `bd:areyousievious-8au` (dead file references, a `/api/test` endpoint that was never built, and a rule shape carrying an `id` that ADR-0001 removed) |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `adr/` | Numbered architecture decision records. `0001-identity-is-view-state.md` governs the wire format |
| `agents/` | Agent-skill configuration: `issue-tracker.md` (beads), `triage-labels.md`, `domain.md` |
| `screenshots/` | UI screenshots used in README (login, dashboard, rule editor) |

## For AI Agents

### Working In This Directory
- The canonical agent instructions are `AGENTS.md` at the repo root. `CLAUDE.md` is a pointer to it and must stay that way — do not add instructions to `CLAUDE.md` or the two will drift
- Read `adr/` before changing anything it governs, and surface the conflict explicitly rather than silently overriding a decision
- Update screenshots after significant UI changes
- Prefer a new ADR over editing `ARCHITECTURE.md` when recording a decision; ADRs are dated and immutable, the architecture doc is prose that rots

<!-- MANUAL: -->
