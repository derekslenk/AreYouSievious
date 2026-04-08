<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-04-08 -->

# frontend

## Purpose
Svelte 5 single-page application for visual Sieve email filter management. Provides login, script dashboard, visual rule editor with drag-and-drop, and raw Sieve text editing.

## Key Files
| File | Description |
|------|-------------|
| `index.html` | Entry HTML shell |
| `package.json` | Dependencies: Svelte 5, Vite 7, SortableJS |
| `vite.config.js` | Vite config with Svelte plugin; dev proxy `/api` to `:8091` |
| `svelte.config.js` | Svelte compiler options |
| `jsconfig.json` | JS/IDE path configuration |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `src/` | Application source code (see `src/AGENTS.md`) |

## For AI Agents

### Working In This Directory
- Run `npm install` after dependency changes
- `npm run dev` starts dev server on `:5173` with proxy to backend
- `npm run build` produces production build in `dist/`
- Uses Svelte 4 compat syntax (`export let`, `$:`, `on:click`) despite Svelte 5 being installed
- Plain JavaScript — no TypeScript

### Testing Requirements
- No test framework configured; verify with `npm run build` (zero errors)
- Manual testing via dev server

## Dependencies

### External
- `svelte` ^5.45.2 — UI framework
- `vite` ^7.3.1 — Build tool
- `sortablejs` ^1.15.7 — Drag-and-drop reordering

<!-- MANUAL: -->
