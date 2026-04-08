<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-04-08 -->

# lib

## Purpose
Shared utilities, state management, and API client used across all frontend components and routes.

## Key Files
| File | Description |
|------|-------------|
| `api.js` | HTTP client wrapping `fetch` for all backend endpoints; auto-dispatches `ays:logout` on 401 |
| `stores.js` | Svelte writable stores: `user`, `scripts`, `currentScript`, `currentScriptName`, `folders`, `view`, `toast` |
| `sortable.js` | Svelte action wrapping SortableJS; handles DOM revert so Svelte `{#each}` reconciles from data |
| `utils.js` | `arrayMove(arr, oldIndex, newIndex)` utility for reordering arrays |

## For AI Agents

### Working In This Directory
- `api.js` uses cookie-based auth (`ays_session`); all methods are async
- `stores.js` is the single source of truth for app state; `view` store drives routing
- `sortable.js` action: critical to revert SortableJS DOM moves in `onEnd` before calling `onReorder`, so Svelte owns DOM reconciliation
- The `filter` option in sortable excludes buttons from initiating drags

### Common Patterns
- Stores are plain Svelte `writable()` — no complex state library
- API methods return parsed JSON or throw on error

<!-- MANUAL: -->
