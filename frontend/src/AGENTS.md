<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# src

## Purpose
Svelte application source. Contains the root component, global styles, and organized subdirectories for routes, reusable components, and shared libraries.

## Key Files
| File | Description |
|------|-------------|
| `App.svelte` | Root component. Store-based routing, lazy route loading, toast rendering, footer, and the global `:root` CSS custom properties (dark theme) |
| `app.css` | Placeholder only — a single comment. The real global styles live in `App.svelte` under `:global(...)` |
| `main.js` | App entry point; mounts `App.svelte` to `#app` via Svelte 5's `mount()` |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `routes/` | Page-level view components (see `routes/AGENTS.md`) |
| `components/` | Reusable UI components (see `components/AGENTS.md`) |
| `lib/` | Shared utilities, stores, API client, and the editable-document module (see `lib/AGENTS.md`) |
| `assets/` | Static assets (`svelte.svg`) |

## For AI Agents

### Working In This Directory
- Routing is store-based (`view` writable store), not a router library. Values: `login`, `dashboard`, `editor`, `raw`, `privacy`
- Only `Login` is imported eagerly. Every other route is lazy — `{#await import('./routes/X.svelte')}` with loading and error branches. Adding a route means adding a branch, not build config
- `view.subscribe` pushes history state and a `popstate` listener restores it, so browser back/forward works. The `skipPush` flag prevents a restore from re-pushing
- Auto-logout on 401 via the `ays:logout` custom event dispatched from `api.js` — EXCEPT on a pre-auth path (`/auth/login`), where a 401 means the credentials were refused and there is no session to end (`.21`)

## Dependencies

### Internal
- `lib/stores.js` — All shared state
- `lib/api.js` — Backend communication

<!-- MANUAL: -->
