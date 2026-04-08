<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-04-08 -->

# src

## Purpose
Svelte application source. Contains the root component, global styles, and organized subdirectories for routes, reusable components, and shared libraries.

## Key Files
| File | Description |
|------|-------------|
| `App.svelte` | Root component; uses `view` store for client-side routing (`login`, `dashboard`, `editor`, `raw`) |
| `app.css` | Global CSS variables and base styles (dark theme) |
| `main.js` | App entry point; mounts `App.svelte` to `#app` |

## Subdirectories
| Directory | Purpose |
|-----------|---------|
| `routes/` | Page-level view components (see `routes/AGENTS.md`) |
| `components/` | Reusable UI components (see `components/AGENTS.md`) |
| `lib/` | Shared utilities, stores, and API client (see `lib/AGENTS.md`) |
| `assets/` | Static assets (SVG icons) |

## For AI Agents

### Working In This Directory
- Routing is store-based (`view` writable store), not a router library
- Auto-logout on 401 via `ays:logout` custom event in `api.js`
- All components use Svelte 4 syntax patterns

## Dependencies

### Internal
- `lib/stores.js` — All shared state
- `lib/api.js` — Backend communication

<!-- MANUAL: -->
