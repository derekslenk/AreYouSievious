<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# frontend

## Purpose
Svelte 5 single-page application for visual Sieve email filter management. Provides login, script dashboard, visual rule editor with drag-and-drop, and raw Sieve text editing.

## Key Files
| File | Description |
|------|-------------|
| `index.html` | Entry HTML shell |
| `package.json` | Dependencies and the `dev` / `build` / `test` / `check` / `gen:types` scripts |
| `vite.config.js` | Vite config with Svelte plugin; dev proxy `/api` to `:8091`; `manualChunks` pulls the Svelte runtime into a cached `vendor` chunk |
| `svelte.config.js` | Svelte compiler options |
| `jsconfig.json` | JS/IDE path configuration; `checkJs` is on and `npm run check` fails on warnings |

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
- Plain JavaScript — no TypeScript. The only `.d.ts` is generated (`src/lib/api-types.d.ts`)
- Routes are lazy-loaded via `{#await import(...)}` in `App.svelte`, so a new route needs no build config — just another branch

### Wire types are generated, not hand-written
`src/lib/openapi.json` and `src/lib/api-types.d.ts` are produced by `npm run gen:types`, which shells out to `tools/dump-openapi.py`. Never edit them by hand. CI's `contract` job regenerates both and fails on any diff — that guard exists because a backend `extra="forbid"` change once shipped a two-month HTTP 422 on every visual-editor save.

### Testing Requirements
- `npm test` — Vitest, run once (`vitest run`). Covers `src/lib/*.test.js`
- `npm run check` — svelte-check with `--fail-on-warnings`
- `npm run build` — must complete with zero errors
- There is no jsdom and no `@testing-library/svelte`, so **nothing inside a `.svelte` file is testable**. Logic that needs coverage belongs in a plain `.js` module under `src/lib/` — this is why `scriptDocument.js` exists

## Dependencies

### External
- `svelte` ^5.56.3 — UI framework
- `vite` ^8.0.16 — Build tool
- `vitest` ^4.1.9 — Test runner
- `svelte-check` ^4.1.0 + `typescript` ^5.7.0 — JS type checking
- `openapi-typescript` ^7.5.0 — Wire-type codegen
- `sortablejs` ^1.15.7 — Drag-and-drop reordering (the only runtime dependency)

<!-- MANUAL: -->
