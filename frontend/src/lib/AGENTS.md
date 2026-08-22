<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# lib

## Purpose
Shared utilities, state management, and API client used across all frontend components and routes.

## Key Files
| File | Description |
|------|-------------|
| `api.js` | HTTP client wrapping `fetch` for all backend endpoints. Fails with `ApiError` carrying `.status` and `.preAuth`, so no caller reads a status out of a message; auto-dispatches `ays:logout` on 401 EXCEPT for `PRE_AUTH_PATHS` (`/auth/login`), where a 401 is a refused password rather than an expired session (`.21`) |
| `stores.js` | Svelte writable stores: `user`, `scripts`, `currentScript`, `currentScriptName`, `folders`, `view`, `toast` |
| `sortable.js` | Svelte action wrapping SortableJS; handles DOM revert so Svelte `{#each}` reconciles from data |
| `scriptDocument.js` | Owns the editable Script: `fromWire`/`toWire`, `ruleEntries`, mutations (`addRule`/`deleteRule`/`moveRule`, `updateEntry`/`setConditions`/`setActions`, `moveItem`), the Condition/Action vocabularies, `deriveAddressTest`, and `snapshot`/`sameWire` for dirty tracking. Mints render keys and strips them at the wire. Its `Condition`/`Action`/`RuleEntry` typedefs are `@import`ed from `api-types.d.ts` plus a key — the SPA's one binding to the generated schema |
| `api-types.d.ts`, `openapi.json` | **Generated** by `npm run gen:types` from the backend's OpenAPI. Do not hand-edit; CI fails if they are stale |

## For AI Agents

### Working In This Directory
- `api.js` uses cookie-based auth (`ays_session`). All methods are async except
  `exportScript(name)`, which synchronously returns a download URL for `window.open`
- Mutating calls attach `X-CSRF-Token` read from the non-httponly `ays_csrf` cookie;
  safe methods and `/auth/login` are exempt (mirrors `backend/middleware.py`)
- `stores.js` is the single source of truth for app state; `view` store drives routing
- `scriptDocument.js` is the ONLY consumer of `api-types.d.ts`, and that is load-bearing.
  CI checks the generated artifact is CURRENT, never that any code CONSUMES it, so before
  `.18` the hand-written typedefs could drift (they said `address_part: string` where the
  schema pinned a four-value union) and nothing rang. `toWire` is declared to return the
  generated wire types, which makes its whitelist a CHECKED one: it cannot leak a render
  key, and it can no longer silently DROP a field either — add one to `ConditionDTO` and
  this file stops compiling. Verified by doing exactly that
- The closed vocabularies (`match`, `match_type`, action `type`, `address_part`) are
  `Literal`s in the backend DTOs, so they arrive here as unions. `HEADERS` is NOT one:
  headers are free text with `<datalist>` suggestions, because any quoted string is a legal
  Sieve header
- `sortable.js` action: critical to revert SortableJS DOM moves in `onEnd` before calling `onReorder`, so Svelte owns DOM reconciliation
- The `filter` option in sortable excludes buttons from initiating drags

### Common Patterns
- Stores are plain Svelte `writable()` — no complex state library
- API methods return parsed JSON or throw on error
- `scriptDocument.js` mutations are pure: each returns a NEW document so Svelte reactivity
  fires on reassignment. The one carve-out: no-op moves (`moveRule`, `moveItem`) return the
  SAME reference so callers can cheaply detect that nothing happened
- There is NO Sieve generator in the SPA. `previewRule` used to be one — a second
  implementation of `SieveGenerator` that both modules described as having to agree with it
  while nothing checked that it did, and that had diverged five ways. It is deleted;
  `api.previewRule` asks `POST /api/scripts/preview` instead (`.17`). If you find yourself
  about to render Sieve here, that is the bug repeating

<!-- MANUAL: -->
