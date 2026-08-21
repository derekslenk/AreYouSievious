<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# routes

## Purpose
Page-level view components, each representing a top-level screen in the app. Routed via the `view` store in `App.svelte`.

## Key Files
| File | Description |
|------|-------------|
| `Login.svelte` | Authentication form: mail server host, username, password, optional custom ports |
| `Dashboard.svelte` | Script management: list, create, import, export, activate, delete scripts |
| `RuleEditor.svelte` | Visual rule editor: left panel (draggable rule list), right panel (selected rule detail with conditions/actions) |
| `RawEditor.svelte` | Raw Sieve text editor with dirty tracking |
| `Privacy.svelte` | Static privacy policy page |

## For AI Agents

### Working In This Directory
- `RuleEditor` renders and tracks selection only — the document and every mutation live in `lib/scriptDocument.js`. Do not reintroduce document logic here; it is untestable in a `.svelte` file (no jsdom, no `@testing-library/svelte`)
- `Dashboard` buttons are always rendered but disabled for active scripts
- Render keys are minted by `scriptDocument` and stripped at the wire. Never send them: the DTOs are `extra="forbid"` and will 422 (see `docs/adr/0001-identity-is-view-state.md`)
- Detail-panel edits patch through `script.entries[selectedEntryIdx]` via scriptDocument setters (`value=` + handler, never `bind:`) — an edit into the `$:`-derived `rules` array would be overwritten on recompute
- `RawEditor` works with raw Sieve text, bypassing the JSON transform pipeline

### Common Patterns
- Views read from stores on mount and call `api.*` methods for backend operations
- Dirty is derived: `sameWire(script, pristine)` against the snapshot taken at load, refreshed on save; navigation confirms while it reports a divergence

## Dependencies

### Internal
- `lib/stores.js` — App state
- `lib/api.js` — Backend calls
- `lib/sortable.js` — Drag-and-drop (RuleEditor)
- `components/` — ConditionBuilder, ActionBuilder, FolderPicker

<!-- MANUAL: -->
