<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-04-08 -->

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
- Bind detail-panel fields through `script.entries[selectedEntryIdx].…`, not through the `$:`-derived `rules` array — binding into a derived value gets overwritten on recompute and the preview goes stale
- `RawEditor` works with raw Sieve text, bypassing the JSON transform pipeline

### Common Patterns
- Views read from stores on mount and call `api.*` methods for backend operations
- `markDirty()` pattern tracks unsaved changes with confirmation on navigation

## Dependencies

### Internal
- `lib/stores.js` — App state
- `lib/api.js` — Backend calls
- `lib/sortable.js` — Drag-and-drop (RuleEditor)
- `lib/utils.js` — Array utilities (RuleEditor)
- `components/` — ConditionBuilder, ActionBuilder, FolderPicker

<!-- MANUAL: -->
