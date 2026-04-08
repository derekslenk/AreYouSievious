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
- `RuleEditor` is the most complex view — manages `script.order` metadata for interleaved rule/raw block positioning
- `Dashboard` buttons are always rendered but disabled for active scripts
- `RuleEditor` patches ephemeral IDs onto conditions/actions in `onMount` for keyed rendering
- Bind conditions/actions directly to `script.rules[selectedIdx].conditions` (not via `@const` alias) to ensure two-way binding propagates correctly
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
