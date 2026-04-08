<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-04-08 -->

# components

## Purpose
Reusable UI components used within the rule editor for building filter conditions, actions, and selecting folders.

## Key Files
| File | Description |
|------|-------------|
| `ConditionBuilder.svelte` | Editable list of email filter conditions (header, match type, value) with drag-and-drop reordering |
| `ActionBuilder.svelte` | Editable list of actions (fileinto, redirect, keep, etc.) with drag-and-drop reordering and folder picker integration |
| `FolderPicker.svelte` | Modal dialog for browsing and selecting IMAP folders |

## For AI Agents

### Working In This Directory
- Components use `bind:` for two-way data flow with parent (`RuleEditor`)
- Events dispatched: `change` (data modified), `pickfolder` (folder picker requested)
- Conditions and actions have ephemeral client-side `id` fields for keyed `{#each}` blocks (not persisted to backend)
- Drag-and-drop via `use:sortable` action from `lib/sortable.js`; arrow buttons as keyboard fallback
- `ConditionBuilder` auto-sets `address_test` based on header type

### Common Patterns
- `createEventDispatcher()` for parent communication
- `arrayMove()` from `lib/utils.js` for reordering
- Scoped CSS with `:global()` for SortableJS dynamic classes

## Dependencies

### Internal
- `lib/sortable.js` — Drag-and-drop Svelte action
- `lib/utils.js` — `arrayMove` utility

<!-- MANUAL: -->
