<!-- Parent: ../AGENTS.md -->
<!-- Generated: 2026-04-08 | Updated: 2026-08-20 -->

# components

## Purpose
Reusable UI components used within the rule editor for building filter conditions, actions, and selecting folders.

## Key Files
| File | Description |
|------|-------------|
| `ConditionBuilder.svelte` | Editable list of filter conditions (header, match type, value, NOT) with drag-and-drop reordering |
| `ActionBuilder.svelte` | Editable list of actions (fileinto, redirect, keep, etc.) with drag-and-drop reordering and folder picker integration |
| `FolderPicker.svelte` | Modal dialog for browsing, searching, and creating IMAP folders |

## For AI Agents

### Working In This Directory
- Components use `bind:` for two-way data flow with parent (`RuleEditor`)
- Events dispatched: `change` (data modified), `pickfolder` (folder picker requested), plus `select` / `created` / `close` from `FolderPicker`
- Keyed `{#each}` blocks key on `cond.key` / `action.key`. Those keys are **view state minted by `lib/scriptDocument.js`** (`newCondition()` / `newAction()`) and stripped by `toWire` before saving. Never construct a bare condition or action literal here, and never let a key reach the backend — the DTOs are `extra="forbid"` and will 422 (see `docs/adr/0001-identity-is-view-state.md`)
- Drag-and-drop via `use:sortable` action from `lib/sortable.js`; arrow buttons as keyboard fallback
- `ConditionBuilder` auto-sets `address_test` based on header type (`from`/`to`/`cc`/`reply-to` are address tests)
- `FolderPicker` must actually call `api.createFolder` before selecting a new name — selecting without creating pointed rules at folders that did not exist and delivery failed silently

### Common Patterns
- `createEventDispatcher()` for parent communication
- `arrayMove()` from `lib/utils.js` for reordering
- Scoped CSS with `:global()` for SortableJS dynamic classes

## Dependencies

### Internal
- `lib/scriptDocument.js` — `newCondition` / `newAction` factories
- `lib/sortable.js` — Drag-and-drop Svelte action
- `lib/utils.js` — `arrayMove` utility
- `lib/api.js` + `lib/stores.js` — `FolderPicker` only

<!-- MANUAL: -->
