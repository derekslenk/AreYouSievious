<script>
  import { createEventDispatcher } from 'svelte';
  import { sortable } from '../lib/sortable.js';
  import { ACTION_TYPES, actionSpec, moveItem, newAction } from '../lib/scriptDocument.js';
  export let actions = [];
  const dispatch = createEventDispatcher();

  // Never mutates `actions` — every edit dispatches a fresh array upward.
  function emit(next) { dispatch('update', next); }

  function addAction() { emit([...actions, newAction()]); }

  function removeAction(idx) { emit(actions.filter((_, i) => i !== idx)); }

  function reorderAction(oldIndex, newIndex) {
    const next = moveItem(actions, oldIndex, newIndex);
    if (next !== actions) emit(next);
  }

  function moveAction(idx, dir) { reorderAction(idx, idx + dir); }

  /** Patch one action, leaving the rest untouched. */
  function patch(idx, fields) {
    emit(actions.map((a, i) => (i === idx ? { ...a, ...fields } : a)));
  }

  function pickFolder(actionKey) {
    // The picker is modal, so `actions` cannot change before the callback.
    dispatch('pickfolder', (folder) => {
      emit(actions.map((a) => (a.key === actionKey ? { ...a, argument: folder } : a)));
    });
  }
</script>

<div class="actions" use:sortable={{ handle: '.drag-handle', onReorder: reorderAction }}>
  {#each actions as action, i (action.key)}
    <div class="action-row">
      <span class="drag-handle" aria-hidden="true" title="Drag to reorder">&#9776;</span>

      <select value={action.type} on:change={(e) => patch(i, { type: e.currentTarget.value })}>
        {#each ACTION_TYPES as at}
          <option value={at.value}>{at.label}</option>
        {/each}
      </select>

      {#if actionSpec(action.type)?.hasArg}
        <input type="text" value={action.argument} on:input={(e) => patch(i, { argument: e.currentTarget.value })} placeholder={actionSpec(action.type)?.placeholder ?? 'value'} />
        {#if action.type.startsWith('fileinto')}
          <button class="btn-xs" on:click={() => pickFolder(action.key)} title="Browse folders">&#128193;</button>
        {/if}
      {/if}

      <div class="row-controls">
        <button class="btn-xs" on:click={() => moveAction(i, -1)} disabled={i === 0} title="Move up">&#9650;</button>
        <button class="btn-xs" on:click={() => moveAction(i, 1)} disabled={i === actions.length - 1} title="Move down">&#9660;</button>
        <button class="btn-xs btn-danger" on:click={() => removeAction(i)} title="Remove">&#10005;</button>
      </div>
    </div>
  {/each}
</div>

<button class="btn-sm" on:click={addAction}>+ Add Action</button>

<style>
  .actions { display: flex; flex-direction: column; gap: 0.4rem; }
  .action-row { display: flex; gap: 0.35rem; align-items: center; }
  .action-row select, .action-row input {
    padding: 0.4rem 0.5rem; border-radius: 5px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text);
    font-size: 0.8rem;
  }
  .action-row select { width: 180px; }
  .action-row input { flex: 1; min-width: 150px; }
  .drag-handle {
    cursor: grab; opacity: 0.3; user-select: none;
    font-size: 0.8rem; flex-shrink: 0;
  }
  .drag-handle:hover { opacity: 0.7; }
  .drag-handle:active { cursor: grabbing; }
  .row-controls { display: flex; gap: 0.15rem; flex-shrink: 0; }
  :global(.sortable-ghost) {
    opacity: 0.3; background: var(--accent); border-radius: 5px;
  }
  .btn-xs {
    padding: 0.2rem 0.4rem; font-size: 0.7rem; border-radius: 4px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text);
    cursor: pointer;
  }
  .btn-sm {
    padding: 0.35rem 0.7rem; font-size: 0.8rem; border-radius: 5px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text);
    cursor: pointer; margin-top: 0.35rem; width: fit-content;
  }
</style>
