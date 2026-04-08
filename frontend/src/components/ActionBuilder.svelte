<script>
  import { createEventDispatcher } from 'svelte';
  import { sortable } from '../lib/sortable.js';
  import { arrayMove } from '../lib/utils.js';
  export let actions = [];
  const dispatch = createEventDispatcher();

  const ACTION_TYPES = [
    { value: 'fileinto', label: 'Move to folder', hasArg: true },
    { value: 'fileinto_copy', label: 'Copy to folder', hasArg: true },
    { value: 'redirect', label: 'Redirect to', hasArg: true },
    { value: 'keep', label: 'Keep in INBOX', hasArg: false },
    { value: 'discard', label: 'Delete', hasArg: false },
    { value: 'stop', label: 'Stop processing', hasArg: false },
    { value: 'addflag', label: 'Add flag', hasArg: true },
    { value: 'reject', label: 'Reject with message', hasArg: true },
  ];

  function addAction() {
    actions = [...actions, { id: Math.random().toString(36).slice(2, 10), type: 'fileinto', argument: '' }];
    dispatch('change');
  }

  function removeAction(idx) {
    actions = actions.filter((_, i) => i !== idx);
    dispatch('change');
  }

  function reorderAction(oldIndex, newIndex) {
    actions = arrayMove(actions, oldIndex, newIndex);
    dispatch('change');
  }

  function moveAction(idx, dir) {
    const newIdx = idx + dir;
    if (newIdx < 0 || newIdx >= actions.length) return;
    reorderAction(idx, newIdx);
  }

  function onChange() { dispatch('change'); }

  function pickFolder(actionId) {
    dispatch('pickfolder', (folder) => {
      const target = actions.find(a => a.id === actionId);
      if (target) {
        target.argument = folder;
        actions = [...actions];
        dispatch('change');
      }
    });
  }

  function needsArg(type) {
    return ACTION_TYPES.find(a => a.value === type)?.hasArg ?? false;
  }
</script>

<div class="actions" use:sortable={{ handle: '.drag-handle', onReorder: reorderAction }}>
  {#each actions as action, i (action.id)}
    <div class="action-row">
      <span class="drag-handle" aria-hidden="true" title="Drag to reorder">&#9776;</span>

      <select bind:value={action.type} on:change={onChange}>
        {#each ACTION_TYPES as at}
          <option value={at.value}>{at.label}</option>
        {/each}
      </select>

      {#if needsArg(action.type)}
        <input type="text" bind:value={action.argument} on:input={onChange} placeholder={
          action.type.startsWith('fileinto') ? 'Folder name' :
          action.type === 'redirect' ? 'email@example.com' :
          action.type === 'addflag' ? '\\Seen' : 'value'
        } />
        {#if action.type.startsWith('fileinto')}
          <button class="btn-xs" on:click={() => pickFolder(action.id)} title="Browse folders">&#128193;</button>
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
