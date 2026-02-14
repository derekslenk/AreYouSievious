<script>
  import { createEventDispatcher } from 'svelte';
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
    actions = [...actions, { type: 'fileinto', argument: '' }];
    dispatch('change');
  }

  function removeAction(idx) {
    actions = actions.filter((_, i) => i !== idx);
    dispatch('change');
  }

  function onChange() { dispatch('change'); }

  function pickFolder(idx) {
    dispatch('pickfolder', (folder) => {
      actions[idx].argument = folder;
      actions = [...actions];
      dispatch('change');
    });
  }

  function needsArg(type) {
    return ACTION_TYPES.find(a => a.value === type)?.hasArg ?? false;
  }
</script>

<div class="actions">
  {#each actions as action, i}
    <div class="action-row">
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
          <button class="btn-xs" on:click={() => pickFolder(i)} title="Browse folders">&#128193;</button>
        {/if}
      {/if}

      <button class="btn-xs btn-danger" on:click={() => removeAction(i)} title="Remove">&#10005;</button>
    </div>
  {/each}

  <button class="btn-sm" on:click={addAction}>+ Add Action</button>
</div>

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
