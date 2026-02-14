<script>
  import { createEventDispatcher } from 'svelte';
  export let folders = [];
  const dispatch = createEventDispatcher();

  let search = '';
  let newFolder = '';
  let showCreate = false;

  $: filtered = folders.filter(f =>
    f.name.toLowerCase().includes(search.toLowerCase())
  );

  // Build tree structure
  $: tree = buildTree(filtered);

  function buildTree(folders) {
    const nodes = [];
    for (const f of folders) {
      const parts = f.name.split(f.delimiter || '/');
      let current = nodes;
      for (let i = 0; i < parts.length; i++) {
        const name = parts.slice(0, i + 1).join(f.delimiter || '/');
        let existing = current.find(n => n.fullName === name);
        if (!existing) {
          existing = { label: parts[i], fullName: name, children: [] };
          current.push(existing);
        }
        current = existing.children;
      }
    }
    return nodes;
  }

  function select(name) {
    dispatch('select', name);
  }

  function close() {
    dispatch('close');
  }

  async function createFolder() {
    if (!newFolder.trim()) return;
    // TODO: call API to create folder
    select(newFolder.trim());
  }
</script>

<!-- svelte-ignore a11y-click-events-have-key-events -->
<div class="overlay" on:click={close} role="presentation">
  <div class="picker" on:click|stopPropagation role="dialog">
    <div class="picker-header">
      <h3>Select Folder</h3>
      <button class="btn-xs" on:click={close}>&#10005;</button>
    </div>

    <input type="text" bind:value={search} placeholder="Search folders..." class="search" />

    <div class="folder-list">
      {#each filtered as folder}
        <button class="folder-item" on:click={() => select(folder.name)}>
          {folder.name}
        </button>
      {/each}
    </div>

    <div class="picker-footer">
      {#if showCreate}
        <div class="create-row">
          <input type="text" bind:value={newFolder} placeholder="New folder name" />
          <button class="btn-sm btn-accent" on:click={createFolder}>Create</button>
        </div>
      {:else}
        <button class="btn-sm" on:click={() => showCreate = true}>+ New Folder</button>
      {/if}
    </div>
  </div>
</div>

<style>
  .overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,0.5);
    display: flex; align-items: center; justify-content: center; z-index: 100;
  }
  .picker {
    background: var(--surface); border-radius: 10px; padding: 1rem;
    width: 400px; max-height: 70vh; display: flex; flex-direction: column;
  }
  .picker-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; }
  .picker-header h3 { margin: 0; font-size: 1rem; }
  .search {
    width: 100%; padding: 0.5rem 0.6rem; border-radius: 6px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text);
    margin-bottom: 0.5rem; box-sizing: border-box;
  }
  .folder-list { overflow-y: auto; flex: 1; max-height: 400px; }
  .folder-item {
    display: block; width: 100%; text-align: left; padding: 0.4rem 0.6rem;
    border: none; background: none; color: var(--text); cursor: pointer;
    border-radius: 4px; font-size: 0.85rem;
  }
  .folder-item:hover { background: var(--bg); }
  .picker-footer { margin-top: 0.5rem; padding-top: 0.5rem; border-top: 1px solid var(--border); }
  .create-row { display: flex; gap: 0.5rem; }
  .create-row input { flex: 1; padding: 0.4rem; border-radius: 5px; border: 1px solid var(--border); background: var(--bg); color: var(--text); }
  .btn-xs {
    padding: 0.2rem 0.4rem; font-size: 0.7rem; border-radius: 4px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text); cursor: pointer;
  }
  .btn-sm {
    padding: 0.35rem 0.7rem; font-size: 0.8rem; border-radius: 5px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text); cursor: pointer;
  }
</style>
