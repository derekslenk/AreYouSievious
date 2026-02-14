<script>
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { user, scripts, view, currentScriptName, currentScript, showToast } from '../lib/stores.js';

  let loading = true;
  let newName = '';
  let showCreate = false;

  onMount(async () => {
    await loadScripts();
  });

  async function loadScripts() {
    loading = true;
    try {
      scripts.set(await api.listScripts());
    } catch (e) {
      showToast(e.message, 'error');
    } finally {
      loading = false;
    }
  }

  async function openScript(name) {
    try {
      const data = await api.getScript(name);
      currentScript.set(data);
      currentScriptName.set(name);
      view.set('editor');
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  async function openRaw(name) {
    currentScriptName.set(name);
    view.set('raw');
  }

  async function activate(name) {
    try {
      await api.activateScript(name);
      showToast(`${name} activated`);
      await loadScripts();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  async function deleteScript(name) {
    if (!confirm(`Delete script "${name}"?`)) return;
    try {
      await api.deleteScript(name);
      showToast(`${name} deleted`);
      await loadScripts();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  async function createScript() {
    if (!newName.trim()) return;
    try {
      // Create empty script
      await api.saveScriptRaw(newName.trim(), '# New script\n');
      showToast(`${newName} created`);
      newName = '';
      showCreate = false;
      await loadScripts();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  function exportScript(name) {
    window.open(api.exportScript(name), '_blank');
  }

  let importFile = null;
  let importName = '';
  let showImport = false;

  async function handleImport() {
    if (!importFile || !importName.trim()) return;
    try {
      await api.importScript(importName.trim(), importFile);
      showToast(`${importName} imported`);
      importFile = null;
      importName = '';
      showImport = false;
      await loadScripts();
    } catch (e) {
      showToast(e.message, 'error');
    }
  }

  async function logout() {
    await api.logout();
    user.set(null);
    view.set('login');
  }
</script>

<div class="dashboard">
  <header>
    <div class="header-left">
      <h1>AreYouSievious</h1>
      <span class="host">{$user?.host}</span>
    </div>
    <div class="header-right">
      <span class="username">{$user?.username}</span>
      <button class="btn-sm" on:click={logout}>Logout</button>
    </div>
  </header>

  <div class="content">
    <div class="section-header">
      <h2>Scripts</h2>
      <div class="section-actions">
        <button class="btn-sm" on:click={() => showImport = !showImport}>Import</button>
        <button class="btn-sm btn-accent" on:click={() => showCreate = !showCreate}>+ New Script</button>
      </div>
    </div>

    {#if showImport}
      <form class="create-form" on:submit|preventDefault={handleImport}>
        <input type="text" bind:value={importName} placeholder="Script name" />
        <input type="file" accept=".sieve,.txt" on:change={(e) => importFile = e.target.files[0]} />
        <button type="submit" class="btn-sm btn-accent" disabled={!importFile || !importName.trim()}>Upload</button>
        <button type="button" class="btn-sm" on:click={() => showImport = false}>Cancel</button>
      </form>
    {/if}

    {#if showCreate}
      <form class="create-form" on:submit|preventDefault={createScript}>
        <input type="text" bind:value={newName} placeholder="Script name" autofocus />
        <button type="submit" class="btn-sm btn-accent">Create</button>
        <button type="button" class="btn-sm" on:click={() => showCreate = false}>Cancel</button>
      </form>
    {/if}

    {#if loading}
      <p class="muted">Loading...</p>
    {:else}
      <div class="script-list">
        {#each $scripts as script}
          <div class="script-card" class:active={script.active}>
            <div class="script-info">
              <span class="script-name">{script.name}</span>
              {#if script.active}
                <span class="badge">Active</span>
              {/if}
            </div>
            <div class="script-actions">
              <button class="btn-sm" on:click={() => openScript(script.name)}>Edit Rules</button>
              <button class="btn-sm" on:click={() => openRaw(script.name)}>Raw</button>
              <button class="btn-sm" on:click={() => exportScript(script.name)}>Export</button>
              {#if !script.active}
                <button class="btn-sm" on:click={() => activate(script.name)}>Activate</button>
                <button class="btn-sm btn-danger" on:click={() => deleteScript(script.name)}>Delete</button>
              {/if}
            </div>
          </div>
        {/each}
      </div>
    {/if}
  </div>
</div>

<style>
  .dashboard { max-width: 900px; margin: 0 auto; padding: 1rem; }
  header {
    display: flex; justify-content: space-between; align-items: center;
    padding: 1rem 0; border-bottom: 1px solid var(--border); margin-bottom: 1.5rem;
  }
  .header-left h1 { margin: 0; font-size: 1.3rem; }
  .host { color: var(--text2); font-size: 0.8rem; }
  .header-right { display: flex; align-items: center; gap: 0.75rem; }
  .username { color: var(--text2); font-size: 0.85rem; }
  .section-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem; }
  .section-header h2 { margin: 0; font-size: 1.1rem; }
  .section-actions { display: flex; gap: 0.5rem; }
  .create-form { display: flex; gap: 0.5rem; margin-bottom: 1rem; }
  .create-form input {
    flex: 1; padding: 0.5rem 0.75rem; border-radius: 6px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text);
  }
  .script-list { display: flex; flex-direction: column; gap: 0.5rem; }
  .script-card {
    display: flex; justify-content: space-between; align-items: center;
    padding: 0.75rem 1rem; border-radius: 8px; background: var(--surface);
    border: 1px solid var(--border);
  }
  .script-card.active { border-color: var(--accent); }
  .script-info { display: flex; align-items: center; gap: 0.5rem; }
  .script-name { font-weight: 500; }
  .badge {
    font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 4px;
    background: var(--accent); color: #fff;
  }
  .script-actions { display: flex; gap: 0.35rem; }
  .muted { color: var(--text2); }
</style>
