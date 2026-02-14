<script>
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import { view, currentScriptName, showToast } from '../lib/stores.js';

  let content = '';
  let loading = true;
  let saving = false;
  let dirty = false;

  onMount(async () => {
    try {
      const data = await api.getScriptRaw($currentScriptName);
      content = data.content;
    } catch (e) {
      showToast(e.message, 'error');
    } finally {
      loading = false;
    }
  });

  async function save() {
    saving = true;
    try {
      await api.saveScriptRaw($currentScriptName, content);
      showToast('Script saved');
      dirty = false;
    } catch (e) {
      showToast(e.message, 'error');
    } finally {
      saving = false;
    }
  }

  function back() {
    if (dirty && !confirm('Unsaved changes. Leave anyway?')) return;
    view.set('dashboard');
  }

  function onInput() { dirty = true; }
</script>

<div class="raw-editor">
  <header>
    <div class="header-left">
      <button class="btn-sm" on:click={back}>&larr; Back</button>
      <h2>{$currentScriptName} (raw)</h2>
      {#if dirty}<span class="dirty-badge">unsaved</span>{/if}
    </div>
    <button class="btn-sm btn-accent" on:click={save} disabled={saving}>
      {saving ? 'Saving...' : 'Save'}
    </button>
  </header>

  {#if loading}
    <p class="muted">Loading...</p>
  {:else}
    <textarea
      bind:value={content}
      on:input={onInput}
      spellcheck="false"
    ></textarea>
  {/if}
</div>

<style>
  .raw-editor { max-width: 1000px; margin: 0 auto; padding: 1rem; display: flex; flex-direction: column; height: 100vh; }
  header {
    display: flex; justify-content: space-between; align-items: center;
    padding: 0.75rem 0; border-bottom: 1px solid var(--border); margin-bottom: 1rem;
  }
  .header-left { display: flex; align-items: center; gap: 0.75rem; }
  .header-left h2 { margin: 0; font-size: 1.1rem; }
  .dirty-badge { font-size: 0.7rem; color: #f0a030; }
  textarea {
    flex: 1; width: 100%; padding: 1rem; border-radius: 8px;
    border: 1px solid var(--border); background: var(--surface); color: var(--text);
    font-family: 'SF Mono', 'Cascadia Code', monospace; font-size: 0.85rem;
    resize: none; line-height: 1.5; box-sizing: border-box;
  }
  textarea:focus { outline: none; border-color: var(--accent); }
  .muted { color: var(--text2); }
</style>
