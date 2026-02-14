<script>
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import {
    view, currentScript, currentScriptName, folders, showToast,
  } from '../lib/stores.js';
  import ConditionBuilder from '../components/ConditionBuilder.svelte';
  import ActionBuilder from '../components/ActionBuilder.svelte';
  import FolderPicker from '../components/FolderPicker.svelte';

  let script = null;
  let selectedIdx = 0;
  let saving = false;
  let dirty = false;
  let folderList = [];
  let showFolderPicker = false;
  let folderPickerCallback = null;

  // Sieve preview of selected rule
  let preview = '';

  onMount(async () => {
    script = $currentScript;
    try {
      folderList = await api.listFolders();
      folders.set(folderList);
    } catch (e) { /* ok */ }
  });

  $: if (script && script.rules[selectedIdx]) {
    preview = generateRulePreview(script.rules[selectedIdx]);
  }

  function generateRulePreview(rule) {
    if (!rule || !rule.conditions.length) return '';
    const tests = rule.conditions.map(c => {
      const t = c.address_test ? 'address' : 'header';
      return `    ${t} :${c.match_type} "${c.header}" "${c.value}"`;
    });
    const acts = rule.actions.map(a => {
      if (a.type === 'fileinto') return `    fileinto "${a.argument}";`;
      if (a.type === 'fileinto_copy') return `    fileinto :copy "${a.argument}";`;
      if (a.type === 'redirect') return `    redirect "${a.argument}";`;
      if (a.type === 'keep') return '    keep;';
      if (a.type === 'discard') return '    discard;';
      if (a.type === 'stop') return '    stop;';
      return `    ${a.type} "${a.argument}";`;
    });

    if (tests.length === 1) {
      return `if ${tests[0].trim()} {\n${acts.join('\n')}\n}`;
    }
    return `if ${rule.match} (\n${tests.join(',\n')}\n) {\n${acts.join('\n')}\n}`;
  }

  function addRule() {
    const rule = {
      id: Math.random().toString(36).slice(2, 10),
      name: 'New Rule',
      enabled: true,
      match: 'anyof',
      conditions: [{ header: 'from', match_type: 'contains', value: '', address_test: true, negate: false }],
      actions: [{ type: 'fileinto', argument: 'INBOX' }],
    };
    script.rules = [...script.rules, rule];
    script.order = [...script.order, ['rule', script.rules.length - 1]];
    selectedIdx = script.rules.length - 1;
    dirty = true;
  }

  function deleteRule(idx) {
    if (!confirm(`Delete rule "${script.rules[idx].name || 'Untitled'}"?`)) return;
    script.rules = script.rules.filter((_, i) => i !== idx);
    // Update order: remove the deleted rule entry and adjust remaining rule indices
    script.order = script.order
      .filter(([type, i]) => !(type === 'rule' && i === idx))
      .map(([type, i]) => type === 'rule' && i > idx ? ['rule', i - 1] : [type, i]);
    if (selectedIdx >= script.rules.length) selectedIdx = Math.max(0, script.rules.length - 1);
    dirty = true;
  }

  function moveRule(idx, dir) {
    const newIdx = idx + dir;
    if (newIdx < 0 || newIdx >= script.rules.length) return;
    const temp = script.rules[idx];
    script.rules[idx] = script.rules[newIdx];
    script.rules[newIdx] = temp;
    script.rules = [...script.rules];
    // Swap in order array too, preserving raw block positions
    script.order = script.order.map(([type, i]) => {
      if (type !== 'rule') return [type, i];
      if (i === idx) return ['rule', newIdx];
      if (i === newIdx) return ['rule', idx];
      return [type, i];
    });
    selectedIdx = newIdx;
    dirty = true;
  }

  async function save() {
    saving = true;
    try {
      await api.saveScript($currentScriptName, script);
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

  function openFolderPicker(cb) {
    folderPickerCallback = cb;
    showFolderPicker = true;
  }

  function onFolderSelected(e) {
    if (folderPickerCallback) folderPickerCallback(e.detail);
    showFolderPicker = false;
    folderPickerCallback = null;
  }

  function markDirty() { dirty = true; }
</script>

<div class="editor">
  <header>
    <div class="header-left">
      <button class="btn-sm" on:click={back}>&larr; Back</button>
      <h2>{$currentScriptName}</h2>
      {#if dirty}<span class="dirty-badge">unsaved</span>{/if}
    </div>
    <div class="header-right">
      <button class="btn-sm" on:click={addRule}>+ Add Rule</button>
      <button class="btn-sm btn-accent" on:click={save} disabled={saving}>
        {saving ? 'Saving...' : 'Save'}
      </button>
    </div>
  </header>

  {#if script}
    <div class="editor-layout">
      <div class="rule-list">
        {#each script.rules as rule, i}
          <div
            class="rule-item"
            class:selected={i === selectedIdx}
            class:disabled={!rule.enabled}
            on:click={() => selectedIdx = i}
            on:keydown={(e) => e.key === 'Enter' && (selectedIdx = i)}
            role="button"
            tabindex="0"
          >
            <div class="rule-item-name">{rule.name || 'Untitled'}</div>
            <div class="rule-item-meta">
              {rule.conditions.length} condition{rule.conditions.length !== 1 ? 's' : ''}
              &rarr; {rule.actions.map(a => a.type).join(', ')}
            </div>
            <div class="rule-item-controls">
              <button class="btn-xs" on:click|stopPropagation={() => moveRule(i, -1)} disabled={i === 0}>&#9650;</button>
              <button class="btn-xs" on:click|stopPropagation={() => moveRule(i, 1)} disabled={i === script.rules.length - 1}>&#9660;</button>
              <button class="btn-xs btn-danger" on:click|stopPropagation={() => deleteRule(i)}>&#10005;</button>
            </div>
          </div>
        {/each}
        {#if !script.rules.length}
          <p class="muted">No rules yet. Click "+ Add Rule" to start.</p>
        {/if}
      </div>

      <div class="rule-detail">
        {#if script.rules[selectedIdx]}
          {@const rule = script.rules[selectedIdx]}
          <div class="field">
            <label>Rule Name</label>
            <input type="text" bind:value={rule.name} on:input={markDirty} />
          </div>

          <div class="field-row">
            <label class="toggle">
              <input type="checkbox" bind:checked={rule.enabled} on:change={markDirty} />
              Enabled
            </label>
            <div class="field">
              <label>Match</label>
              <select bind:value={rule.match} on:change={markDirty}>
                <option value="anyof">Any condition (OR)</option>
                <option value="allof">All conditions (AND)</option>
              </select>
            </div>
          </div>

          <h3>Conditions</h3>
          <ConditionBuilder
            bind:conditions={rule.conditions}
            on:change={markDirty}
          />

          <h3>Actions</h3>
          <ActionBuilder
            bind:actions={rule.actions}
            on:change={markDirty}
            on:pickfolder={(e) => openFolderPicker(e.detail)}
          />

          <h3>Preview</h3>
          <pre class="sieve-preview">{preview}</pre>
        {:else}
          <p class="muted">Select a rule from the list.</p>
        {/if}
      </div>
    </div>
  {/if}
</div>

{#if showFolderPicker}
  <FolderPicker folders={folderList} on:select={onFolderSelected} on:close={() => showFolderPicker = false} />
{/if}

<style>
  .editor { max-width: 1200px; margin: 0 auto; padding: 1rem; }
  header {
    display: flex; justify-content: space-between; align-items: center;
    padding: 0.75rem 0; border-bottom: 1px solid var(--border); margin-bottom: 1rem;
  }
  .header-left { display: flex; align-items: center; gap: 0.75rem; }
  .header-left h2 { margin: 0; font-size: 1.1rem; }
  .header-right { display: flex; gap: 0.5rem; }
  .dirty-badge { font-size: 0.7rem; color: #f0a030; }
  .editor-layout { display: flex; gap: 1rem; min-height: 70vh; }
  .rule-list {
    width: 300px; flex-shrink: 0; overflow-y: auto;
    border-right: 1px solid var(--border); padding-right: 1rem;
  }
  .rule-item {
    padding: 0.6rem 0.75rem; border-radius: 6px; cursor: pointer;
    margin-bottom: 0.35rem; position: relative;
  }
  .rule-item:hover { background: var(--surface); }
  .rule-item.selected { background: var(--surface); border-left: 3px solid var(--accent); }
  .rule-item.disabled { opacity: 0.5; }
  .rule-item-name { font-weight: 500; font-size: 0.9rem; }
  .rule-item-meta { font-size: 0.75rem; color: var(--text2); margin-top: 0.15rem; }
  .rule-item-controls {
    position: absolute; top: 0.5rem; right: 0.5rem;
    display: none; gap: 0.2rem;
  }
  .rule-item:hover .rule-item-controls { display: flex; }
  .rule-detail { flex: 1; min-width: 0; }
  .field { margin-bottom: 0.75rem; }
  .field label { display: block; font-size: 0.8rem; color: var(--text2); margin-bottom: 0.2rem; }
  .field input, .field select {
    width: 100%; padding: 0.5rem 0.6rem; border-radius: 6px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text);
    font-size: 0.85rem; box-sizing: border-box;
  }
  .field-row { display: flex; gap: 1rem; align-items: flex-end; margin-bottom: 0.75rem; }
  .toggle { display: flex; align-items: center; gap: 0.4rem; font-size: 0.85rem; cursor: pointer; }
  h3 { font-size: 0.95rem; margin: 1rem 0 0.5rem; color: var(--text2); }
  .sieve-preview {
    background: var(--surface); padding: 0.75rem; border-radius: 6px;
    font-family: monospace; font-size: 0.8rem; overflow-x: auto;
    white-space: pre-wrap; color: var(--text2);
  }
  .btn-xs {
    padding: 0.15rem 0.35rem; font-size: 0.7rem; border-radius: 4px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text);
    cursor: pointer;
  }
  .muted { color: var(--text2); font-size: 0.9rem; }
</style>
