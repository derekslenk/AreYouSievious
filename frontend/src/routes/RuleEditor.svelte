<script>
  import { onMount } from 'svelte';
  import { api } from '../lib/api.js';
  import {
    view, currentScript, currentScriptName, folders, showToast,
  } from '../lib/stores.js';
  import { sortable } from '../lib/sortable.js';
  import * as doc from '../lib/scriptDocument.js';
  import ConditionBuilder from '../components/ConditionBuilder.svelte';
  import ActionBuilder from '../components/ActionBuilder.svelte';
  import FolderPicker from '../components/FolderPicker.svelte';

  // The editable document. ScriptDocument owns its shape, its render keys and
  // its mutations; this component only renders and tracks selection.
  let script = null;
  let selectedIdx = 0;
  let saving = false;
  let dirty = false;
  let folderList = [];
  let showFolderPicker = false;
  let folderPickerCallback = null;

  // Sieve preview of selected rule
  let preview = '';

  // Rule entries, in order. Raw Blocks stay in `script.entries` and are never
  // rendered, but keep their position through every mutation.
  $: rules = script ? doc.ruleEntries(script) : [];

  // Index of the selected rule within `script.entries`. Detail-panel binds go
  // through this rather than through `rules`, so a two-way bind invalidates
  // the document itself — binding into a `$:`-derived array would be
  // overwritten on the next recompute and the preview would go stale.
  $: selectedEntryIdx = script ? script.entries.indexOf(rules[selectedIdx]) : -1;

  onMount(async () => {
    script = doc.fromWire($currentScript);
    try {
      folderList = await api.listFolders();
      folders.set(folderList);
    } catch (e) { /* ok */ }
  });

  $: if (rules[selectedIdx]) {
    preview = generateRulePreview(rules[selectedIdx]);
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
    script = doc.addRule(script);
    selectedIdx = doc.ruleEntries(script).length - 1;
    dirty = true;
  }

  function deleteRule(idx) {
    const target = doc.ruleEntries(script)[idx];
    if (!confirm(`Delete rule "${target?.name || 'Untitled'}"?`)) return;
    script = doc.deleteRule(script, idx);
    const remaining = doc.ruleEntries(script).length;
    if (selectedIdx >= remaining) selectedIdx = Math.max(0, remaining - 1);
    dirty = true;
  }

  function moveRule(idx, dir) {
    reorderRule(idx, idx + dir);
  }

  function reorderRule(oldIndex, newIndex) {
    const next = doc.moveRule(script, oldIndex, newIndex);
    if (next === script) return;
    script = next;
    selectedIdx = newIndex;
    dirty = true;
  }

  async function save() {
    saving = true;
    try {
      await api.saveScript($currentScriptName, doc.toWire(script));
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
      <div class="rule-list" use:sortable={{ onReorder: reorderRule }}>
        {#each rules as rule, i (rule.key)}
          <div
            class="rule-item"
            class:selected={i === selectedIdx}
            class:disabled={!rule.enabled}
            on:click={() => selectedIdx = i}
            on:keydown={(e) => e.key === 'Enter' && (selectedIdx = i)}
            tabindex="0"
          >
            <span class="drag-icon" aria-hidden="true">&#9776;</span>
            <div class="rule-item-content">
              <div class="rule-item-name">{rule.name || 'Untitled'}</div>
              <div class="rule-item-meta">
                {rule.conditions.length} condition{rule.conditions.length !== 1 ? 's' : ''}
                &rarr; {rule.actions.map(a => a.type).join(', ')}
              </div>
            </div>
            <div class="rule-item-controls">
              <button class="btn-xs" on:click|stopPropagation={() => moveRule(i, -1)} disabled={i === 0} title="Move up">&#9650;</button>
              <button class="btn-xs" on:click|stopPropagation={() => moveRule(i, 1)} disabled={i === rules.length - 1} title="Move down">&#9660;</button>
              <button class="btn-xs btn-danger" on:click|stopPropagation={() => deleteRule(i)}>&#10005;</button>
            </div>
          </div>
        {/each}
        {#if !rules.length}
          <p class="muted">No rules yet. Click "+ Add Rule" to start.</p>
        {/if}
      </div>

      <div class="rule-detail">
        {#if selectedEntryIdx >= 0}
          <div class="field">
            <label>Rule Name</label>
            <input type="text" bind:value={script.entries[selectedEntryIdx].name} on:input={markDirty} />
          </div>

          <div class="field-row">
            <label class="toggle">
              <input type="checkbox" bind:checked={script.entries[selectedEntryIdx].enabled} on:change={markDirty} />
              Enabled
            </label>
            <!-- Only meaningful with 2+ conditions. A rule parsed from a bare
                 `if <test> {` has no anyof/allof wrapper and carries match=""
                 so the shape round-trips; showing an empty dropdown for it
                 would be noise. -->
            {#if script.entries[selectedEntryIdx].conditions.length > 1}
              <div class="field">
                <label>Match</label>
                <select bind:value={script.entries[selectedEntryIdx].match} on:change={markDirty}>
                  <option value="anyof">Any condition (OR)</option>
                  <option value="allof">All conditions (AND)</option>
                </select>
              </div>
            {/if}
          </div>

          <h3>Conditions</h3>
          <ConditionBuilder
            bind:conditions={script.entries[selectedEntryIdx].conditions}
            on:change={markDirty}
          />

          <h3>Actions</h3>
          <ActionBuilder
            bind:actions={script.entries[selectedEntryIdx].actions}
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
    padding: 0.6rem 0.75rem; border-radius: 6px; cursor: grab;
    margin-bottom: 0.35rem; position: relative; display: flex; align-items: center; gap: 0.5rem;
    user-select: none;
  }
  .rule-item:active { cursor: grabbing; }
  .rule-item:hover { background: var(--surface); }
  .rule-item.selected { background: var(--surface); border-left: 3px solid var(--accent); }
  .rule-item.disabled { opacity: 0.5; }
  .rule-item-content { flex: 1; min-width: 0; }
  .rule-item-name { font-weight: 500; font-size: 0.9rem; }
  .rule-item-meta { font-size: 0.75rem; color: var(--text2); margin-top: 0.15rem; }
  .drag-icon {
    opacity: 0.3; font-size: 0.85rem; flex-shrink: 0;
  }
  .rule-item:hover .drag-icon { opacity: 0.6; }
  :global(.sortable-ghost) {
    opacity: 0.3; background: var(--accent); border-radius: 6px;
  }
  :global(.sortable-chosen) {
    box-shadow: 0 2px 8px rgba(0,0,0,0.15);
  }
  .rule-item-controls {
    position: absolute; top: 0.5rem; right: 0.5rem;
    display: flex; gap: 0.2rem;
    opacity: 0; pointer-events: none;
    transition: opacity 0.15s;
  }
  .rule-item:hover .rule-item-controls,
  .rule-item:focus-within .rule-item-controls {
    opacity: 1; pointer-events: auto;
  }
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
