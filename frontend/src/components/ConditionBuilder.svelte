<script context="module">
  // One datalist per instance. Only one ConditionBuilder is mounted today, but
  // a duplicate DOM id is the kind of bug that appears the day a second one is,
  // and costs nothing to make unrepresentable.
  let datalistSeq = 0;
</script>

<script>
  import { createEventDispatcher } from 'svelte';
  import { sortable } from '../lib/sortable.js';
  import {
    HEADERS, MATCH_TYPES, deriveAddressTest, moveItem, newCondition,
  } from '../lib/scriptDocument.js';
  export let conditions = [];
  const dispatch = createEventDispatcher();

  // The builder never mutates `conditions` — every edit dispatches a fresh
  // array upward and the document applies it as one mutation. Vocabularies
  // live in scriptDocument; this component only renders them.
  function emit(next) { dispatch('update', next); }

  // The header is FREE TEXT with suggestions, not a closed list. Any quoted
  // string is a legal Sieve header, and a `<select>` here lost data: a
  // Condition on `x-spam-flag` matched no `<option>`, so it rendered as an
  // empty dropdown and the real value survived only until the user opened
  // that select — at which point the pick overwrote it. An enum would have
  // turned that display bug into a hard restriction (areyousievious-8fg.18).
  const HEADER_SUGGESTIONS = `header-suggestions-${(datalistSeq += 1)}`;

  function addCondition() { emit([...conditions, newCondition()]); }

  function removeCondition(idx) { emit(conditions.filter((_, i) => i !== idx)); }

  function reorderCondition(oldIndex, newIndex) {
    const next = moveItem(conditions, oldIndex, newIndex);
    if (next !== conditions) emit(next);
  }

  function moveCondition(idx, dir) { reorderCondition(idx, idx + dir); }

  /** Patch one condition, leaving its siblings untouched. */
  function patch(idx, fields) {
    emit(conditions.map((c, i) => (i === idx ? { ...c, ...fields } : c)));
  }

  /** A header pick re-derives address_test for the edited condition ONLY.
      Siblings keep what the parser recorded — address_test is not derivable
      from a parsed Condition (`header :contains "from"` is legal Sieve). */
  function setHeader(idx, header) {
    emit(conditions.map((c, i) => (i === idx ? deriveAddressTest({ ...c, header }) : c)));
  }
</script>

<datalist id={HEADER_SUGGESTIONS}>
  {#each HEADERS as h}
    <option value={h.value}>{h.label}</option>
  {/each}
</datalist>

<div class="conditions" use:sortable={{ handle: '.drag-handle', onReorder: reorderCondition }}>
  {#each conditions as cond, i (cond.key)}
    <div class="condition-row">
      <span class="drag-handle" aria-hidden="true" title="Drag to reorder">&#9776;</span>

      <input
        class="header-input"
        type="text"
        list={HEADER_SUGGESTIONS}
        value={cond.header}
        on:input={(e) => setHeader(i, e.currentTarget.value)}
        placeholder="header"
      />

      <select value={cond.match_type} on:change={(e) => patch(i, { match_type: e.currentTarget.value })}>
        {#each MATCH_TYPES as mt}
          <option value={mt.value}>{mt.label}</option>
        {/each}
      </select>

      <input type="text" value={cond.value} on:input={(e) => patch(i, { value: e.currentTarget.value })} placeholder="value" />

      <label class="negate-toggle" title="Negate (NOT)">
        <input type="checkbox" checked={cond.negate} on:change={(e) => patch(i, { negate: e.currentTarget.checked })} />
        NOT
      </label>

      <div class="row-controls">
        <button class="btn-xs" on:click={() => moveCondition(i, -1)} disabled={i === 0} title="Move up">&#9650;</button>
        <button class="btn-xs" on:click={() => moveCondition(i, 1)} disabled={i === conditions.length - 1} title="Move down">&#9660;</button>
        <button class="btn-xs btn-danger" on:click={() => removeCondition(i)} title="Remove">&#10005;</button>
      </div>
    </div>
  {/each}
</div>

<button class="btn-sm" on:click={addCondition}>+ Add Condition</button>

<style>
  .conditions { display: flex; flex-direction: column; gap: 0.4rem; }
  .condition-row { display: flex; gap: 0.35rem; align-items: center; }
  .condition-row select, .condition-row input {
    padding: 0.4rem 0.5rem; border-radius: 5px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text);
    font-size: 0.8rem;
  }
  .condition-row select { width: 120px; }
  .condition-row input[type="text"] { flex: 1; min-width: 150px; }
  /* The header is an input, not a select, but it keeps the select's width so
     the row still reads as three aligned columns. */
  .condition-row input.header-input { flex: 0 0 120px; width: 120px; min-width: 0; }
  .negate-toggle {
    font-size: 0.7rem; color: var(--text2); display: flex;
    align-items: center; gap: 0.2rem; cursor: pointer; white-space: nowrap;
  }
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
