<script>
  import { createEventDispatcher } from 'svelte';
  export let conditions = [];
  const dispatch = createEventDispatcher();

  const HEADERS = [
    { value: 'from', label: 'From' },
    { value: 'to', label: 'To' },
    { value: 'cc', label: 'CC' },
    { value: 'subject', label: 'Subject' },
    { value: 'reply-to', label: 'Reply-To' },
    { value: 'list-id', label: 'List-ID' },
  ];

  const MATCH_TYPES = [
    { value: 'contains', label: 'contains' },
    { value: 'is', label: 'is exactly' },
    { value: 'matches', label: 'matches (glob)' },
    { value: 'regex', label: 'regex' },
  ];

  function addCondition() {
    conditions = [...conditions, {
      header: 'from', match_type: 'contains', value: '',
      address_test: true, negate: false,
    }];
    dispatch('change');
  }

  function removeCondition(idx) {
    conditions = conditions.filter((_, i) => i !== idx);
    dispatch('change');
  }

  function onChange() {
    // Auto-set address_test based on header
    conditions = conditions.map(c => ({
      ...c,
      address_test: ['from', 'to', 'cc', 'reply-to'].includes(c.header),
    }));
    dispatch('change');
  }
</script>

<div class="conditions">
  {#each conditions as cond, i}
    <div class="condition-row">
      <select bind:value={cond.header} on:change={onChange}>
        {#each HEADERS as h}
          <option value={h.value}>{h.label}</option>
        {/each}
      </select>

      <select bind:value={cond.match_type} on:change={onChange}>
        {#each MATCH_TYPES as mt}
          <option value={mt.value}>{mt.label}</option>
        {/each}
      </select>

      <input type="text" bind:value={cond.value} on:input={onChange} placeholder="value" />

      <label class="negate-toggle" title="Negate (NOT)">
        <input type="checkbox" bind:checked={cond.negate} on:change={onChange} />
        NOT
      </label>

      <button class="btn-xs btn-danger" on:click={() => removeCondition(i)} title="Remove">&#10005;</button>
    </div>
  {/each}

  <button class="btn-sm" on:click={addCondition}>+ Add Condition</button>
</div>

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
  .negate-toggle {
    font-size: 0.7rem; color: var(--text2); display: flex;
    align-items: center; gap: 0.2rem; cursor: pointer; white-space: nowrap;
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
