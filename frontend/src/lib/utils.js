/** Move element from oldIndex to newIndex, returning a new array. */
export function arrayMove(arr, oldIndex, newIndex) {
  const result = [...arr];
  const [removed] = result.splice(oldIndex, 1);
  result.splice(newIndex, 0, removed);
  return result;
}

/**
 * Rebuild `script.order` after a rules-array mutation (add/delete/reorder).
 *
 * The wire format is `[["rule", ruleArrayIndex], ["raw", rawBlockIndex], ...]`.
 * Pre-existing ad-hoc index juggling desynced `order` from `rules` after a
 * delete-following-reorder sequence, silently corrupting RawBlock positions
 * relative to rules on save (Quality C-3). This rebuild uses rule IDs as the
 * single source of truth: it walks the old order, maps rule entries by id to
 * their new position in `newRules`, drops entries whose id no longer exists,
 * and appends any rules in `newRules` that weren't seen.
 *
 * @param {Array<[string, number]>} oldOrder
 * @param {Array<{id: string}>} oldRules
 * @param {Array<{id: string}>} newRules
 * @returns {Array<[string, number]>}
 */
export function rebuildOrder(oldOrder, oldRules, newRules) {
  const newIdxById = new Map(newRules.map((r, i) => [r.id, i]));
  const seen = new Set();
  const out = [];

  for (const [kind, idx] of oldOrder) {
    if (kind === 'raw') {
      out.push(['raw', idx]);
    } else if (kind === 'rule') {
      const id = oldRules[idx]?.id;
      const newIdx = id != null ? newIdxById.get(id) : undefined;
      if (newIdx != null && !seen.has(id)) {
        out.push(['rule', newIdx]);
        seen.add(id);
      }
    }
  }

  for (let i = 0; i < newRules.length; i++) {
    if (!seen.has(newRules[i].id)) out.push(['rule', i]);
  }

  return out;
}
