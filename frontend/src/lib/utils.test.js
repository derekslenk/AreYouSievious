/**
 * Regression tests locking in the rebuildOrder() fix for the
 * delete-after-reorder script.order desync (Quality C-3, Phase-CP1 Fix 4).
 *
 * Pre-fix algorithm was extract-permute-renumber against rules-array
 * indices, which silently produced a stale order array after a reorder
 * was followed by a delete (or vice versa) — RawBlock positions slid
 * relative to rules on save.
 *
 * The fixed algorithm uses rule IDs as the single source of truth:
 *   - walk oldOrder, map 'rule' entries by id to their new index
 *   - preserve 'raw' entries verbatim (in slot order)
 *   - drop entries whose id no longer exists in newRules
 *   - append any newRules ids that weren't seen
 */

import { describe, it, expect } from 'vitest';
import { rebuildOrder } from './utils.js';

describe('rebuildOrder', () => {
  it('reorder then delete (the original repro)', () => {
    // Start: [a, b, c] with order matching rules.
    let rules = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
    let order = [['rule', 0], ['rule', 1], ['rule', 2]];

    // Reorder: move b before a → [b, a, c]
    const afterReorder = [{ id: 'b' }, { id: 'a' }, { id: 'c' }];
    order = rebuildOrder(order, rules, afterReorder);
    rules = afterReorder;
    expect(order).toEqual([['rule', 1], ['rule', 0], ['rule', 2]]);

    // Delete c → [b, a]
    const afterDelete = [{ id: 'b' }, { id: 'a' }];
    order = rebuildOrder(order, rules, afterDelete);

    // Every remaining rule MUST be referenced exactly once with a valid index.
    expect(order).toEqual([['rule', 1], ['rule', 0]]);
    const ruleRefs = order.filter(([k]) => k === 'rule').map(([, i]) => i);
    expect([...ruleRefs].sort()).toEqual([0, 1]);
  });

  it('delete then reorder', () => {
    let rules = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
    let order = [['rule', 0], ['rule', 1], ['rule', 2]];

    // Delete b → [a, c]
    const afterDelete = [{ id: 'a' }, { id: 'c' }];
    order = rebuildOrder(order, rules, afterDelete);
    rules = afterDelete;
    expect(order).toEqual([['rule', 0], ['rule', 1]]);

    // Reorder: c before a → [c, a]
    const afterReorder = [{ id: 'c' }, { id: 'a' }];
    order = rebuildOrder(order, rules, afterReorder);
    expect(order).toEqual([['rule', 1], ['rule', 0]]);
  });

  it('add new rule appends to order', () => {
    const oldRules = [{ id: 'a' }];
    const newRules = [{ id: 'a' }, { id: 'b' }];
    const oldOrder = [['rule', 0]];
    expect(rebuildOrder(oldOrder, oldRules, newRules)).toEqual([
      ['rule', 0],
      ['rule', 1],
    ]);
  });

  it('combined add + delete + reorder in one tick', () => {
    // Old: [a, b, c]; New: [b, d] (deleted a, c; added d; b is now at front).
    const oldRules = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
    const newRules = [{ id: 'b' }, { id: 'd' }];
    const oldOrder = [['rule', 0], ['rule', 1], ['rule', 2]];
    expect(rebuildOrder(oldOrder, oldRules, newRules)).toEqual([
      ['rule', 0], // surviving b, remapped from old idx 1 → new idx 0
      ['rule', 1], // d appended
    ]);
  });

  it('RawBlock order entries are preserved verbatim', () => {
    // Raw blocks are interleaved with rules; their slot indices must NOT
    // shift just because the rules array was permuted around them.
    const oldRules = [{ id: 'a' }, { id: 'b' }];
    const newRules = [{ id: 'b' }, { id: 'a' }];
    const oldOrder = [
      ['rule', 0],
      ['raw', 7],
      ['rule', 1],
      ['raw', 13],
    ];
    expect(rebuildOrder(oldOrder, oldRules, newRules)).toEqual([
      ['rule', 1],
      ['raw', 7],
      ['rule', 0],
      ['raw', 13],
    ]);
  });

  it('RawBlocks survive delete-after-reorder unchanged', () => {
    // The core C-3 regression: raw block indices must stay put when
    // a delete follows a reorder.
    let rules = [{ id: 'a' }, { id: 'b' }, { id: 'c' }];
    let order = [['rule', 0], ['raw', 99], ['rule', 1], ['rule', 2]];

    const afterReorder = [{ id: 'b' }, { id: 'a' }, { id: 'c' }];
    order = rebuildOrder(order, rules, afterReorder);
    rules = afterReorder;

    const afterDelete = [{ id: 'b' }, { id: 'a' }];
    order = rebuildOrder(order, rules, afterDelete);

    // ['raw', 99] must still be present, untouched.
    expect(order.filter(([k]) => k === 'raw')).toEqual([['raw', 99]]);
    // All surviving rules referenced exactly once.
    const ruleRefs = order.filter(([k]) => k === 'rule').map(([, i]) => i);
    expect([...ruleRefs].sort()).toEqual([0, 1]);
  });
});
