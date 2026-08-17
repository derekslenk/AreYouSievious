/**
 * `rebuildOrder` used to live here, along with six regression tests for the
 * delete-after-reorder desync it existed to work around. Both are gone: the
 * wire now carries one ordered `entries` sequence where position IS the order,
 * so there is no index to rebuild and no way for the arrays to disagree. The
 * behaviour those tests protected is covered structurally in
 * scriptDocument.test.js.
 *
 * `arrayMove` survives — ConditionBuilder and ActionBuilder reorder their own
 * lists with it — and had no coverage of its own until now.
 */

import { describe, it, expect } from 'vitest';
import { arrayMove } from './utils.js';

describe('arrayMove', () => {
  it('moves an element forward', () => {
    expect(arrayMove(['a', 'b', 'c'], 0, 2)).toEqual(['b', 'c', 'a']);
  });

  it('moves an element backward', () => {
    expect(arrayMove(['a', 'b', 'c'], 2, 0)).toEqual(['c', 'a', 'b']);
  });

  it('moves between adjacent positions', () => {
    expect(arrayMove(['a', 'b', 'c'], 1, 0)).toEqual(['b', 'a', 'c']);
  });

  it('is a no-op when the indices match', () => {
    expect(arrayMove(['a', 'b', 'c'], 1, 1)).toEqual(['a', 'b', 'c']);
  });

  it('does not mutate the input', () => {
    const original = ['a', 'b', 'c'];
    arrayMove(original, 0, 2);
    expect(original).toEqual(['a', 'b', 'c']);
  });

  it('preserves length and membership', () => {
    const out = arrayMove(['a', 'b', 'c', 'd'], 3, 1);
    expect(out).toHaveLength(4);
    expect([...out].sort()).toEqual(['a', 'b', 'c', 'd']);
  });
});
