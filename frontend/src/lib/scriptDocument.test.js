/**
 * ScriptDocument tests.
 *
 * These cover logic that used to live inside RuleEditor.svelte, where no test
 * could reach it — the frontend has vitest but no jsdom and no
 * @testing-library/svelte, so anything inside a component is untestable today.
 * Moving the document and its mutations into a plain-JS module is what makes
 * this suite possible with the runner already in the repo.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
  fromWire,
  toWire,
  ruleEntries,
  addRule,
  deleteRule,
  moveRule,
  newCondition,
  newAction,
  __resetKeys,
} from './scriptDocument.js';

beforeEach(() => __resetKeys());

/** A wire payload with rules and a raw block interleaved. */
const WIRE = {
  requires: ['fileinto'],
  entries: [
    {
      kind: 'rule',
      name: 'A',
      enabled: true,
      match: 'anyof',
      conditions: [
        { header: 'from', match_type: 'is', value: 'a@x.com', address_test: true, negate: false },
      ],
      actions: [{ type: 'fileinto', argument: 'A' }],
    },
    { kind: 'raw', text: '# untouched', comment: '' },
    {
      kind: 'rule',
      name: 'B',
      enabled: true,
      match: 'anyof',
      conditions: [
        { header: 'from', match_type: 'is', value: 'b@x.com', address_test: true, negate: false },
      ],
      actions: [{ type: 'fileinto', argument: 'B' }],
    },
  ],
};

describe('wire translation', () => {
  it('round-trips a payload unchanged', () => {
    expect(toWire(fromWire(WIRE))).toEqual(WIRE);
  });

  it('mints a render key for every rule, condition and action', () => {
    const doc = fromWire(WIRE);
    for (const e of doc.entries) {
      expect(e.key).toBeTruthy();
      for (const c of e.conditions ?? []) expect(c.key).toBeTruthy();
      for (const a of e.actions ?? []) expect(a.key).toBeTruthy();
    }
  });

  it('keys are unique across the document', () => {
    const doc = fromWire(WIRE);
    const keys = [];
    for (const e of doc.entries) {
      keys.push(e.key);
      for (const c of e.conditions ?? []) keys.push(c.key);
      for (const a of e.actions ?? []) keys.push(a.key);
    }
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('REGRESSION: strips every key at the wire', () => {
    // The 422 bug: RuleEditor sent its render keys, and the DTOs are
    // extra="forbid". Nothing view-shaped may cross the seam.
    const payload = toWire(fromWire(WIRE));
    const json = JSON.stringify(payload);
    expect(json).not.toContain('"key"');
    expect(json).not.toContain('"id"');
  });

  it('tolerates a minimal payload', () => {
    expect(toWire(fromWire({}))).toEqual({ requires: [], entries: [] });
  });
});

describe('addRule', () => {
  it('appends a rule and leaves the original untouched', () => {
    const doc = fromWire(WIRE);
    const next = addRule(doc);
    expect(ruleEntries(next).length).toBe(3);
    expect(ruleEntries(doc).length).toBe(2);
  });

  it('produces a rule that survives the wire', () => {
    const payload = toWire(addRule(fromWire({})));
    expect(payload.entries).toHaveLength(1);
    expect(payload.entries[0].kind).toBe('rule');
    expect(payload.entries[0].conditions).toHaveLength(1);
    expect(JSON.stringify(payload)).not.toContain('"key"');
  });
});

describe('newCondition / newAction', () => {
  it('mint distinct keys', () => {
    const keys = [newCondition().key, newCondition().key, newAction().key, newAction().key];
    expect(new Set(keys).size).toBe(4);
  });

  it('produce entries whose keys are stripped at the wire', () => {
    let doc = addRule(fromWire({}));
    doc.entries[0].conditions.push(newCondition());
    doc.entries[0].actions.push(newAction());
    expect(JSON.stringify(toWire(doc))).not.toContain('"key"');
  });
});

describe('deleteRule', () => {
  it('removes the rule at the given rule-list index', () => {
    const next = deleteRule(fromWire(WIRE), 0);
    expect(ruleEntries(next).map((r) => r.name)).toEqual(['B']);
  });

  it('leaves raw blocks in place', () => {
    const next = deleteRule(fromWire(WIRE), 0);
    expect(next.entries.filter((e) => e.kind === 'raw')).toHaveLength(1);
  });

  it('ignores an out-of-range index', () => {
    const doc = fromWire(WIRE);
    expect(deleteRule(doc, 99)).toBe(doc);
  });
});

describe('moveRule', () => {
  it('reorders rules', () => {
    const next = moveRule(fromWire(WIRE), 1, 0);
    expect(ruleEntries(next).map((r) => r.name)).toEqual(['B', 'A']);
  });

  it('REGRESSION: raw blocks keep their absolute slot', () => {
    // rebuildOrder's job, now structural. Reordering rules must never drag
    // unparsed Sieve around — the user can't see it to notice.
    const next = moveRule(fromWire(WIRE), 1, 0);
    expect(next.entries.map((e) => e.kind)).toEqual(['rule', 'raw', 'rule']);
    expect(next.entries[1].text).toBe('# untouched');
  });

  it('is a no-op for equal or out-of-range indices', () => {
    const doc = fromWire(WIRE);
    expect(moveRule(doc, 1, 1)).toBe(doc);
    expect(moveRule(doc, -1, 0)).toBe(doc);
    expect(moveRule(doc, 0, 5)).toBe(doc);
  });
});

describe('REGRESSION: no entry can be orphaned', () => {
  it('every rule survives delete-after-reorder', () => {
    // The candidate-03 repro. The old rules[]/order[] pair desynced here and
    // silently dropped a rule on save; position-as-order cannot.
    let doc = fromWire(WIRE);
    doc = addRule(doc); // A, raw, B, New Rule
    doc = moveRule(doc, 2, 0); // New Rule, raw, A, B
    doc = deleteRule(doc, 1); // drop A

    const names = ruleEntries(doc).map((r) => r.name);
    expect(names).toEqual(['New Rule', 'B']);

    const payload = toWire(doc);
    expect(payload.entries.filter((e) => e.kind === 'rule')).toHaveLength(2);
    expect(payload.entries.filter((e) => e.kind === 'raw')).toHaveLength(1);
  });

  it('entry count on the wire always matches the document', () => {
    let doc = fromWire(WIRE);
    for (const step of [addRule, (d) => moveRule(d, 0, 1), (d) => deleteRule(d, 0), addRule]) {
      doc = step(doc);
      expect(toWire(doc).entries).toHaveLength(doc.entries.length);
    }
  });
});
