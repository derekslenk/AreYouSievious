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
  entryToWire,
  fromWire,
  toWire,
  ruleEntries,
  addRule,
  deleteRule,
  moveRule,
  newCondition,
  newAction,
  HEADERS,
  MATCH_TYPES,
  ACTION_TYPES,
  actionSpec,
  deriveAddressTest,
  updateEntry,
  setConditions,
  setActions,
  moveItem,
  snapshot,
  sameWire,
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
        {
          header: 'from',
          match_type: 'is',
          value: 'a@x.com',
          address_test: true,
          negate: false,
          address_part: 'domain',
          comparator: '',
        },
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
        {
          header: 'from',
          match_type: 'is',
          value: 'b@x.com',
          address_test: true,
          negate: false,
          address_part: '',
          comparator: 'i;octet',
        },
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
    for (const e of doc.entries) expect(e.key).toBeTruthy();
    for (const r of ruleEntries(doc)) {
      for (const c of r.conditions) expect(c.key).toBeTruthy();
      for (const a of r.actions) expect(a.key).toBeTruthy();
    }
  });

  it('keys are unique across the document', () => {
    const doc = fromWire(WIRE);
    const keys = doc.entries.map((e) => e.key);
    for (const r of ruleEntries(doc)) {
      keys.push(...r.conditions.map((c) => c.key), ...r.actions.map((a) => a.key));
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
    const entry = payload.entries[0];
    // Narrowed rather than asserted: `entries` is the generated union, so
    // reaching for `.conditions` without proving `kind` is a type error now.
    if (entry.kind !== 'rule') throw new Error(`expected a rule entry, got ${entry.kind}`);
    expect(entry.conditions).toHaveLength(1);
    expect(JSON.stringify(payload)).not.toContain('"key"');
  });
});

describe('newCondition / newAction', () => {
  it('mint distinct keys', () => {
    const keys = [newCondition().key, newCondition().key, newAction().key, newAction().key];
    expect(new Set(keys).size).toBe(4);
  });

  it('produce entries whose keys are stripped at the wire', () => {
    const doc = addRule(fromWire({}));
    const rule = ruleEntries(doc)[0];
    rule.conditions.push(newCondition());
    rule.actions.push(newAction());
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
    const raw = next.entries[1];
    expect(raw.kind === 'raw' && raw.text).toBe('# untouched');
  });

  it('is a no-op for equal or out-of-range indices', () => {
    const doc = fromWire(WIRE);
    expect(moveRule(doc, 1, 1)).toBe(doc);
    expect(moveRule(doc, -1, 0)).toBe(doc);
    expect(moveRule(doc, 0, 5)).toBe(doc);
  });
});


describe('entryToWire', () => {
  it('is the same projection toWire applies, one entry at a time', () => {
    // The preview endpoint takes ONE Rule. If it were fed a differently
    // shaped payload the preview would once again be of something other
    // than what a save writes — the exact defect .17 deletes.
    const document = fromWire(WIRE);
    expect(document.entries.map(entryToWire)).toEqual(toWire(document).entries);
  });

  it('strips the render key from a rule and from a raw block alike', () => {
    for (const entry of fromWire(WIRE).entries) {
      expect(entryToWire(entry)).not.toHaveProperty('key');
      expect(JSON.stringify(entryToWire(entry))).not.toContain('"key"');
    }
  });

  it('drops the keys inside conditions and actions, not just the entry key', () => {
    const rule = ruleEntries(fromWire(WIRE))[0];
    const wire = entryToWire(rule);
    if (wire.kind !== 'rule') throw new Error('expected a rule on the wire');
    expect(rule.conditions.every((c) => c.key)).toBe(true);
    expect((wire.conditions ?? []).every((c) => !('key' in c))).toBe(true);
    expect((wire.actions ?? []).every((a) => !('key' in a))).toBe(true);
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

// ── areyousievious-8fg.16: semantics extracted from the components ──

describe('deriveAddressTest', () => {
  it('derives true for address-bearing headers and false otherwise', () => {
    for (const header of ['from', 'to', 'cc', 'reply-to']) {
      expect(deriveAddressTest({ ...newCondition(), header }).address_test).toBe(true);
    }
    for (const header of ['subject', 'list-id']) {
      expect(deriveAddressTest({ ...newCondition(), header }).address_test).toBe(false);
    }
  });

  it('returns a new object and touches nothing but address_test', () => {
    const cond = {
      ...newCondition(),
      header: 'subject',
      address_part: /** @type {'domain'} */ ('domain'),
      value: 'x',
    };
    const derived = deriveAddressTest(cond);
    expect(derived).not.toBe(cond);
    expect(derived).toEqual({ ...cond, address_test: false });
  });

  it('is per-condition: a parsed header-test on "from" is untouched by edits to siblings', () => {
    // The old component re-derived EVERY condition on EVERY keystroke, so a
    // parsed `header :contains "from"` flipped to an address test the moment
    // the user typed anywhere in the rule. address_test is not derivable from
    // a parsed Condition — only a user's header pick may set the default.
    const script = fromWire(WIRE);
    const rule = ruleEntries(script)[0];
    const edited = rule.conditions.map((c, i) => (i === 1 ? { ...c, value: 'Newsletter' } : c));
    const next = setConditions(script, rule.key, edited);
    expect(ruleEntries(next)[0].conditions[0].address_test).toBe(
      rule.conditions[0].address_test
    );
  });
});

describe('updateEntry / setConditions / setActions', () => {
  it('patches only the keyed entry and returns a new document', () => {
    const script = fromWire(WIRE);
    const rule = ruleEntries(script)[0];
    const next = updateEntry(script, rule.key, { name: 'Renamed', enabled: false });
    expect(next).not.toBe(script);
    expect(ruleEntries(next)[0].name).toBe('Renamed');
    expect(ruleEntries(next)[0].enabled).toBe(false);
    // untouched entries keep their identity — Svelte's keyed each relies on it
    expect(next.entries.filter((e) => e.key !== rule.key)).toEqual(
      script.entries.filter((e) => e.key !== rule.key)
    );
    // the original document is unchanged
    expect(ruleEntries(script)[0].name).toBe('A');
  });

  it('setConditions and setActions replace the arrays wholesale', () => {
    const script = fromWire(WIRE);
    const rule = ruleEntries(script)[0];
    const conds = [newCondition()];
    const acts = [newAction()];
    const next = setActions(setConditions(script, rule.key, conds), rule.key, acts);
    expect(ruleEntries(next)[0].conditions).toBe(conds);
    expect(ruleEntries(next)[0].actions).toBe(acts);
  });

  it('an unknown key is a no-op on the entries', () => {
    const script = fromWire(WIRE);
    const next = updateEntry(script, 'nope', { name: 'X' });
    expect(next.entries).toEqual(script.entries);
  });
});

describe('moveItem', () => {
  const list = ['a', 'b', 'c'];

  it('moves an item and returns a new list', () => {
    expect(moveItem(list, 0, 2)).toEqual(['b', 'c', 'a']);
    expect(moveItem(list, 2, 0)).toEqual(['c', 'a', 'b']);
    expect(list).toEqual(['a', 'b', 'c']);
  });

  it('is a no-op (same reference) for same-slot or out-of-bounds moves', () => {
    expect(moveItem(list, 1, 1)).toBe(list);
    expect(moveItem(list, -1, 0)).toBe(list);
    expect(moveItem(list, 0, 3)).toBe(list);
  });
});

describe('snapshot / sameWire', () => {
  it('snapshot is a deep copy — later edits cannot reach it', () => {
    const script = fromWire(WIRE);
    const pristine = snapshot(script);
    ruleEntries(script)[0].conditions[0].value = 'mutated';
    expect(ruleEntries(pristine)[0].conditions[0].value).toBe('a@x.com');
  });

  it('sameWire ignores render keys and compares wire content', () => {
    const a = fromWire(WIRE);
    const b = fromWire(WIRE); // fresh keys
    expect(sameWire(a, b)).toBe(true);
    const edited = updateEntry(a, ruleEntries(a)[0].key, { name: 'Changed' });
    expect(sameWire(edited, b)).toBe(false);
  });
});

describe('vocabularies', () => {
  it('exports the closed Condition and Action vocabularies', () => {
    // HEADERS is the exception: suggestions, not a closed set. See below.
    expect(HEADERS.map((h) => h.value)).toEqual([
      'from', 'to', 'cc', 'subject', 'reply-to', 'list-id',
    ]);
    expect(MATCH_TYPES.map((m) => m.value)).toEqual(['contains', 'is', 'matches', 'regex']);
    expect(ACTION_TYPES.map((a) => a.value)).toEqual([
      'fileinto', 'fileinto_copy', 'redirect', 'keep', 'discard', 'stop', 'addflag', 'reject',
    ]);
    // hasArg drives whether the builder renders an argument input
    expect(ACTION_TYPES.filter((a) => a.hasArg).map((a) => a.value)).toEqual([
      'fileinto', 'fileinto_copy', 'redirect', 'addflag', 'reject',
    ]);
    // every arg-bearing action carries the hint text its input shows
    expect(ACTION_TYPES.filter((a) => a.hasArg).every((a) => a.placeholder)).toBe(true);
  });

  it('a header outside the suggestions survives the document untouched', () => {
    // The trap this closes: the builder rendered `header` as a <select> over
    // HEADERS, so `x-spam-flag` matched no option and the value lived only
    // until the user opened that select. The document has always carried it —
    // the loss was in the widget, which is why the fix is a free-text input
    // with a <datalist> rather than a wider list here.
    const wire = {
      requires: [],
      entries: [{
        kind: 'rule', name: 'Spam', enabled: true, match: 'anyof',
        conditions: [{
          header: 'x-spam-flag', match_type: 'is', value: 'YES',
          address_test: false, negate: false, address_part: '', comparator: '',
        }],
        actions: [{ type: 'fileinto', argument: 'Junk' }],
      }],
    };
    const roundTripped = toWire(fromWire(wire));
    expect(roundTripped).toEqual(wire);
    expect(HEADERS.map((h) => h.value)).not.toContain('x-spam-flag');
  });

  it('actionSpec resolves a type to its vocabulary entry', () => {
    expect(actionSpec('redirect')).toEqual({
      value: 'redirect', label: 'Redirect to', hasArg: true, placeholder: 'email@example.com',
    });
    expect(actionSpec('keep')?.hasArg).toBe(false);
    expect(actionSpec('nonsense')).toBeUndefined();
  });
});
