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
  previewRule,
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

describe('previewRule', () => {
  /** Build a rule entry directly, bypassing the wire. */
  function rule(overrides = {}) {
    const doc = addRule(fromWire({}));
    return { ...ruleEntries(doc)[0], ...overrides };
  }

  function cond(overrides = {}) {
    return { ...newCondition(), header: 'from', match_type: 'is', value: 'a@x.com', ...overrides };
  }

  it('renders a bare single-condition rule', () => {
    const out = previewRule(
      rule({ match: '', conditions: [cond()], actions: [{ ...newAction(), argument: 'A' }] })
    );
    expect(out).toBe('if address :is "from" "a@x.com" {\n    fileinto "A";\n}');
  });

  it('renders a multi-condition rule with its match type', () => {
    const out = previewRule(
      rule({
        match: 'allof',
        conditions: [cond(), cond({ value: 'b@x.com' })],
        actions: [{ ...newAction(), argument: 'A' }],
      })
    );
    expect(out).toContain('if allof (');
    expect(out.split('\n')[1]).toBe('    address :is "from" "a@x.com",');
  });

  it('REGRESSION: renders a negated condition as NOT', () => {
    // The component's version dropped `negate` entirely, so a NOT condition
    // previewed as its exact opposite.
    const out = previewRule(rule({ match: '', conditions: [cond({ negate: true })], actions: [] }));
    expect(out).toContain('not address :is "from" "a@x.com"');
  });

  it('REGRESSION: escapes quotes and backslashes', () => {
    // The component interpolated raw, so a folder containing a quote produced
    // a preview that was not what got saved.
    const out = previewRule(
      rule({
        match: '',
        conditions: [cond({ value: 'a"b' })],
        actions: [{ ...newAction(), argument: 'X\\Y"Z' }],
      })
    );
    expect(out).toContain('"a\\"b"');
    expect(out).toContain('fileinto "X\\\\Y\\"Z";');
  });

  it('REGRESSION: shows a disabled rule commented out', () => {
    // A disabled rule is stored `##`-commented; the component showed it live.
    const out = previewRule(
      rule({ match: '', enabled: false, conditions: [cond()], actions: [] })
    );
    expect(out.split('\n').every((l) => l.startsWith('##'))).toBe(true);
  });

  it('renders tagged arguments', () => {
    const out = previewRule(
      rule({
        match: '',
        conditions: [cond({ address_part: 'domain', comparator: 'i;octet' })],
        actions: [],
      })
    );
    expect(out).toContain('address :domain :comparator "i;octet" :is "from" "a@x.com"');
  });

  it('renders every action type', () => {
    const types = [
      ['fileinto', 'fileinto "F";'],
      ['fileinto_copy', 'fileinto :copy "F";'],
      ['redirect', 'redirect "F";'],
      ['addflag', 'addflag "F";'],
      ['reject', 'reject "F";'],
      ['keep', 'keep;'],
      ['discard', 'discard;'],
      ['stop', 'stop;'],
    ];
    for (const [type, expected] of types) {
      const out = previewRule(
        rule({ match: '', conditions: [cond()], actions: [{ ...newAction(), type, argument: 'F' }] })
      );
      expect(out).toContain(`    ${expected}`);
    }
  });

  it('returns empty for a rule with no conditions', () => {
    expect(previewRule(rule({ conditions: [] }))).toBe('');
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
