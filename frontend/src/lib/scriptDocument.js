/**
 * ScriptDocument — the editable Script and its mutations.
 *
 * This module owns everything about the shape of a Script while it is being
 * edited: minting the render keys Svelte's keyed `{#each}` needs, applying
 * mutations, and translating to and from the wire.
 *
 * Two rules make the whole thing work:
 *
 *   1. **Identity is view state.** The wire carries no ids (see
 *      docs/adr/0001-identity-is-view-state.md). Keys are minted here on the
 *      way in and stripped here on the way out, so no other module has to know
 *      they exist. Sending them was a hard 422 for two months.
 *
 *   2. **Position is the order.** `entries` is one ordered sequence of Rules
 *      and Raw Blocks. There is no separate order array to fall out of sync,
 *      which is what used to drop rules silently on save.
 *
 * Every mutation returns a NEW document rather than mutating in place, so
 * Svelte reactivity fires on reassignment.
 *
 * @typedef {{key: string, kind: 'rule', name: string, enabled: boolean,
 *            match: string, conditions: Condition[], actions: Action[]}} RuleEntry
 * @typedef {{key: string, kind: 'raw', text: string, comment: string}} RawEntry
 * @typedef {RuleEntry | RawEntry} Entry
 * @typedef {{key: string, header: string, match_type: string, value: string,
 *            address_test: boolean, negate: boolean, address_part: string,
 *            comparator: string}} Condition
 * @typedef {{key: string, type: string, argument: string}} Action
 * @typedef {{requires: string[], entries: Entry[]}} ScriptDocument
 */

let _keySeq = 0;

/** Mint a render key. Unique within a session; never crosses the wire. */
function key() {
  _keySeq += 1;
  return `k${_keySeq}`;
}

/** Reset the key counter. Test seam — keeps expected keys readable. */
export function __resetKeys() {
  _keySeq = 0;
}

// ── Wire translation ──

/**
 * Build an editable document from a wire payload.
 * @param {{requires?: string[], entries?: object[]}} payload
 * @returns {ScriptDocument}
 */
export function fromWire(payload) {
  const entries = (payload?.entries ?? []).map((e) => {
    if (e.kind === 'raw') {
      /** @type {RawEntry} */
      const raw = { key: key(), kind: 'raw', text: e.text ?? '', comment: e.comment ?? '' };
      return raw;
    }
    /** @type {RuleEntry} */
    const rule = {
      key: key(),
      kind: 'rule',
      name: e.name ?? '',
      enabled: e.enabled ?? true,
      match: e.match ?? 'anyof',
      conditions: (e.conditions ?? []).map((c) => ({
        key: key(),
        header: c.header,
        match_type: c.match_type,
        value: c.value ?? '',
        address_test: c.address_test ?? false,
        negate: c.negate ?? false,
        // RFC 5228 tagged arguments. Not editable in the builder — they are
        // carried through untouched so a save can't change what a rule
        // matches. Dropping :domain turned "the domain is example.com" into
        // "the whole address is example.com".
        address_part: c.address_part ?? '',
        comparator: c.comparator ?? '',
      })),
      actions: (e.actions ?? []).map((a) => ({
        key: key(),
        type: a.type,
        argument: a.argument ?? '',
      })),
    };
    return rule;
  });
  return { requires: payload?.requires ?? [], entries };
}

/**
 * Strip view state and produce the wire payload.
 *
 * The backend DTOs are `extra="forbid"`, so a leaked `key` here is a 422.
 * That strictness is deliberate: a silent accept would write junk fields.
 * @param {ScriptDocument} doc
 * @returns {{requires: string[], entries: object[]}}
 */
export function toWire(doc) {
  return {
    requires: doc.requires,
    entries: doc.entries.map((e) =>
      e.kind === 'raw'
        ? { kind: 'raw', text: e.text, comment: e.comment }
        : {
            kind: 'rule',
            name: e.name,
            enabled: e.enabled,
            match: e.match,
            conditions: e.conditions.map((c) => ({
              header: c.header,
              match_type: c.match_type,
              value: c.value,
              address_test: c.address_test,
              negate: c.negate,
              address_part: c.address_part,
              comparator: c.comparator,
            })),
            actions: e.actions.map((a) => ({ type: a.type, argument: a.argument })),
          }
    ),
  };
}

// ── Reading ──

/**
 * The Rule entries, in order. The editor's rule list renders these; Raw Blocks
 * are never shown but keep their place in `entries`.
 * @param {ScriptDocument} doc
 * @returns {RuleEntry[]}
 */
export function ruleEntries(doc) {
  return doc.entries.filter((e) => e.kind === 'rule');
}

// ── Preview ──

/** Escape a string for use inside Sieve double quotes (mirrors the backend). */
function quote(s) {
  return String(s ?? '').replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

/** Render one test exactly as the backend generator would. */
function renderTest(c) {
  let out = c.negate ? 'not ' : '';
  out += c.address_test ? 'address' : 'header';
  if (c.address_part) out += ` :${c.address_part}`;
  if (c.comparator) out += ` :comparator "${quote(c.comparator)}"`;
  out += ` :${c.match_type} "${quote(c.header)}" "${quote(c.value)}"`;
  return out;
}

/** Render one action exactly as the backend generator would. */
function renderAction(a) {
  switch (a.type) {
    case 'fileinto':
      return `fileinto "${quote(a.argument)}";`;
    case 'fileinto_copy':
      return `fileinto :copy "${quote(a.argument)}";`;
    case 'redirect':
      return `redirect "${quote(a.argument)}";`;
    case 'keep':
      return 'keep;';
    case 'discard':
      return 'discard;';
    case 'stop':
      return 'stop;';
    case 'addflag':
      return `addflag "${quote(a.argument)}";`;
    case 'reject':
      return `reject "${quote(a.argument)}";`;
    default:
      return `# unknown action: ${a.type}`;
  }
}

/**
 * Render a Rule as the Sieve it will actually be saved as.
 *
 * This lives here, not in the component, because it is a second implementation
 * of the backend generator and the two must agree. The component's version
 * silently diverged on three counts — it dropped `negate` (so a NOT condition
 * previewed as its positive), did no quote escaping, and showed a disabled
 * rule as live. The preview is the feature that tells users what will be
 * saved, so a divergence here is a lie with consequences.
 *
 * @param {RuleEntry} rule
 * @returns {string}
 */
export function previewRule(rule) {
  if (!rule || !rule.conditions.length) return '';

  const tests = rule.conditions.map(renderTest);
  const actions = rule.actions.map((a) => `    ${renderAction(a)}`);

  const head =
    tests.length === 1 && !rule.match
      ? `if ${tests[0]} {`
      : `if ${rule.match || 'anyof'} (\n${tests.map((t) => `    ${t}`).join(',\n')}\n) {`;

  const body = [head, ...actions, '}'].join('\n');

  // A disabled rule is stored commented out; preview it that way.
  return rule.enabled
    ? body
    : body
        .split('\n')
        .map((line) => (line.trim() ? `## ${line}` : '##'))
        .join('\n');
}

// ── Mutations (each returns a new document) ──

/**
 * A blank Condition, keyed. Key minting lives here so no component has to
 * know that render keys exist, let alone that they must not cross the wire.
 * @returns {Condition}
 */
export function newCondition() {
  return {
    key: key(),
    header: 'from',
    match_type: 'contains',
    value: '',
    address_test: true,
    negate: false,
    address_part: '',
    comparator: '',
  };
}

/**
 * A blank Action, keyed.
 * @returns {Action}
 */
export function newAction() {
  return { key: key(), type: 'fileinto', argument: '' };
}

/**
 * Append a new Rule with one blank condition and a default action.
 * @param {ScriptDocument} doc
 * @returns {ScriptDocument}
 */
export function addRule(doc) {
  /** @type {RuleEntry} */
  const rule = {
    key: key(),
    kind: 'rule',
    name: 'New Rule',
    enabled: true,
    match: 'anyof',
    conditions: [newCondition()],
    actions: [{ ...newAction(), argument: 'INBOX' }],
  };
  return { ...doc, entries: [...doc.entries, rule] };
}

/**
 * Delete the Rule at `index` within the rule list (not within `entries`).
 * @param {ScriptDocument} doc
 * @param {number} index
 * @returns {ScriptDocument}
 */
export function deleteRule(doc, index) {
  const target = ruleEntries(doc)[index];
  if (!target) return doc;
  return { ...doc, entries: doc.entries.filter((e) => e !== target) };
}

/**
 * Move a Rule from one position in the rule list to another.
 *
 * Raw Blocks keep their absolute slots in `entries` — reordering rules must
 * never drag unparsed Sieve around, since the user can't see it to notice.
 * @param {ScriptDocument} doc
 * @param {number} from
 * @param {number} to
 * @returns {ScriptDocument}
 */
export function moveRule(doc, from, to) {
  const rules = ruleEntries(doc);
  if (from === to) return doc;
  if (from < 0 || from >= rules.length) return doc;
  if (to < 0 || to >= rules.length) return doc;

  const reordered = [...rules];
  const [moved] = reordered.splice(from, 1);
  reordered.splice(to, 0, moved);

  // Write the new rule order back into the slots rules already occupied.
  let n = 0;
  const entries = doc.entries.map((e) => (e.kind === 'rule' ? reordered[n++] : e));
  return { ...doc, entries };
}
