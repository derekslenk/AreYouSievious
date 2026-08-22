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
 * The editable types are the WIRE types plus a render key, imported from the
 * generated `api-types.d.ts` rather than restated here (areyousievious-8fg.18).
 * They used to be hand-written, and were already looser than the schema — this
 * block said `address_part: string` where the schema pins a four-value union.
 * Worse, nothing in the SPA imported the generated file at all: CI checked the
 * artifact was CURRENT, never that any code CONSUMED it, so the alarm could not
 * ring. Now `toWire` is declared to return the wire types, which makes it a
 * checked whitelist: add a field to `ConditionDTO` and this file stops
 * compiling, instead of every save silently discarding it — precisely the
 * `:domain` loss the parser memorialises below.
 *
 * @import { components } from './api-types.d.ts'
 * @typedef {components['schemas']['ConditionDTO']} WireCondition
 * @typedef {components['schemas']['ActionDTO']} WireAction
 * @typedef {components['schemas']['RuleDTO']} WireRule
 * @typedef {components['schemas']['RawBlockDTO']} WireRaw
 *
 * @typedef {WireCondition & {key: string}} Condition
 * @typedef {WireAction & {key: string}} Action
 * @typedef {Omit<WireRule, 'conditions' | 'actions'>
 *           & {key: string, conditions: Condition[], actions: Action[]}} RuleEntry
 * @typedef {WireRaw & {key: string}} RawEntry
 * @typedef {RuleEntry | RawEntry} Entry
 * @typedef {{requires: string[], entries: Entry[]}} ScriptDocument
 */

// ── Vocabularies ──
//
// These lived inside the builder components, where nothing could test them
// and where ConditionBuilder re-derived address_test from its own private
// header list. The components render these; they do not define them.

/**
 * Headers SUGGESTED by the Condition builder. Not a vocabulary: the field is
 * free text backed by a `<datalist>`, because any quoted string is a legal
 * Sieve header. Rendering it as a `<select>` lost data — a Condition on
 * `x-spam-flag` matched no option, showed an empty dropdown, and kept its real
 * value only until the user opened that select (areyousievious-8fg.18).
 */
export const HEADERS = [
  { value: 'from', label: 'From' },
  { value: 'to', label: 'To' },
  { value: 'cc', label: 'CC' },
  { value: 'subject', label: 'Subject' },
  { value: 'reply-to', label: 'Reply-To' },
  { value: 'list-id', label: 'List-ID' },
];

/** Match types offered by the Condition builder. */
export const MATCH_TYPES = [
  { value: 'contains', label: 'contains' },
  { value: 'is', label: 'is exactly' },
  { value: 'matches', label: 'matches (glob)' },
  { value: 'regex', label: 'regex' },
];

/** Actions offered by the Action builder. `hasArg` drives the argument
 * input and `placeholder` is its hint text. */
export const ACTION_TYPES = [
  { value: 'fileinto', label: 'Move to folder', hasArg: true, placeholder: 'Folder name' },
  { value: 'fileinto_copy', label: 'Copy to folder', hasArg: true, placeholder: 'Folder name' },
  { value: 'redirect', label: 'Redirect to', hasArg: true, placeholder: 'email@example.com' },
  { value: 'keep', label: 'Keep in INBOX', hasArg: false },
  { value: 'discard', label: 'Delete', hasArg: false },
  { value: 'stop', label: 'Stop processing', hasArg: false },
  { value: 'addflag', label: 'Add flag', hasArg: true, placeholder: '\\Seen' },
  { value: 'reject', label: 'Reject with message', hasArg: true, placeholder: 'value' },
];

/**
 * The vocabulary entry for an action type. Interpreting ACTION_TYPES belongs
 * here, next to the vocabulary, where it is testable.
 * @param {string} type
 * @returns {{value: string, label: string, hasArg: boolean, placeholder?: string} | undefined}
 */
export function actionSpec(type) {
  return ACTION_TYPES.find((a) => a.value === type);
}

/** Headers whose natural test is `address` rather than `header`. */
const ADDRESS_HEADERS = new Set(['from', 'to', 'cc', 'reply-to']);

/**
 * Default a Condition's address_test from its header.
 *
 * Apply this to the ONE condition whose header the user just picked — never
 * to a whole rule. address_test is not derivable from a parsed Condition
 * (`header :contains "from"` is legal Sieve; the parser records what the
 * source said), so re-deriving siblings silently rewrites what their rule
 * matches. That was the old component behaviour: one keystroke anywhere
 * flipped every parsed header-test on from/to/cc/reply-to into an address
 * test.
 * @param {Condition} condition
 * @returns {Condition}
 */
export function deriveAddressTest(condition) {
  return { ...condition, address_test: ADDRESS_HEADERS.has(condition.header) };
}

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
 * One entry as the wire carries it — view state stripped.
 *
 * Exported because the preview endpoint takes ONE Rule, and it must be the
 * same projection a save uses: a preview built from a differently-shaped
 * payload would be back to previewing something other than what gets saved.
 *
 * The backend DTOs are `extra="forbid"`, so a leaked `key` here is a 422.
 * That strictness is deliberate: a silent accept would write junk fields.
 *
 * The return type is the GENERATED wire type, not `object`. That is what turns
 * this whitelist from a convention into a check: it cannot leak a render key
 * (it names every field it copies), and it can no longer silently DROP one
 * either, because a field added to the schema makes this function stop
 * type-checking.
 * @param {Entry} e
 * @returns {WireRule | WireRaw}
 */
export function entryToWire(e) {
  return e.kind === 'raw'
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
      };
}

/**
 * Strip view state and produce the wire payload for a whole Script.
 * @param {ScriptDocument} doc
 * @returns {{requires: string[], entries: (WireRule | WireRaw)[]}}
 */
export function toWire(doc) {
  return { requires: doc.requires, entries: doc.entries.map(entryToWire) };
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


/**
 * Patch fields on the entry with render key `key`. Untouched entries keep
 * their identity, so Svelte's keyed `{#each}` does not re-render them.
 * @param {ScriptDocument} doc
 * @param {string} key
 * @param {object} patch
 * @returns {ScriptDocument}
 */
export function updateEntry(doc, key, patch) {
  return { ...doc, entries: doc.entries.map((e) => (e.key === key ? { ...e, ...patch } : e)) };
}

/**
 * Replace a Rule's conditions wholesale. The builder computes the next array
 * and hands it over; the document applies it as one mutation.
 * @param {ScriptDocument} doc
 * @param {string} key
 * @param {Condition[]} conditions
 * @returns {ScriptDocument}
 */
export function setConditions(doc, key, conditions) {
  return updateEntry(doc, key, { conditions });
}

/**
 * Replace a Rule's actions wholesale.
 * @param {ScriptDocument} doc
 * @param {string} key
 * @param {Action[]} actions
 * @returns {ScriptDocument}
 */
export function setActions(doc, key, actions) {
  return updateEntry(doc, key, { actions });
}

/**
 * Move one item within a list, returning a new list — or the SAME list when
 * the move is a no-op, so callers can cheaply detect "nothing happened".
 * Condition and action reordering is the same problem `moveRule` solves.
 * @template T
 * @param {T[]} list
 * @param {number} from
 * @param {number} to
 * @returns {T[]}
 */
export function moveItem(list, from, to) {
  if (from === to) return list;
  if (from < 0 || from >= list.length) return list;
  if (to < 0 || to >= list.length) return list;
  const next = [...list];
  const [moved] = next.splice(from, 1);
  next.splice(to, 0, moved);
  return next;
}

// ── Pristine copy ──

/**
 * A deep copy for keeping the as-loaded document. Dirty state is "the wire
 * content diverged from this", and the verbatim re-emission work needs the
 * untouched original to compare against.
 * @param {ScriptDocument} doc
 * @returns {ScriptDocument}
 */
export function snapshot(doc) {
  return structuredClone(doc);
}

/**
 * Wire-content equality: true when both documents would save identical
 * payloads. Render keys never cross the wire, so they never affect this.
 * @param {ScriptDocument} a
 * @param {ScriptDocument} b
 * @returns {boolean}
 */
export function sameWire(a, b) {
  return JSON.stringify(toWire(a)) === JSON.stringify(toWire(b));
}
