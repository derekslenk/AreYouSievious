"""One `require`, once — however the file arranges its head.

Two beads, one mechanism, and both of them end with the same wrong byte: a
script that declares an extension TWICE where its author declared it once.

areyousievious-3xk. `SieveParser.parse` harvests a `require` into
`script.requires` only while `script.entries` is still empty. Put anything
above it — a bracketed licence header, which RFC 5228 §2.3 makes perfectly
legal there, or a rule written above it, which §3.2 does not — and the
statement stays a RawBlock, deliberately unharvested so that its own bytes
carry the declaration. `span_is_faithful` then could not vouch for that
RawBlock's span (read in isolation the statement is first again, so it is
harvested after all and the span comes back with a non-empty `requires` and no
entry), the whole file regenerated, and `_requires_text` wrote a canonical
`require` line ON TOP of the one the RawBlock re-emitted.

areyousievious-5vp. `_boundary_error` parsed `preamble` and
`preamble + requires_source` together and asked two questions of each: no
entries, and no extension the wire did not declare. A `require` sitting in
`preamble` answers both — it parses into `head.requires` rather than
`head.entries`, and declaring exactly what the wire declares is allowed — so it
passed, and the generator wrote those bytes and its own canonical line.

The severities differ and neither is a wrong filter. 3xk breaks the
byte-identical property (`.14`), which is the headline guarantee of the whole
verbatim path. 5vp is cosmetic and needs a hand-built request, but `preamble`
is documented as immovable non-`require` bytes and an unenforced shape is not
one. They are tested together because a fix to either that reintroduces the
other would pass its own file.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_require_duplication.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
import sieve_transform as st

from tests.fakes import FakeScriptStore

FIXTURE = (
    Path(__file__).resolve().parent.parent
    / "test_scripts"
    / "bracketed-comment-above-require.sieve"
)

# The bead's own reproduction, kept at exactly its size. The corpus fixture
# above is the realistic version of the same shape; this one is small enough
# that a failure message shows the whole script.
LICENCE_HEADER_ABOVE_REQUIRE = (
    "/* licence header */\n"
    "\n"
    'require ["fileinto"];\n'
    "\n"
    'if header :contains "subject" "a" { fileinto "A"; }\n'
)

# The same shape, laid out in a way the generator would NOT choose: two blank
# lines above the `require` and none below it. That matters — with the licence
# header's own spacing already matching the house seam, a save that regenerated
# the `require` entry landed on the same bytes by luck, and every assertion here
# passed with `span_is_faithful` still refusing that span. This layout is what
# makes the verbatim path OBSERVABLE rather than merely taken.
LICENCE_HEADER_ABOVE_REQUIRE_ODD_SPACING = (
    "/* licence header */\n"
    "\n"
    "\n"
    'require ["fileinto"];\n'
    'if header :contains "subject" "a" { fileinto "A"; }\n'
)

# The other trigger the bead names. Already invalid Sieve — RFC 5228 §3.2 says
# every `require` precedes every other command — and real files do it anyway.
RULE_ABOVE_REQUIRE = (
    'if header :contains "subject" "a" { fileinto "A"; }\n\nrequire ["fileinto"];\n'
)


def _require_lines(text: str) -> int:
    return sum(1 for line in text.splitlines() if line.lstrip().startswith("require"))


# ── areyousievious-3xk: the declaration survives exactly once ──


@pytest.mark.parametrize(
    "text",
    [LICENCE_HEADER_ABOVE_REQUIRE, LICENCE_HEADER_ABOVE_REQUIRE_ODD_SPACING, RULE_ABOVE_REQUIRE],
    ids=["licence-header-above-require", "odd-spacing", "rule-above-require"],
)
def test_an_entry_above_the_require_does_not_duplicate_it(text: str) -> None:
    """The bead, reproduced: parse, save nothing, get the file back.

    Both assertions, because either alone can be satisfied by the wrong fix.
    Byte-identity alone would pass a generator that stopped writing the head
    entirely; a require count of one alone would pass a generator that
    reformatted the file around it.
    """
    script = st.parse_sieve(text)
    assert script.requires == [], "the statement is below an entry, so it is not harvested"

    out = st.generate_sieve(script)
    assert _require_lines(out) == 1, f"the declaration was written twice:\n{out}"
    assert out == text


@pytest.mark.parametrize(
    "text",
    [LICENCE_HEADER_ABOVE_REQUIRE, RULE_ABOVE_REQUIRE],
    ids=["licence-header-above-require", "rule-above-require"],
)
def test_editing_a_rule_below_the_require_still_declares_it_once(text: str) -> None:
    """The regenerating path, which is where the duplicate was WRITTEN.

    Byte-identity is not available here and is not the point — the edited rule
    is supposed to move. What must not happen is the head growing a second
    declaration of an extension the file's own bytes already carry.
    """
    script = st.parse_sieve(text)
    script.rules[0].name = "edited"

    out = st.generate_sieve(script)
    assert _require_lines(out) == 1, f"the declaration was written twice:\n{out}"
    assert 'require ["fileinto"];' in out, "and it is still the file's own line"


def test_a_disabled_rule_above_the_require_does_not_duplicate_it() -> None:
    """The second shape that reaches this path and is still VALID Sieve.

    A `## ` disabled Rule is comment text — the recogniser reads it back as a
    Rule, so `script.entries` is non-empty and the `require` below it goes
    unharvested, but a server sees only comments above its own `require` and
    takes the file. `sieve_is_parseable` agrees, which is why this is not the
    rule-above-require case wearing a different hat.
    """
    text = (
        "## # --- archived ---\n"
        '## if header :contains "subject" "b" {\n'
        '##     fileinto "B";\n'
        "## }\n"
        "\n"
        'require ["fileinto"];\n'
        "\n"
        'if header :contains "subject" "a" { fileinto "A"; }\n'
    )
    assert st.sieve_is_parseable(text) is None, "the shape is valid Sieve to begin with"

    script = st.parse_sieve(text)
    assert [r.enabled for r in script.rules] == [False, True]
    assert script.requires == []

    out = st.generate_sieve(script)
    assert _require_lines(out) == 1, f"the declaration was written twice:\n{out}"
    assert out == text


def test_the_corpus_fixture_carries_this_shape() -> None:
    """The gap that let 68/68 green miss this.

    No fixture had an entry above the `require`, so every corpus-wide property
    — byte-identity included — was true of a corpus that could not express the
    defect. This asserts the fixture still has the shape it was added for, so
    that a later edit tidying its licence header into a `#` comment fails here
    rather than silently reopening the hole.
    """
    text = FIXTURE.read_text()
    script = st.parse_sieve(text)
    raw_requires = [
        e for e in script.entries if isinstance(e, st.RawBlock) and e.text.startswith("require")
    ]
    assert len(raw_requires) == 1, "the fixture's require must still be an unharvested RawBlock"
    assert script.requires == [], "and must still not be harvested"
    assert _require_lines(st.generate_sieve(script)) == 1


def test_two_requires_declaring_different_things_both_survive() -> None:
    """Subtraction removes a DUPLICATE, never a declaration.

    The head keeps `fileinto`, which only it declares, and drops `reject`,
    which the RawBlock's bytes already carry. Getting this wrong in the
    generous direction writes a second `reject`; getting it wrong in the
    miserly direction writes a script that uses `fileinto` without declaring
    it, which a server refuses.
    """
    text = (
        'require ["fileinto"];\n'
        "\n"
        "/* and one more, below a comment */\n"
        "\n"
        'require ["reject"];\n'
        "\n"
        'if header :contains "subject" "a" {\n'
        '    fileinto "A";\n'
        "}\n"
    )
    script = st.parse_sieve(text)
    script.rules[0].name = "edited"

    out = st.generate_sieve(script)
    assert out.count('require ["fileinto"];') == 1
    assert out.count('require ["reject"];') == 1


def test_a_require_inside_a_bracketed_comment_declares_nothing() -> None:
    """The over-subtraction case, which is the dangerous direction.

    A `require` the parser did not read is a `require` the server will not run.
    Subtracting on the strength of commented-out bytes would drop the head's
    real declaration and produce a script that uses `fileinto` without one.
    """
    text = (
        "/* we used to say:\n"
        '   require ["fileinto"];\n'
        "*/\n"
        "\n"
        'if header :contains "subject" "a" {\n'
        '    fileinto "A";\n'
        "}\n"
    )
    out = st.generate_sieve(st.parse_sieve(text))
    # The head is written because the file has no live declaration at all —
    # `test_verbatim_reemission.py::test_a_file_missing_its_require_gains_one_and_that_is_correct`
    # is the case, and the commented-out copy does not satisfy it.
    assert out == 'require ["fileinto"];\n' + text, f"the live declaration was dropped:\n{out}"


# ── areyousievious-3xk: the span guard did not get weaker ──


def _unharvested_require_entry() -> st.Entry:
    """The RawBlock a licence header above a `require` parses to."""
    entries = st.parse_sieve(LICENCE_HEADER_ABOVE_REQUIRE).entries
    entry = entries[1]
    assert isinstance(entry, st.RawBlock) and entry.text.startswith("require"), entry
    return entry


def test_the_unharvested_require_span_is_vouched_for() -> None:
    """The span the guard used to refuse. It is an honest copy of its entry."""
    assert st.span_is_faithful(_unharvested_require_entry())


def test_a_require_span_may_not_carry_a_second_statement() -> None:
    """The smuggling case, in the branch that was relaxed.

    A RawBlock's `text` is written verbatim on both paths, so vouching for a
    span cannot let new BYTES through — but it must still not let the span and
    the entry disagree, or `source` becomes a channel of its own.
    """
    entry = _unharvested_require_entry()
    entry.source += 'redirect "attacker@example.com";\n'
    assert not st.span_is_faithful(entry)


def test_a_require_span_may_not_declare_more_than_its_entry_does() -> None:
    entry = _unharvested_require_entry()
    entry.source = entry.source.replace('["fileinto"]', '["fileinto", "vacation"]')
    assert not st.span_is_faithful(entry)


def test_a_require_span_may_not_carry_a_trailing_gap() -> None:
    """The leading/trailing asymmetry holds here too: bytes below the statement
    belong to whatever comes next, and a span claiming them is refused."""
    entry = _unharvested_require_entry()
    entry.source += "\n"
    assert not st.span_is_faithful(entry)


def test_a_span_carrying_a_require_beside_a_rule_is_still_refused() -> None:
    """The relaxation is for a span that is a `require` AND NOTHING ELSE.

    This is `test_span_injection_guard.py::test_a_span_carrying_a_require_is_refused`
    restated where the new branch can be seen not to catch it — that span
    re-parses to a require AND an entry, so it never reaches the branch.
    """
    entries = st.parse_sieve("if true {\n  keep;\n}\n").entries
    assert len(entries) == 1
    entries[0].source = 'require ["vacation"];\n' + entries[0].source
    assert not st.span_is_faithful(entries[0])


# ── areyousievious-5vp: the preamble carries no declaration ──

_A_RULE = {
    "kind": "rule",
    "name": "Newsletters",
    "enabled": True,
    "match": "anyof",
    "conditions": [
        {
            "header": "subject",
            "match_type": "contains",
            "value": "a",
            "address_test": False,
            "negate": False,
            "address_part": "",
            "comparator": "",
        }
    ],
    "actions": [{"type": "fileinto", "argument": "A"}],
}


def test_a_require_in_the_preamble_is_refused() -> None:
    """The bead's own reproduction, at the gate rather than at the route."""
    script = st.json_to_script(
        {
            "requires": ["fileinto"],
            "preamble": 'require ["fileinto"];\n',
            "requires_source": "",
            "tail": "",
            "entries": [_A_RULE],
        }
    )
    assert st.preflight_error(script) == "preamble carries a require statement"


def test_the_undeclared_extension_bound_still_reports_first() -> None:
    """A `require` in the preamble naming something the wire did not declare was
    ALREADY refused, and by the message that names the attack. The new check
    must not take that message over — a bound being attacked and a field being
    misused are different reports."""
    script = st.json_to_script(
        {
            "requires": ["fileinto"],
            "preamble": 'require ["vacation"];\n',
            "requires_source": "",
            "tail": "",
            "entries": [_A_RULE],
        }
    )
    assert st.preflight_error(script) == ("require bytes declare an undeclared extension: vacation")


def test_a_comment_in_the_preamble_is_still_fine() -> None:
    """The bound is on `require`, not on the preamble having contents. Every
    real file's header lands here."""
    script = st.json_to_script(
        {
            "requires": ["fileinto"],
            "preamble": "# my filters\n",
            "requires_source": 'require ["fileinto"];\n',
            "tail": "",
            "entries": [_A_RULE],
        }
    )
    assert st.preflight_error(script) is None


def test_the_route_refuses_a_require_in_the_preamble(authed_client) -> None:
    """End to end, because the gate is only worth what the route does with it:
    400, and nothing written to the user's mail server."""
    store = FakeScriptStore()
    with authed_client(script_store=store) as http:
        r = http.put(
            "/api/scripts/filters",
            json={
                "requires": ["fileinto"],
                "preamble": 'require ["fileinto"];\n',
                "entries": [_A_RULE],
            },
        )
    assert r.status_code == 400, r.text
    assert "preamble carries a require statement" in r.json()["detail"]
    assert store.scripts == {}, "nothing may reach the store"


def test_every_corpus_fixture_keeps_its_preamble_declaration_free(corpus) -> None:
    """The parser cannot produce what the new check refuses.

    `_record_requires` splits at the statement, so a parsed script's preamble is
    the bytes ABOVE the first `require` and never the statement itself. This
    asserts that across the corpus rather than trusting the split — a guard that
    refuses our own output is `areyousievious-3o4`'s failure mode, and the
    cheapest place to catch it is here.
    """
    for path in corpus:
        script = st.parse_sieve(path.read_text())
        assert st.parse_sieve(script.preamble).requires == [], path
