"""
The projection is NARROWING (areyousievious-8fg.11).

`.10` gave the parser a lexical model, so it can no longer mis-segment a
script. This is the other half: what it does with a span it segmented
correctly but only PARTLY understands.

Until now, partly-understood meant projected anyway. A block whose `allof`
held one `header` test and two `date` tests came back as a Rule carrying the
header test alone — and regenerating wrote a script with the `date` tests
gone. Measured on a vendored fixture:

    if allof(header :is "from" "boss@example.com",
             date :value "ge" :originalzone "date" "hour" "09",
             date :value "lt" :originalzone "date" "hour" "17")
    { fileinto "urgent"; }

    ->  if allof ( header :is "from" "boss@example.com" ) { fileinto "urgent"; }

A rule that filed the boss's mail during office hours now files it at every
hour of the day. Nothing failed; it round-tripped cleanly.

So the rule is: a span becomes a Rule only if EVERY construct in it is one we
model. Anything else is a RawBlock carrying its verbatim bytes. Reach is
bounded by what the visual builder can render, deliberately — this is not a
gap to close later by teaching the projection more constructs.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_narrowing_projection.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
import sieve_transform as st

BACKEND = Path(__file__).resolve().parent.parent


# ── A test we do not model is not silently dropped ──


DATE_RULE = """require ["date", "relational", "fileinto"];

if allof(header :is "from" "boss@example.com",
         date :value "ge" :originalzone "date" "hour" "09",
         date :value "lt" :originalzone "date" "hour" "17")
{ fileinto "urgent"; }
"""


def test_a_condition_we_cannot_represent_keeps_the_whole_block_raw() -> None:
    """The office-hours rule. Both `date` tests must survive, and the only way
    they can is for the block never to become a Rule at all."""
    script = st.parse_sieve(DATE_RULE)

    assert script.rules == [], "a partly-understood block must not project"
    (raw,) = script.raw_blocks
    assert raw.text.count("date :value") == 2, raw.text
    assert raw.text in DATE_RULE, "verbatim bytes, not a reconstruction"


def test_the_office_hours_rule_survives_a_save() -> None:
    """The property a user would notice: regenerate, and the hours are still
    there. This is what failed before — silently, with valid Sieve out."""
    generated = st.generate_sieve(st.parse_sieve(DATE_RULE))
    assert generated.count("date :value") == 2, generated
    assert '"09"' in generated and '"17"' in generated


def test_the_extensions_such_a_block_needs_are_not_pruned() -> None:
    """`require` is derived from content, so an unrecognised block would lose
    its extensions if the derivation only looked at Rules. It does not: a
    RawBlock's requirements are unknowable, so its declared set is kept."""
    generated = st.generate_sieve(st.parse_sieve(DATE_RULE))
    for extension in ("date", "relational", "fileinto"):
        assert f'"{extension}"' in generated, generated


# ── An action we do not model is not silently dropped ──


def test_a_command_we_do_not_model_keeps_the_whole_block_raw() -> None:
    """This was pinned `xfail(strict=True)` by `.10`, naming this bead.

    `setflag` is valid Sieve we have no Action for. The block matched our
    regexes, so it projected onto a Rule carrying only `fileinto` — and
    regenerating wrote the script with `setflag` gone.
    """
    src = (
        'require ["fileinto", "imap4flags"];\n\n'
        'if header :is "subject" "alpha" {\n'
        '    fileinto "Filed";\n'
        '    setflag "\\\\Seen";\n'
        "}\n"
    )
    script = st.parse_sieve(src)

    assert script.rules == []
    assert "setflag" in st.generate_sieve(script)


@pytest.mark.parametrize(
    "body",
    [
        pytest.param('    vacation "away";', id="vacation"),
        pytest.param('    notify :message "hi" "mailto:x@y.com";', id="notify"),
        pytest.param('    addheader "X-Tag" "v";', id="addheader"),
    ],
)
def test_the_same_holds_for_every_command_outside_the_vocabulary(body: str) -> None:
    """Not a list of special cases — anything outside `ACTION_TYPES`."""
    src = f'require ["fileinto"];\n\nif header :is "a" "b" {{\n    fileinto "X";\n{body}\n}}\n'
    script = st.parse_sieve(src)
    assert script.rules == []
    assert body.strip().split()[0] in st.generate_sieve(script)


def test_reach_is_bounded_by_the_builder_and_not_by_the_parser() -> None:
    """The subtle one, stated as a test so it is not quietly "improved" later.

    sievelib understands `vacation` perfectly well. That is irrelevant: the
    projection decides Rule-vs-RawBlock, and it answers "can the visual builder
    render this", not "can something parse it". Teaching the projection more
    constructs is a product decision about the BUILDER, not a parser upgrade.
    """
    src = 'require ["vacation"];\n\nif header :is "a" "b" {\n    vacation "away";\n}\n'
    assert st.parse_sieve(src).rules == []


# ── Nesting the projection cannot say ──


NESTED_LIST = """require ["fileinto"];

if allof(anyof(header :is "from" "a", header :is "from" "b"),
         header :is "subject" "c") { fileinto "X"; }
"""


def test_a_nested_test_list_stays_raw() -> None:
    """Raised in review of this PR, and it is the SAME corruption class as the
    office-hours rule above — reached through nesting rather than through an
    unmodelled test.

    `allof(anyof(a, b), c)` means `(a OR b) AND c`. Every word in it is one we
    model, so the vocabulary gate has nothing to object to; but `_parse_tests`
    scans the list text with no parenthesis-awareness and returned three
    conditions, which regenerate as `a AND b AND c`. Measured before the fix:

        match='allof' conds=[('from','a'), ('from','b'), ('subject','c')]

    A message from `b` with subject `c` matched before and would not after. A
    Rule has ONE flat `match`; nesting cannot be said in it, so the block stays
    raw. A vocabulary check is not a grammar check.
    """
    script = st.parse_sieve(NESTED_LIST)

    assert script.rules == [], "a nested test list has no flat representation"
    (raw,) = script.raw_blocks
    assert "anyof(" in raw.text and "allof(" in raw.text
    assert raw.text in NESTED_LIST, "verbatim"


def test_the_nested_list_survives_a_save() -> None:
    generated = st.generate_sieve(st.parse_sieve(NESTED_LIST))
    assert "anyof(" in generated and "allof(" in generated


@pytest.mark.parametrize(
    ("shape", "rules"),
    [
        pytest.param('if allof (header :is "a" "b", header :is "c" "d")', 1, id="one flat list"),
        pytest.param('if header :is "a" "b"', 1, id="no list at all"),
        pytest.param('if allof (anyof (header :is "a" "b"), header :is "c" "d")', 0, id="nested"),
        pytest.param(
            'if anyof (allof (header :is "a" "b", header :is "c" "d"))',
            0,
            id="nested the other way",
        ),
    ],
)
def test_only_nesting_is_refused(shape: str, rules: int) -> None:
    """The gate counts parenthesis TOKENS, so it must not fire on the ordinary
    single-list shape most real scripts use, nor miss either nesting order."""
    script = st.parse_sieve(f'require ["fileinto"];\n\n{shape} {{\n    fileinto "X";\n}}\n')
    assert len(script.rules) == rules, shape


def test_a_parenthesis_inside_a_string_is_not_nesting() -> None:
    """The lexical model again: a folder called `Mail (old)` must not read as a
    nested list and cost the user their rule."""
    script = st.parse_sieve(
        'require ["fileinto"];\n\nif allof (header :is "a" "b") {\n    fileinto "Mail (old)";\n}\n'
    )
    assert len(script.rules) == 1
    assert script.rules[0].actions[0].argument == "Mail (old)"


# ── The modifier-ordering gap ──


def test_an_address_part_after_the_match_type_is_still_a_rule() -> None:
    """RFC 5228's own example (rfc5228.txt line 1351) puts the address-part
    AFTER the match-type. The docstring claimed "any tagged-argument order"
    and the regex only captured modifiers BEFORE it, so this was half true.
    Measured:

        address :domain :is "from" "example.com"  -> rules=1  address_part='domain'
        address :is :all "from" "tim@example.com" -> rules=0  raw=1

    The model already carried `address_part`; only the regex disagreed.
    """
    script = st.parse_sieve(
        'require ["fileinto"];\n\n'
        'if address :is :all "from" "tim@example.com" {\n    fileinto "X";\n}\n'
    )
    (rule,) = script.rules
    (condition,) = rule.conditions
    assert condition.address_part == "all"
    assert condition.match_type == "is"
    assert condition.value == "tim@example.com"


@pytest.mark.parametrize(
    "test_source",
    [
        pytest.param('address :domain :is "from" "example.com"', id="part before"),
        pytest.param('address :is :domain "from" "example.com"', id="part after"),
        pytest.param(
            'address :comparator "i;octet" :is "from" "example.com"', id="comparator before"
        ),
        pytest.param(
            'address :is :comparator "i;octet" "from" "example.com"', id="comparator after"
        ),
        pytest.param(
            'address :domain :is :comparator "i;octet" "from" "example.com"', id="split either side"
        ),
    ],
)
def test_tagged_arguments_parse_in_any_order(test_source: str) -> None:
    """RFC 5228 §2.7.1 lets ADDRESS-PART, COMPARATOR and MATCH-TYPE appear in
    any order. Every ordering must reach the same Condition."""
    script = st.parse_sieve(
        f'require ["fileinto"];\n\nif {test_source} {{\n    fileinto "X";\n}}\n'
    )
    assert len(script.rules) == 1, f"{test_source} did not project"
    (condition,) = script.rules[0].conditions
    assert condition.match_type == "is"
    assert condition.header == "from"
    assert condition.value == "example.com"


def test_a_reordered_modifier_regenerates_in_rfc_order() -> None:
    """Accepting any order does not mean emitting any order — generation picks
    one (ADDRESS-PART, COMPARATOR, MATCH-TYPE) so the round trip has a fixed
    point.

    The spans are cleared because an unedited script is now re-emitted byte for
    byte (docs/adr/0002-the-file-is-a-sequence-of-spans.md); only an entry that
    regenerates reaches the canonical renderer this test is about.
    """

    def regenerate(src: str) -> str:
        script = st.parse_sieve(src)
        for entry in script.entries:
            entry.source = ""
        return st.generate_sieve(script)

    generated = regenerate(
        'require ["fileinto"];\n\n'
        'if address :is :all "from" "tim@example.com" {\n    fileinto "X";\n}\n'
    )
    assert 'address :all :is "from" "tim@example.com"' in generated
    assert generated == regenerate(generated)


# ── parse_sieve never raises ──


@pytest.mark.parametrize(
    "src",
    [
        pytest.param("", id="empty"),
        pytest.param("﻿keep;\n", id="byte order mark"),
        pytest.param("@@@ not sieve at all @@@\n", id="unlexable"),
        pytest.param('if header :is "a" "b" {\n', id="unclosed block"),
        pytest.param('require ["fileinto"];\nif {{{{{\n', id="brace soup"),
        pytest.param("keep;" * 5000, id="very long line"),
    ],
)
def test_parse_sieve_never_raises(src: str) -> None:
    """A caller distinguishes outcomes from the RESULT, never from an
    exception. Raising would turn a script we cannot read into a 500 and lock
    the user out of their own filters — the one thing worse than showing them
    a big RawBlock is showing them nothing at all.
    """
    script = st.parse_sieve(src)
    assert isinstance(script, st.SieveScript)


def test_a_file_we_understand_nothing_of_is_still_returned_whole() -> None:
    """ "Understood nothing" is a readable state, not an error: zero Rules and
    the content still present."""
    src = "@@@ not sieve at all @@@\n"
    script = st.parse_sieve(src)
    assert script.rules == []
    assert "@@@ not sieve at all @@@" in "\n".join(b.text for b in script.raw_blocks)


# ── Reach did not move except where it had to ──


def _without_requires(text: str) -> str:
    """The script minus its `require` statements.

    Naming an extension is not USING a construct, and conflating the two made
    the first draft of the sweep below fail on `grak.sieve`: it declares
    `envelope` and never tests one, so `.15`'s pruning correctly drops it and a
    keyword scan read that as a dropped construct. Requires are `.15`'s
    subject; what this sweep is looking for is a test or command that vanished.
    """
    kept, skipping = [], False
    for line in text.split("\n"):
        if not skipping and line.lstrip().startswith("require"):
            skipping = True
        if skipping:
            if ";" in line:
                skipping = False
            continue
        kept.append(line)
    return "\n".join(kept)


def test_every_rule_in_the_corpus_uses_only_modelled_constructs() -> None:
    """The invariant behind all of the above, over every fixture at once.

    If a Rule anywhere carries fewer conditions or actions than its source
    block contained, that is this bead's defect returning — and it returns
    silently, so nothing but a sweep like this would say so.
    """
    offenders = []
    for path in sorted((BACKEND / "test_scripts").rglob("*.sieve")):
        text = _without_requires(path.read_text())
        script = st.parse_sieve(path.read_text())
        if not script.rules:
            continue
        regenerated = _without_requires(st.generate_sieve(script))
        for keyword in ("date ", "notify", "vacation", "setflag", "envelope", "size :"):
            if keyword in text and keyword not in regenerated:
                offenders.append((path.name, keyword))
    assert not offenders, f"constructs dropped on regeneration: {offenders}"


def test_the_source_vocabulary_and_the_wire_vocabulary_stay_in_step() -> None:
    """`COMMAND_NAMES` is what appears in Sieve SOURCE; `ACTION_TYPES` is what
    appears on the WIRE. They are not the same list and must not be derived
    from one another — raised in review of this change, and correct:

      - `fileinto_copy` is a wire name for what the source spells
        `fileinto :copy`, so the Lexer can never emit it as an identifier.
        Leaving it in the modelled set was harmless but meaningless.
      - Deriving one from the other couples them the wrong way round. Widening
        `ACTION_TYPES` for the builder's DTOs (`.18`) would then silently widen
        what the PARSER is willing to project onto a Rule — a product decision
        about the editor quietly becoming a parser decision.

    So they are separate declarations, pinned to each other HERE. This is the
    check that the decoupling did not just become drift: exactly one difference
    is allowed, and it is named.
    """
    assert set(st.COMMAND_NAMES) == set(st.ACTION_TYPES) - {"fileinto_copy"}
    assert "fileinto_copy" not in st._MODELLED_IDENTIFIERS, (
        "a wire name in the source vocabulary means the two were conflated again"
    )


def test_widening_the_wire_vocabulary_does_not_widen_the_parser() -> None:
    """The consequence of the above, stated as behaviour rather than as set
    arithmetic: a command the builder gained a DTO for is still raw to the
    parser until `COMMAND_NAMES` says otherwise."""
    src = (
        'require ["fileinto"];\n\n'
        'if header :is "a" "b" {\n'
        '    fileinto "X";\n'
        '    setflag "\\\\Seen";\n'
        "}\n"
    )
    assert st.parse_sieve(src).rules == []
    assert "setflag" not in st.COMMAND_NAMES
