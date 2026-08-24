"""
The lexical model behind the recogniser (areyousievious-8fg.10).

The parser used to answer "where does this block end" with
`line.count("{") - line.count("}")` and "what are this block's actions" with a
regex over raw text. Neither knows what a string or a comment IS, and three
data-corrupting defects came out of that — all reachable from the UI, none of
which tripped the RawBlock safety net, because the parser did not FAIL. It
succeeded, misread, and regenerated valid Sieve that routed mail elsewhere.

`_LexicalMap` borrows sievelib's Lexer for the model we lacked. Two halves are
tested here:

  - THE DEFECTS, at the level a user would meet them: parse, then look at what
    the rule now says.
  - THE MECHANISM, because it rests on `Lexer.pos` meaning "the start of the
    token just yielded", which is TRUE but is not a documented API. A sievelib
    upgrade could change it, and the symptom would be silently mis-segmented
    scripts rather than an exception. That is what the pins at the bottom are
    for.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_lexical_map.py -v
"""

from __future__ import annotations

import concurrent.futures
from pathlib import Path

import pytest
import sieve_transform as st
from sievelib.parser import Lexer, Parser
from sievelib.parser import ParseError as SieveLibParseError

from tests.conftest import CORPUS, corpus_id

BACKEND = Path(__file__).resolve().parent.parent


# ── The three defects ──


def test_a_brace_in_a_folder_name_no_longer_swallows_the_next_rule() -> None:
    """Defect 1, and the worst of the three.

    `fileinto "Weird{Folder";` — the brace is INSIDE a string, but the block
    collector counted it, so the block never closed and the following rule was
    absorbed into it. Measured before the fix: one rule came back, carrying
    `subject is alpha` and BOTH actions. The second rule's condition was gone
    entirely, so mail matching `beta` stopped being filed and mail matching
    `alpha` was filed twice — from a script that regenerated as valid Sieve.
    """
    script = st.parse_sieve(
        (BACKEND / "test_scripts" / "lexical-brace-in-a-string.sieve").read_text()
    )

    assert len(script.rules) == 2, "the second rule was swallowed by the first"
    first, second = script.rules
    assert [c.value for c in first.conditions] == ["alpha"]
    assert [a.argument for a in first.actions] == ["Weird{Folder"]
    assert [c.value for c in second.conditions] == ["beta"], "the second rule lost its condition"
    assert [a.argument for a in second.actions] == ["Beta"]


def test_a_nested_if_is_not_flattened_into_its_parent() -> None:
    """Defect 2. `if A { if B { fileinto "X"; } }` came back as
    `if A { fileinto "X"; }` — condition B simply gone, so the filing happened
    on A alone.

    The fix is not to represent nesting (that is not what a Rule is) but to
    refuse it: the whole block is preserved verbatim as a RawBlock, which is
    what the safety net is for and what it never got the chance to do.
    """
    src = (BACKEND / "test_scripts" / "lexical-nested-if.sieve").read_text()
    script = st.parse_sieve(src)

    assert script.rules == [], "a nested block must not be projected onto a Rule"
    assert len(script.raw_blocks) == 1
    raw = script.raw_blocks[0].text
    assert "boss@example.com" in raw, "the inner condition must survive verbatim"
    assert raw in src, "a RawBlock is the promise that we hand back what we were given"


def test_a_commented_out_action_stays_commented_out() -> None:
    """Defect 3. `# fileinto "Disabled";` inside a block was matched by the
    action regex and came back LIVE, so a user who disabled a rule's action by
    commenting it out had it re-enabled by opening the editor."""
    script = st.parse_sieve(
        (BACKEND / "test_scripts" / "lexical-commented-action.sieve").read_text()
    )

    (rule,) = script.rules
    assert [a.argument for a in rule.actions] == ["Live"]
    # The old assertion was "Disabled" is absent from the output, which held
    # only because generation dropped every comment inside a block. Verbatim
    # re-emission keeps the user's own line, so the check is now the thing the
    # test is actually named for: it is still a COMMENT, never a live action.
    out = st.generate_sieve(script)
    assert [ln for ln in out.split("\n") if "Disabled" in ln] == ['    # fileinto "Disabled";'], out


def test_none_of_the_three_ever_failed_loudly() -> None:
    """Why these are corruption and not bugs anyone would have reported.

    Each one produced a script that PARSES and REGENERATES cleanly. There was
    no exception, no RawBlock, and nothing in the output to look wrong — only
    different mail routing. Asserted against the fixtures so the class of
    defect stays named: silent misreading is what the lexical model prevents,
    and a test that only checked "does it crash" would have passed throughout.
    """
    for name in (
        "lexical-brace-in-a-string.sieve",
        "lexical-nested-if.sieve",
        "lexical-commented-action.sieve",
    ):
        src = (BACKEND / "test_scripts" / name).read_text()
        first = st.generate_sieve(st.parse_sieve(src))
        assert first == st.generate_sieve(st.parse_sieve(first)), name


# ── The mechanism ──


def _tokens(raw: bytes) -> list[tuple[int, str, bytes]]:
    lexer = Lexer(Parser.lrules)
    return [(lexer.pos, name, value) for name, value in lexer.scan(raw)]


SAMPLE = b"""require ["fileinto"];

# --- weird ---
if header :is "subject" "alpha" {
    fileinto "Weird{Folder";
    # fileinto "Disabled";
}
"""


def test_lexer_pos_is_the_start_of_the_token_just_yielded() -> None:
    """THE UNDOCUMENTED API THIS RESTS ON.

    `Lexer.scan` is a generator: it suspends at `yield` and advances `self.pos`
    only afterwards, so reading `pos` at each yield gives the token's START
    offset. Nothing in sievelib promises that. If an upgrade moved the
    increment above the yield, every offset would be off by one token and the
    map would mis-attribute braces to lines — silently.

    So: every token's recorded offset must reproduce that token's bytes.
    """
    for start, name, value in _tokens(SAMPLE):
        assert SAMPLE[start : start + len(value)] == value, f"{name} at {start} does not line up"


def test_a_brace_inside_a_string_is_not_a_brace_token() -> None:
    """The property that fixes defect 1, asserted about the Lexer itself
    rather than only about its consequences."""
    braces = [(s, n) for s, n, _ in _tokens(SAMPLE) if n.endswith("cbracket")]
    assert [n for _, n in braces] == ["left_cbracket", "right_cbracket"], (
        f"expected one real block, got {braces}"
    )
    strings = [v for _, n, v in _tokens(SAMPLE) if n == "string"]
    assert b'"Weird{Folder"' in strings, "the brace must be inside a single string token"


def test_a_commented_action_is_one_comment_token() -> None:
    """The property that fixes defect 3."""
    comments = [v for _, n, v in _tokens(SAMPLE) if n == "hash_comment"]
    assert b'# fileinto "Disabled";' in comments


# ── What the map does with all that ──


def test_masking_preserves_length_so_offsets_still_land() -> None:
    """Comments are blanked to spaces rather than removed. Removing them would
    renumber every line after the first one and the block ranges would point
    somewhere else."""
    text = SAMPLE.decode()
    lex = st._LexicalMap(text)
    assert lex.usable
    original = text.split("\n")
    assert len(lex.masked_lines) == len(original)
    for masked, source in zip(lex.masked_lines, original, strict=True):
        assert len(masked) == len(source)
    assert "Disabled" not in "\n".join(lex.masked_lines)
    assert "Weird{Folder" in "\n".join(lex.masked_lines), "strings must NOT be masked"


def test_braces_are_counted_per_line_from_real_tokens_only() -> None:
    text = SAMPLE.decode()
    lex = st._LexicalMap(text)
    assert sum(lex.open_braces) == 1, "one real block in the sample"
    assert sum(lex.brace_delta) == 0, "and it is balanced"
    # The line carrying `fileinto "Weird{Folder";` has a `{` character and no
    # brace token at all. That difference is the whole fix.
    weird = next(i for i, line in enumerate(text.split("\n")) if "Weird{Folder" in line)
    assert "{" in text.split("\n")[weird]
    assert lex.open_braces[weird] == 0
    assert lex.brace_delta[weird] == 0


def test_a_byte_order_mark_does_not_disable_the_map() -> None:
    """A BOM kills the Lexer for the WHOLE file — verified: it reports every
    remaining byte as one unknown token. The map skips it rather than removing
    it, so `text` and every offset into it stay as the caller sees them."""
    with pytest.raises(SieveLibParseError, match="unknown token"):
        list(Lexer(Parser.lrules).scan("﻿".encode() + SAMPLE))

    lex = st._LexicalMap("﻿" + SAMPLE.decode())
    assert lex.usable, "a BOM must not cost us the lexical model"
    assert sum(lex.open_braces) == 1

    with_bom = st.parse_sieve("﻿" + SAMPLE.decode())
    assert len(with_bom.rules) == 1
    assert [a.argument for a in with_bom.rules[0].actions] == ["Weird{Folder"]


def test_text_the_lexer_refuses_becomes_one_whole_file_raw_block() -> None:
    """An unknown token anywhere and the map is abandoned whole.

    A PARTIAL map is worse than none: lines past the failure would report zero
    braces and a block would run to end of file.

    And so is guessing. The first version of this fell back to character
    counting — "worse than the map, but not worse than yesterday". That was
    wrong, and `.11` says so in terms: `Lexer failure -> the whole file as one
    RawBlock, content intact`. Character counting IS the thing whose three
    corrupting defects `.10` exists to close, so falling back to it turns the
    file we understand LEAST into the one we are most willing to guess about.

    Zero Rules plus one whole-file RawBlock is a readable state meaning
    "understood nothing". No fixture in the corpus reaches it;
    `test_every_fixture_is_lexable` below is what says so.
    """
    hostile = 'require ["fileinto"];\n\n@@@ not sieve @@@\n'
    assert not st._LexicalMap(hostile).usable

    script = st.parse_sieve(hostile)
    assert script.rules == []
    assert script.requires == [], "nothing is read out of a file we cannot lex"
    (raw,) = script.raw_blocks
    assert raw.text == hostile.rstrip("\n"), "content intact, byte for byte"


def test_a_file_the_lexer_refuses_still_round_trips() -> None:
    """Whole-file RawBlock or not, saving it must not change it."""
    hostile = 'require ["fileinto"];\n\n@@@ not sieve @@@\n'
    first = st.generate_sieve(st.parse_sieve(hostile))
    assert first == st.generate_sieve(st.parse_sieve(first))
    assert "@@@ not sieve @@@" in first
    assert 'require ["fileinto"];' in first, "the require survives as raw text"


def test_a_lexable_file_is_never_treated_that_way() -> None:
    """The whole-file RawBlock is for text we cannot read, and nothing else.
    A script that lexes must still be parsed normally, or this "safety" would
    quietly make the editor useless."""
    ordinary = 'require ["fileinto"];\n\nif header :is "a" "b" {\n    fileinto "X";\n}\n'
    script = st.parse_sieve(ordinary)
    assert len(script.rules) == 1
    assert script.raw_blocks == []


def test_text_that_cannot_be_bytes_falls_back_rather_than_500ing() -> None:
    """Raised in review of #62, and it was a REGRESSION, not a pre-existing gap.

    `json.loads` decodes `"\\ud800"` into a lone-surrogate Python str, and
    `SaveRawRequest.content` is a plain `str`, so one can be stored through
    `PUT /api/scripts/{name}/raw` and read back. The character-counting parser
    this replaced never needed the text to be bytes at all and handled it
    fine; the first draft of this class encoded OUTSIDE its own safety net and
    answered a 500 on the next GET.

    Measured on that draft:
        UnicodeEncodeError: 'utf-8' codec can't encode character '\\ud800'
    Now it falls back, exactly as an unknown token does.
    """
    import json

    lone_surrogate = json.loads(r'{"c": "keep;\ud800"}')["c"]

    lex = st._LexicalMap(lone_surrogate)
    assert not lex.usable

    script = st.parse_sieve(lone_surrogate)
    assert script.entries, "the old parser produced an entry here and so must this one"


def test_the_fallback_is_narrow_by_construction() -> None:
    """Also from the #62 review: a bare `except Exception` around the scan
    would swallow bugs in our own arithmetic and silently drop the lexical
    model — letting the three defects back in with no signal.

    Only `_scan` is guarded, and only for the two ways the INPUT can be the
    problem. Everything after it is our own arithmetic over tokens we already
    hold, and is left to fail loudly.
    """
    assert st._LexicalMap._scan.__doc__, "_scan is the guarded boundary; keep it documented"
    with pytest.raises(SieveLibParseError):
        st._LexicalMap._scan("@@@ not sieve @@@")
    with pytest.raises(UnicodeEncodeError):
        st._LexicalMap._scan("\ud800")


@pytest.mark.parametrize("path", CORPUS, ids=corpus_id)
def test_every_fixture_is_lexable(path: Path) -> None:
    """The fallback above is the safety net, not the plan. Every fixture —
    including all 45 third-party ones — must go through the real map, or the
    defects this bead closes are only closed for some scripts."""
    assert st._LexicalMap(path.read_text()).usable


# ── Why no lock is needed ──


def test_parsing_is_thread_safe_because_only_the_lexer_is_borrowed() -> None:
    """sievelib's PARSER has process-global state: `Parser.parse` resets
    `RequireCommand.loaded_extensions`, a CLASS attribute, so two concurrent
    parses race and one sees the other's extensions. FastAPI runs sync handlers
    on a threadpool, so that race is reachable from two requests.

    This wrap takes the LEXER only, which holds nothing across calls, and
    builds a fresh one per parse. Checked here rather than asserted: identical
    input must give identical output under contention.
    """
    from sievelib.commands import RequireCommand

    assert "loaded_extensions" in vars(RequireCommand), (
        "the hazard this test reasons about has moved; re-check the claim"
    )

    corpus = [p.read_text() for p in sorted((BACKEND / "test_scripts").glob("*.sieve"))]
    expected = [st.generate_sieve(st.parse_sieve(text)) for text in corpus]

    def once(i: int) -> bool:
        return (
            st.generate_sieve(st.parse_sieve(corpus[i % len(corpus)])) == expected[i % len(corpus)]
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(once, range(4000)))
    assert all(results), f"{results.count(False)} of {len(results)} concurrent parses disagreed"


# ── Where this bead's fix stops ──


# The fixtures whose recognised Rules sievelib refuses, and the bead that owns
# each. Asserted as an EXACT set below, never as an `xfail` on the test: this
# test's claim is about all 66 fixtures, and a function-level marker would
# switch that claim off for every one of them to accommodate this one.
RULES_THE_ORACLE_REFUSES = {
    "modifiers-comparator-declared.sieve": "areyousievious-3o4",
}
"""For one reason: sievelib's comparator whitelist holds i;octet and i;ascii-casemap and nothing else, so it refuses the collation i;ascii-numeric that RFC 5228 §2.7.3 mandates a require for."""


def test_every_rule_we_recognise_is_sieve_sievelib_accepts() -> None:
    """A standing check on the projection, and the measurement `.11` needs.

    The design for this bead ran the whole span through sievelib's PARSER as
    well as its Lexer, and the stated risk was recognition LOSS — sievelib is
    stricter than our regexes, so a gate could push working rules into
    RawBlock. Measured across the corpus: it would reject 0 of the rules we
    recognise. That is the number that says a Parser gate is affordable, and
    it is asserted here rather than written down once in a commit message.

    Adopting the gate is still not free — sievelib's Parser resets a CLASS
    attribute per parse, so it needs a process-wide lock that the Lexer does
    not — which is why `.10` takes the Lexer only.

    The number is no longer 0: `modifiers-comparator-declared.sieve` yields a
    Rule the oracle refuses, for a defect someone owns. That is held as an
    exact set rather than as an exemption, so the measurement still runs over
    every other fixture and a NEW refusal fails here by name.
    """
    from sievelib.parser import Parser as SieveLibParser

    refused: dict[str, list[str]] = {}
    for path in CORPUS:
        script = st.parse_sieve(path.read_text())
        for rule in script.rules:
            alone = st.SieveScript(requires=list(script.requires), entries=[rule])
            if not SieveLibParser().parse(st.generate_sieve(alone).encode()):
                refused.setdefault(corpus_id(path), []).append(rule.name)

    known = set(RULES_THE_ORACLE_REFUSES)
    assert set(refused) == known, (
        f"we recognise rules sievelib refuses, owned by nobody: {refused}. "
        f"Accepted again, so delete from RULES_THE_ORACLE_REFUSES: "
        f"{sorted(known - set(refused))}"
    )


def test_a_command_we_do_not_model_is_not_silently_dropped() -> None:
    """The fourth corruption class. Closed by areyousievious-8fg.11; this was
    pinned xfail(strict=True) naming that bead until it landed.

    `setflag` is valid Sieve we have no Action for. The block still matches our
    regexes, so it is projected onto a Rule carrying only `fileinto` — and
    regenerating writes a script with `setflag` gone. Measured, not predicted.

    The lexical model could not help: nothing here is mis-SEGMENTED. Deciding
    what may be projected onto a Rule at all was `.11`, which now keeps the
    whole block raw rather than narrowing it to the part we understand.
    """
    src = (
        'require ["fileinto", "imap4flags"];\n\n'
        'if header :is "subject" "alpha" {\n'
        '    fileinto "Filed";\n'
        '    setflag "\\\\Seen";\n'
        "}\n"
    )
    assert "setflag" in st.generate_sieve(st.parse_sieve(src)), (
        "a command we cannot represent must reach RawBlock, not vanish"
    )
