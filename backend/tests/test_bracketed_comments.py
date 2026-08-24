"""
Bracketed comments, `/* ... */` (RFC 5228 §2.3, areyousievious-hr6).

The parser had no branch for them. A `/*` line fell through to
`_consume_raw_statement`, which runs forward to the next `;` — and a comment
has no `;` of its own — so everything from the `/*` through the end of the
first statement AFTER the `*/` collapsed into one opaque `RawBlock`:

    [Rule(A), RawBlock("/*"), RawBlock(B + "*/" + "# --- also live ---" + C)]

The harm was never that the commented-out rule B showed as live; it did not,
it was raw text. It was that the LIVE rule C was fused into the same lump. A
rule the server executes became un-editable in the builder, and any reorder
moved B, the `*/` and C as one indivisible block — because a comment happened
to appear above it.

The fix reads the comment off the LEXER's tokens, never off the text, which is
the only way `fileinto "a/*b";` stays a folder name rather than the start of a
comment that eats the rest of the file.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_bracketed_comments.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest
import sieve_transform as st

BACKEND = Path(__file__).resolve().parent.parent

# The shape from the bead, and the reason this module exists. `A` and `C` are
# live; `B` is commented out.
FUSED = """require ["fileinto"];

# --- live ---
if header :contains "subject" "a" { fileinto "A"; }

/*
if header :contains "subject" "b" { fileinto "B"; }
*/

# --- also live ---
if header :contains "subject" "c" { fileinto "C"; }
"""


def _kinds(script: st.SieveScript) -> list[str]:
    return [type(e).__name__ for e in script.entries]


def _reassembles(text: str) -> bool:
    """The invariant everything else rests on, for one input."""
    script = st.parse_sieve(text)
    rebuilt = (
        script.preamble
        + script.requires_source
        + "".join(e.source for e in script.entries)
        + script.tail
    )
    return rebuilt == text


# ── The defect ──


def test_a_bracketed_comment_no_longer_fuses_the_rule_below_it() -> None:
    """The headline. Three entries, and the third is a Rule of its own.

    This is the assertion the whole bead is for. Revert the branch in
    `SieveParser.parse` and it fails with two entries, the second holding B,
    the `*/`, C's name comment and C — verified by doing exactly that.
    """
    script = st.parse_sieve(FUSED)

    assert _kinds(script) == ["Rule", "RawBlock", "Rule"], (
        f"the entry split is still fused: {[(type(e).__name__, e.source) for e in script.entries]}"
    )
    live_a, commented, live_c = script.entries

    assert live_a.actions[0].argument == "A"
    assert live_c.actions[0].argument == "C", "the live rule below the comment lost its action"
    assert live_c.name == "also live", "the live rule below the comment lost its name"

    # The comment is exactly itself: opener, body, closer, and nothing else.
    assert commented.text == ('/*\nif header :contains "subject" "b" { fileinto "B"; }\n*/'), (
        f"the comment entry claimed bytes that are not the comment: {commented.text!r}"
    )
    assert 'fileinto "C"' not in commented.source, "rule C is still inside the comment's span"


def test_the_commented_out_rule_is_not_projected_as_a_rule() -> None:
    """B is inside a comment, so the server never runs it and neither do we.

    Two rules in, two rules out — which is also what sievelib sees in this
    script, and the reason the count is worth pinning rather than assuming.
    """
    script = st.parse_sieve(FUSED)
    assert [r.actions[0].argument for r in script.rules] == ["A", "C"]


# ── What a comment is, and is not ──


def test_a_bracket_in_a_string_is_not_a_comment() -> None:
    """`fileinto "a/*b";` is a folder name. Nothing here is a comment.

    This is why the branch is driven off the Lexer's tokens: any scan for a
    literal `/*` in the line would open a comment here and swallow the rest of
    the file. The lexical map is asked directly, so a regression cannot hide
    behind the parser agreeing with itself by luck.
    """
    text = 'require ["fileinto"];\n\nif header :contains "subject" "x" { fileinto "a/*b"; }\n'
    assert not any(st._LexicalMap(text).bracket_comment_lines)

    script = st.parse_sieve(text)
    assert _kinds(script) == ["Rule"]
    assert script.rules[0].actions[0].argument == "a/*b"
    assert st.generate_sieve(script) == text


def test_the_corpus_fixture_for_a_bracket_in_a_string_stays_one_rule() -> None:
    """The same claim on the vendored fixture, whose `/*` is in a match value."""
    text = (BACKEND / "test_scripts/vendor/string-with-bracket-comment.sieve").read_text()
    assert not any(st._LexicalMap(text).bracket_comment_lines)
    assert _kinds(st.parse_sieve(text)) == ["Rule"]


def test_a_comment_sharing_a_line_with_code_is_left_where_it_was() -> None:
    """A `/*` that does not start its line belongs to the statement handler.

    `discard /* c */ ;` is one statement with a comment inside it, not a
    comment. Taking the line as a comment entry would swallow the `discard`,
    which is the very fusion this bead removes — in the other direction. The
    vendored fixture is that shape and must keep landing whole.
    """
    text = (BACKEND / "test_scripts/vendor/bracket-comment.sieve").read_text()
    script = st.parse_sieve(text)
    assert _kinds(script) == ["RawBlock"]
    assert script.entries[0].source == text
    assert st.generate_sieve(script) == text


# ── The boundaries ──


def test_a_comment_before_anything_else_is_its_own_entry() -> None:
    """The preamble boundary: the comment is an entry, and nothing leaks past it.

    Multi-line on purpose. A ONE-line comment above a block came out right by
    accident before this bead — the old scan stopped at the `{` it could not
    step over — so a one-line fixture here would pass with the fix reverted and
    prove nothing.
    """
    text = '/* a header\n   over two lines */\n\nif header :contains "subject" "a" { discard; }\n'
    script = st.parse_sieve(text)

    assert _kinds(script) == ["RawBlock", "Rule"]
    assert script.preamble == ""
    assert script.entries[0].source == "/* a header\n   over two lines */\n"
    assert _reassembles(text)
    assert st.generate_sieve(script) == text


def test_a_comment_after_the_last_rule_is_its_own_entry() -> None:
    """The tail boundary. The comment claims its own bytes, the tail keeps the rest."""
    text = (
        'if header :contains "subject" "a" { discard; }\n\n/* nothing below\n   here is live */\n\n'
    )
    script = st.parse_sieve(text)

    assert _kinds(script) == ["Rule", "RawBlock"]
    assert script.entries[1].source == "\n/* nothing below\n   here is live */\n"
    assert script.tail == "\n"
    assert _reassembles(text)
    assert st.generate_sieve(script) == text


def test_a_comment_that_ends_a_file_without_a_newline_keeps_its_bytes() -> None:
    """`_span` drops the separator only for a line at the true end of the file."""
    text = 'if header :contains "subject" "a" { discard; }\n/* the\n   end */'
    script = st.parse_sieve(text)

    assert _kinds(script) == ["Rule", "RawBlock"]
    assert script.entries[1].source == "/* the\n   end */"
    assert _reassembles(text)
    assert st.generate_sieve(script) == text


def test_a_one_line_comment_is_one_entry() -> None:
    """`/* like this */`, followed by a statement it must not swallow.

    A bare statement rather than a block: the old scan ran to the next `;`, so
    a one-line comment above `keep;` fused the two. A block below would have
    stopped it at the `{` and hidden the defect.
    """
    text = "/* like this */\nkeep;\n"
    script = st.parse_sieve(text)

    assert _kinds(script) == ["RawBlock", "RawBlock"]
    assert script.entries[0].text == "/* like this */"
    assert script.entries[1].text == "keep;"
    assert _reassembles(text)
    assert st.generate_sieve(script) == text


def test_a_comment_closing_and_reopening_on_one_line_is_one_entry() -> None:
    """`*/ /*` — the close of one comment and the open of the next.

    Consumed as a RUN rather than a single token, so the second comment's tail
    is not orphaned onto a line the statement handler then tries to read.
    """
    text = '/*\na\n*/ /*\nb\n*/\nif header :contains "subject" "c" { discard; }\n'
    script = st.parse_sieve(text)

    assert _kinds(script) == ["RawBlock", "Rule"]
    assert script.entries[0].text == "/*\na\n*/ /*\nb\n*/"
    assert _reassembles(text)
    assert st.generate_sieve(script) == text


# ── The degenerate case ──


def test_an_unterminated_comment_becomes_the_whole_file_verbatim() -> None:
    """A `/*` with no `*/` is not lexable, so the fallback owns the file.

    Deliberate and pinned rather than surprising: the Lexer refuses the text
    outright, `usable` is False, the new branch never fires, and the parser
    takes the path it already had for text it cannot lex — one whole-file
    `RawBlock`, content intact. Nothing is guessed at and nothing is lost.
    """
    text = 'if header :contains "subject" "a" { discard; }\n/* never closed\n'
    assert st._LexicalMap(text).usable is False

    script = st.parse_sieve(text)
    assert _kinds(script) == ["RawBlock"]
    assert script.entries[0].source == text
    assert st.generate_sieve(script) == text


# ── The invariants, on the shapes above ──


@pytest.mark.parametrize(
    "text",
    [
        FUSED,
        '/* a header\n   over two lines */\n\nif header :contains "subject" "a" { discard; }\n',
        'if header :contains "subject" "a" { discard; }\n\n/* trailing\n   comment */\n\n',
        "/* like this */\nkeep;\n",
        "/*\n\n\n*/\n",
        'if header :contains "subject" "a" { discard; }\n/* the\n   end */',
        "/* one */\n/* two */\nkeep;\n",
    ],
    ids=["fused", "leading", "trailing", "one-line", "blank-body", "no-final-newline", "adjacent"],
)
def test_the_spans_reassemble_and_the_bytes_come_back(text: str) -> None:
    """Invariants 1 and 2 on every bracketed-comment shape this module knows."""
    assert _reassembles(text), "the span decomposition lost or duplicated bytes"
    assert st.generate_sieve(st.parse_sieve(text)) == text


def test_a_comment_next_to_a_regenerated_rule_still_re_emits_its_own_bytes() -> None:
    """The seam case: edit the rule BELOW the comment and save.

    Editing puts that rule on the canonical path, so `_join` settles the seam
    between it and the comment above. The comment is a verbatim span and must
    come back exactly once, unaltered — the blank line around it is `_join`'s
    to decide, its own bytes are not.
    """
    script = st.parse_sieve(FUSED)
    comment_text = script.entries[1].text
    script.entries[2].name = "renamed"

    out = st.generate_sieve(script)

    assert out.count(comment_text) == 1, "the comment was duplicated or rewritten"
    assert 'fileinto "C"' in out
    assert "renamed" in out
    # The comment's own body stays commented out: B must not become live Sieve.
    assert out.count('fileinto "B"') == 1
    assert out.index(comment_text) < out.index('fileinto "C"')


# ── The map underneath ──


def test_the_map_marks_every_line_a_comment_occupies() -> None:
    """Start line through end line, from the token's offset and its own bytes."""
    text = 'if header :contains "subject" "a" { discard; }\n/*\nb\n*/\n\n'
    assert st._LexicalMap(text).bracket_comment_lines == [
        False,
        True,
        True,
        True,
        False,
        False,
    ]


def test_the_map_reports_no_comment_lines_when_it_is_unusable() -> None:
    """No tokens, no marks — so the parser's branch simply never fires."""
    lex = st._LexicalMap("/* never closed")
    assert lex.usable is False
    assert lex.bracket_comment_lines == [False]
