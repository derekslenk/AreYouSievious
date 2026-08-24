"""
Nothing reaches the mail server that the script was not entitled to write
(areyousievious-8fg.14).

A guard is only as good as the question the fuzzer asks it. Two earlier oracles
for this missed a live Critical each, and both times for the same reason —
someone enumerated the fields by hand and the attack came through the one that
was not on the list:

  - The first split lines with Python's `str.splitlines()`, which breaks on
    \\x0b, \\x0c, \\x85, U+2028 and U+2029. Those are legal comment octets under
    RFC 5228, which ends a comment at CRLF and at nothing else, so that oracle
    reported a wall of false positives and could not have shown a real one.
  - The second fixed that but only ever fed `preamble`, `requires_source`,
    `tail`, `RawBlock.comment` and `Rule.name` — precisely the set of injection
    sites already known. `Rule.source` was not among them, which is exactly why
    200,000 cases and zero escapes did not find the NUL that rode into the mail
    server inside a rule's span.

So this one enumerates nothing by hand. It reads the string fields off the
dataclasses, so a field added later is fuzzed the day it is added, and it judges
the RENDERED OUTPUT rather than the input: generate the script, split the way a
server splits, and refuse any live statement the same script does not already
write with a benign value in that field.

Run from the backend/ directory:
    cd backend && python -m pytest tests/test_generated_output_fuzz.py -v
"""

from __future__ import annotations

import dataclasses as dc
import random
import re

import pytest
import sieve_transform as st

# Sieve tokens, plus every byte an injection would want to end a line with.
TOKENS = [
    "redirect",
    "keep",
    "discard",
    "stop",
    "fileinto",
    "vacation",
    "require",
    '"a@b.com"',
    '"subject"',
    '"fileinto"',
    ":contains",
    ":days",
    "header",
    "if",
    "elsif",
    "else",
    "anyof",
    "true",
    "7",
    "#c",
    "text:",
    ".",
    "{",
    "}",
    "[",
    "]",
    "(",
    ")",
    ",",
    ";",
    "\\",
    '"',
    "/*",
    "*/",
    "\n",
    "\r",
    "\r\n",
    "\x00",
    "\x0b",
    "\x0c",
    "\x85",
    "\t",
    " ",
    " ",
    " ",
]

# `match` is the one string field left out. It is a closed vocabulary on the
# wire (`MatchOperator` is a pydantic Literal), so no payload reaches it, and
# fuzzing it would assert on a path the endpoint cannot be driven down.
NOT_FREE_TEXT = {"match"}

# The bytes under test, removed to build each case's own reference rendering.
HARMLESS = {ord(c): None for c in "\r\n\x00"}


def _string_fields(cls) -> list[str]:
    """Every field that carries client text, whether or not it is bare `str`.

    `list[str]` counts. Stopping at `f.type is str` is why `requires` was
    invisible here while `_requires_text` interpolated each item into
    `require ["..."];` unescaped — a Critical that survived a passing fuzz run
    because the fuzzer could not see the field it lived in. Twice before, this
    generalisation was ALMOST wide enough: fields but not shapes, then shapes but
    not container types, and each time the gap was exactly where the next bug
    was. Widen it when in doubt; a field fuzzed needlessly costs a second.
    """
    return [
        f.name for f in dc.fields(cls) if f.type in (str, list[str]) and f.name not in NOT_FREE_TEXT
    ]


def _is_list_field(cls, name: str) -> bool:
    return any(f.name == name and f.type is not str for f in dc.fields(cls))


def _statement_part(line: str) -> str:
    """The line with any trailing comment cut off.

    A `#` outside a quoted string starts a comment that runs to end of line, so
    everything after it is inert and its TEXT is not what this oracle is asking
    about — only whether a statement appeared. Without this, a payload that
    merely rearranged the text of a trailing comment reads as an escape, which
    is a false positive in the shape most likely to be dismissed as noise.

    Quote-aware because `#` inside a string is an ordinary character, and
    backslash-aware because `\"` does not close the string.
    """
    quoted = False
    index = 0
    while index < len(line):
        char = line[index]
        if char == "\\" and quoted:
            index += 2
            continue
        if char == '"':
            quoted = not quoted
        elif char == "#" and not quoted:
            return line[:index].strip()
        index += 1
    return line.strip()


def _live_lines(out: str) -> list[str]:
    """The lines a server would execute.

    It breaks lines on CRLF, LF or CR and on nothing else — NOT on the other
    characters Python calls line boundaries. And if it is written in C it may
    stop dead at a NUL, so split there too and judge both halves: whichever side
    of the truncation a statement lands on, it is still a statement.
    """
    lines = (_statement_part(line) for line in re.split(r"\r\n|\n|\r", out.replace("\x00", "\n")))
    return [line for line in lines if line]


def _rule(**over) -> st.Rule:
    fields = {
        "name": "n",
        "conditions": [st.Condition(header="subject", match_type="contains", value="x")],
        "actions": [st.Action(action_type="keep")],
    }
    return st.Rule(**{**fields, **over})


# Every place a client-supplied string reaches the generator: the script's own
# three fields, and each string field of each entry type.
TARGETS = (
    [("SieveScript", f) for f in _string_fields(st.SieveScript)]
    + [("Rule", f) for f in _string_fields(st.Rule)]
    + [("RawBlock", f) for f in _string_fields(st.RawBlock)]
)


# The body each `source` payload is smuggled above. One lexes to a Rule and one
# to a RawBlock, so both entry types are exercised on the verbatim path.
BODIES = {
    "Rule": '# --- n ---\nif header :contains "subject" "x" {\n  keep;\n}\n',
    "RawBlock": 'vacation :days 7 "Away";\n',
}

# Where inside a span the payload sits. The previous version of this file built
# ONE shape by hand — a single comment line above the body — and that constant is
# exactly what hid the next bug: the parser keeps only the LAST comment line as
# `comment`, so a payload in a NON-FINAL comment lands in no modelled field at
# all and the guard that read `comment` never saw it. A field list that
# generalises is worth little while the shape it is fed does not, so the shape is
# generated too. If a hand-written constant is left below, ask what it stands in
# for.
IN_BODY_COMMENT = {
    "Rule": '# --- n ---\nif header :contains "subject" "x" {{\n  keep; # {p}\n}}\n',
    "RawBlock": 'vacation :days 7 "Away"; # {p}\n',
}

# A THIRD SHAPE — the payload inside a QUOTED VALUE — was written and then
# removed, because this oracle cannot judge it and a check that cannot fail
# honestly is worse than an absent one. A line break inside a Sieve quoted
# string is LEGAL and inert: a real server tokenises, so `"a\nb"` is one string
# and one statement, while `_live_lines` splits it and calls the second half a
# smuggled command. Every case would be a false positive.
#
# Probed by hand instead, since dropping a shape is not the same as clearing it:
# a newline in a value, an escaped `"` mid-value, and a value closed early
# followed by a statement. The first two stay one faithful Rule that renders
# byte-identical; the third lexes to a RawBlock, which grants arbitrary
# statements by design anyway, and sievelib rejects the result outright. No
# vector found. Judging this shape properly needs an AST oracle rather than a
# line oracle — `tests/test_ast_oracle.py` is where that would go.


def _leading_gap(rng: random.Random, kind: str, payload: str) -> str:
    """The payload in a comment somewhere in the gap above the body.

    Varies how many comment lines the gap holds, whether a blank line sits among
    them, and — the part that matters — WHICH of them carries the payload. Only
    the last is kept as `comment`; any earlier one is in `source` and nowhere
    else.
    """
    lines = [f"# {c}\n" for c in ("a", "b", "c")][: rng.randint(0, 3)]
    lines.insert(rng.randint(0, len(lines)), f"# {payload}\n")
    if rng.random() < 0.5:
        lines.insert(rng.randint(0, len(lines)), "\n")
    return "".join(lines) + BODIES[kind]


SPAN_SHAPES = {
    "leading gap": _leading_gap,
    "in-body comment": lambda rng, kind, payload: IN_BODY_COMMENT[kind].format(p=payload),
}


def _build(
    kind: str, field: str, payload: str, rng: random.Random, shape: str = "leading gap"
) -> st.SieveScript | None:
    """The script a client proposes with `payload` in this field, or None when
    the case does not exercise the path under test.

    A `source` CANNOT usefully be fuzzed by assigning it directly. It is only
    ever written when `span_is_faithful` vouches for it, and a random string
    assigned to `source` never re-parses to the entry beside it — so every such
    case takes the regenerating path, `source` is discarded unread, and the fuzz
    proves nothing. THIS IS WHY THE PREVIOUS ORACLE MISSED THE NUL: it fuzzed
    `source` and never once reached the branch that writes it.

    So a `source` payload is PARSED into place instead, in one of the shapes in
    `SPAN_SHAPES` — a comment somewhere in the leading gap, or a comment inside
    the body. Those are the places a span holds bytes that no compared field
    does, which is precisely what makes them a free-text channel. Cases
    where the payload broke out into its own entry are skipped: the parser saw
    the line break too, so the client merely sent a different script, which is
    its right. What is left is the vulnerability class exactly — a byte that ends
    a line for the server and not for us.
    """
    if kind == "SieveScript":
        value = [payload] if _is_list_field(st.SieveScript, field) else payload
        fields = {"requires": ["fileinto"], "entries": [st.RawBlock(text="keep;")]}
        return st.SieveScript(**{**fields, field: value})
    if field == "source":
        script = st.parse_sieve(SPAN_SHAPES[shape](rng, kind, payload))
        if len(script.entries) != 1 or type(script.entries[0]).__name__ != kind:
            return None
        return script if st.span_is_faithful(script.entries[0]) else None
    if kind == "Rule":
        return st.SieveScript(entries=[_rule(**{field: payload})])
    return st.SieveScript(entries=[st.RawBlock(**{"text": "keep;", field: payload})])


def test_the_targets_cover_every_string_field_including_source():
    """The oracle's own coverage, asserted rather than assumed — this is the
    part both previous versions got wrong, and a silently shrinking target list
    would make everything below pass vacuously."""
    assert ("Rule", "source") in TARGETS, "the field that carried the last Critical"
    assert ("RawBlock", "source") in TARGETS
    assert ("SieveScript", "requires") in TARGETS, "the field that carried the last one"
    assert {f for k, f in TARGETS if k == "SieveScript"} == {
        "preamble",
        "requires",
        "requires_source",
        "tail",
    }
    assert {f for k, f in TARGETS if k == "Rule"} == {"name", "source"}
    assert {f for k, f in TARGETS if k == "RawBlock"} == {"text", "comment", "source"}


@pytest.mark.parametrize(("kind", "field"), TARGETS, ids=lambda v: str(v))
def test_no_fuzzed_field_writes_a_statement_the_script_did_not_earn(kind: str, field: str):
    """Generate, split the way a server splits, and refuse any live line that the
    SAME PAYLOAD does not write once CR, LF and NUL are taken out of it.

    That reference is the point. A payload is entitled to whatever it writes as
    inert text; it is not entitled to gain a statement by carrying a byte that
    ends a line for the server and not for us. Every finding on this branch has
    been an instance of that one sentence, and this is it asserted directly
    rather than approximated by a fixed baseline.

    Whatever a `RawBlock.text` holds counts as earned — that channel grants
    arbitrary statements by design and by ADR 0002, and no guard here pretends
    otherwise. Everything else must earn every line it writes.
    """
    rng = random.Random(f"{kind}.{field}")
    shapes = list(SPAN_SHAPES) if field == "source" else ["leading gap"]

    escapes = []
    exercised = dict.fromkeys(shapes, 0)
    for i in range(4000):
        shape = shapes[i % len(shapes)]
        payload = "".join(rng.choice(TOKENS) for _ in range(rng.randint(1, 12)))
        script = _build(kind, field, payload, rng, shape)
        if script is None or st.preflight_error(script) is not None:
            continue

        # The reference: THE SAME PAYLOAD with the bytes under test taken out.
        # Whatever a payload is entitled to write, it is entitled to write with
        # or without them — a quoted value stays one line, an in-body comment
        # stays inert. So any difference between the two renderings is one of
        # these bytes changing the statement structure the server sees, which is
        # the vulnerability in one sentence. Comparing against a fixed "benign"
        # baseline instead cannot express this: the payload is INSIDE a line for
        # two of the three shapes, so every case differs from the baseline and
        # the oracle drowns in its own false positives.
        inert = _build(kind, field, payload.translate(HARMLESS), rng, shape)
        if inert is None:
            continue
        exercised[shape] += 1

        # A RawBlock's own `text` is an arbitrary-statement channel by design and
        # by ADR 0002 — no guard here pretends otherwise, so whatever it holds is
        # a line that block earned.
        allowed = set(_live_lines(st.generate_sieve(inert)))
        for entry in script.entries:
            if isinstance(entry, st.RawBlock):
                allowed.update(_live_lines(entry.text))
        for line in _live_lines(st.generate_sieve(script)):
            if line in allowed or line.startswith("require"):
                continue
            escapes.append((payload, line))
            break

    assert not escapes, f"{kind}.{field} wrote {escapes[:3]}"
    # A parametrisation that generated nothing the guard let through would pass
    # for the worst possible reason, and so would a SHAPE that never produced a
    # faithful span — the coverage is asserted per shape for that reason, not
    # just in total. Every oracle before this one passed; not all of them were
    # asking anything.
    assert all(exercised.values()), f"{kind}.{field} exercised nothing for {exercised}"
    assert sum(exercised.values()) > 50, f"{kind}.{field} only exercised {exercised}"
