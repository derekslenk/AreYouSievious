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


def _string_fields(cls) -> list[str]:
    return [f.name for f in dc.fields(cls) if f.type is str and f.name not in NOT_FREE_TEXT]


def _live_lines(out: str) -> list[str]:
    """The lines a server would execute.

    It breaks lines on CRLF, LF or CR and on nothing else — NOT on the other
    characters Python calls line boundaries. And if it is written in C it may
    stop dead at a NUL, so split there too and judge both halves: whichever side
    of the truncation a statement lands on, it is still a statement.
    """
    return [
        line.strip()
        for line in re.split(r"\r\n|\n|\r", out.replace("\x00", "\n"))
        if line.strip() and not line.strip().startswith("#")
    ]


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


def _build(kind: str, field: str, payload: str) -> st.SieveScript | None:
    """The script a client proposes with `payload` in this field, or None when
    the case does not exercise the path under test.

    A `source` CANNOT usefully be fuzzed by assigning it directly. It is only
    ever written when `span_is_faithful` vouches for it, and a random string
    assigned to `source` never re-parses to the entry beside it — so every such
    case takes the regenerating path, `source` is discarded unread, and the fuzz
    proves nothing. THIS IS WHY THE PREVIOUS ORACLE MISSED THE NUL: it fuzzed
    `source` and never once reached the branch that writes it.

    So a `source` payload is PARSED into place instead, sitting in a comment
    above the body — the leading gap rides in the span by design, in no compared
    field, which is precisely what made it a free-text channel. Cases where the
    payload broke out into its own entry are skipped: the parser saw the line
    break too, so the client merely sent a different script, which is its right.
    What is left is the vulnerability class exactly — a byte that ends a line for
    the server and not for us.
    """
    if kind == "SieveScript":
        return st.SieveScript(
            requires=["fileinto"], entries=[st.RawBlock(text="keep;")], **{field: payload}
        )
    if field == "source":
        script = st.parse_sieve(f"# {payload}\n{BODIES[kind]}")
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
    assert {f for k, f in TARGETS if k == "SieveScript"} == {
        "preamble",
        "requires_source",
        "tail",
    }
    assert {f for k, f in TARGETS if k == "Rule"} == {"name", "source"}
    assert {f for k, f in TARGETS if k == "RawBlock"} == {"text", "comment", "source"}


@pytest.mark.parametrize(("kind", "field"), TARGETS, ids=lambda v: str(v))
def test_no_fuzzed_field_writes_a_statement_the_script_did_not_earn(kind: str, field: str):
    """Generate, split the way a server splits, and refuse a live line the same
    script does not write with a benign value in this field.

    Whatever a `RawBlock.text` holds counts as earned — that channel grants
    arbitrary statements by design and by ADR 0002, and no guard here pretends
    otherwise. Everything else must earn every line it writes.
    """
    rng = random.Random(f"{kind}.{field}")
    entitled = set(_live_lines(st.generate_sieve(_build(kind, field, "benign"))))

    escapes, exercised = [], 0
    for _ in range(4000):
        payload = "".join(rng.choice(TOKENS) for _ in range(rng.randint(1, 12)))
        script = _build(kind, field, payload)
        if script is None or st.preflight_error(script) is not None:
            continue
        exercised += 1
        # A RawBlock's own `text` is an arbitrary-statement channel by design and
        # by ADR 0002 — no guard here pretends otherwise, so whatever it holds is
        # a line that block earned. The question this asks is what gets written
        # BESIDES that.
        allowed = set(entitled)
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
    # for the worst possible reason. Both previous oracles passed; only one of
    # them was actually asking anything.
    assert exercised > 50, f"{kind}.{field} only exercised {exercised} cases"
